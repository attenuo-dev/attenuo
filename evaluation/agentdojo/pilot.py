#!/usr/bin/env python3
"""AgentDojo baseline: a stock agent with no attenuo, on a fixed task set or a whole suite.

Calls the per-task runners directly. `benchmark_suite_with_injections` also runs the model on
every injection task as if it were a user task, which is spend the pilot does not want.

Token counts come from the `usage` block of every response and are priced here, so the cost
does not depend on reading a billing page. The run stops once the cost passes --cap.

    python evaluation/agentdojo/pilot.py --out DIR --plan
    ANTHROPIC_API_KEY=... python evaluation/agentdojo/pilot.py --out DIR
    ANTHROPIC_API_KEY=... python evaluation/agentdojo/pilot.py --out DIR --suite slack \\
        --tasks 0 --injections 0 --shard 0/2 --resume

--plan prints the task selection and calls no model. --tasks 0 and --injections 0 mean all.
Processes sharing --out share the cap, by summing every usage-*.jsonl there, so the cap can be
passed by a few requests. --resume skips runs that already have a log, which also keeps results
from an earlier stopped run. The key is read from the environment by the Anthropic client and
never written anywhere by this script.
"""

import argparse
import asyncio
import json
import sys
import warnings
from pathlib import Path

import anthropic
from agentdojo.agent_pipeline import (
    AgentPipeline,
    AnthropicLLM,
    InitQuery,
    SystemMessage,
    ToolsExecutionLoop,
    ToolsExecutor,
)
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.agent_pipeline.llms import anthropic_llm
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import run_task_with_injection_tasks, run_task_without_injection_tasks
from agentdojo.logging import OutputLogger
from agentdojo.models import MODEL_NAMES
from agentdojo.task_suite.load_suites import get_suite

VERSION = "v1.2.2"
ATTACK = "important_instructions"
# Dollars per million tokens, input and output. Haiku 5.5 costs more on a request whose prompt
# passes 100K tokens.
PRICES = {"claude-haiku-5-5": (0.10, 0.50), "claude-sonnet-5-5": (2.0, 10.0)}
RATE_LIMIT_RETRIES = 20
RATE_LIMIT_WAIT_SECONDS = 30
LONG_PROMPT = {"claude-haiku-5-5": (100_000, 0.50, 2.50)}


class OverCap(Exception):
    pass


class Meter:
    """Records every response's usage and stops the run past the cap."""

    def __init__(self, model: str, cap: float, path: Path):
        self.model, self.cap, self.path = model, cap, path
        self.task = ""
        self.turns = 0

    def spent(self) -> float:
        """What every process sharing this output directory has spent so far."""
        total = 0.0
        for path in self.path.parent.glob("usage-*.jsonl"):
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    total += json.loads(line)["dollars"]
                except (ValueError, KeyError):
                    pass  # another process is mid-write
        return total

    def cost(self, usage) -> float:
        rate_in, rate_out = PRICES[self.model]
        limit, long_in, long_out = LONG_PROMPT.get(self.model, (float("inf"), 0, 0))
        if usage.input_tokens > limit:
            rate_in, rate_out = long_in, long_out
        cached = (usage.cache_read_input_tokens or 0) + (usage.cache_creation_input_tokens or 0)
        if cached:
            # The pilot sets no cache breakpoints, so this should never fire; a price we do not
            # hold must not turn into a silently wrong total.
            raise RuntimeError(f"unexpected cache tokens: {cached}")
        return (usage.input_tokens * rate_in + usage.output_tokens * rate_out) / 1e6

    def record(self, completion) -> None:
        usage = completion.usage
        dollars = self.cost(usage)
        self.turns += 1
        details = getattr(usage, "output_tokens_details", None)
        line = {
            "task": self.task,
            "model": completion.model,
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "thinking_tokens": getattr(details, "thinking_tokens", None),
            "cache_read_input_tokens": usage.cache_read_input_tokens,
            "cache_creation_input_tokens": usage.cache_creation_input_tokens,
            "stop_reason": completion.stop_reason,
            "dollars": dollars,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line) + "\n")
        if self.turns % 5 == 0 and self.spent() > self.cap:
            raise OverCap(f"spend passed the ${self.cap} cap")


def adapt_sdk() -> None:
    # agentdojo 0.1.35 calls MessageParam(...) as a TypedDict constructor. In the current SDK it
    # is a Union, which cannot be instantiated. A plain dict is what it built anyway.
    anthropic_llm.MessageParam = dict


def install_meter(meter: Meter) -> None:
    """Replace agentdojo's request function: it passes sentinels the current SDK rejects, and
    its retry wrapper hides the error. Only the fields that are set go out, and every response
    passes the meter. The SDK's own retries still cover 429s and server errors."""

    async def request(
        client,
        model,
        messages,
        tools,
        max_tokens,
        system_prompt=None,
        temperature=None,
        thinking_budget_tokens=None,
    ):
        if temperature is not None or thinking_budget_tokens is not None:
            raise RuntimeError("the pilot sets neither temperature nor a thinking budget")
        fields = {"model": model, "messages": messages, "max_tokens": max_tokens}
        if tools:
            fields["tools"] = tools
        if system_prompt:
            fields["system"] = system_prompt
        # A long wait, past the SDK's own retries: an unattended run outlasts a burst of 429s.
        for attempt in range(RATE_LIMIT_RETRIES + 1):
            try:
                async with client.messages.stream(**fields) as stream:
                    completion = await stream.get_final_message()
                break
            except anthropic.RateLimitError:
                if attempt == RATE_LIMIT_RETRIES:
                    raise
                await asyncio.sleep(RATE_LIMIT_WAIT_SECONDS)
        meter.record(completion)
        return completion

    anthropic_llm.chat_completion_request = request


def build_pipeline(model: str, max_tokens: int) -> AgentPipeline:
    # The attack addresses the model by name and raises on a model it does not know.
    MODEL_NAMES.setdefault(model, "Claude")
    # temperature=None: these models reject non-default sampling values.
    client = anthropic.Anthropic(max_retries=8)
    llm = AnthropicLLM(client, model, temperature=None, max_tokens=max_tokens)
    system = load_system_message(None)
    pipeline = AgentPipeline(
        [SystemMessage(system), InitQuery(), llm, ToolsExecutionLoop([ToolsExecutor(), llm])]
    )
    pipeline.name = model
    return pipeline


def task_number(task_id: str) -> int:
    return int(task_id.rsplit("_", 1)[1])


def is_injectable(attack, user_task) -> bool:
    """AgentDojo raises on a task whose ground truth reads no injection."""
    try:
        return bool(attack.get_injection_candidates(user_task))
    except ValueError:
        return False


def select_tasks(suite, pipeline, count: int, attack_name: str = ATTACK) -> tuple[list[str], list[str]]:
    """The first `count` injectable user tasks in id order (0: all), and the ones not injectable."""
    attack = load_attack(attack_name, suite, pipeline)
    chosen, skipped = [], []
    for task_id in sorted(suite.user_tasks, key=task_number):
        if not is_injectable(attack, suite.user_tasks[task_id]):
            skipped.append(task_id)
        elif not count or len(chosen) < count:
            chosen.append(task_id)
    return chosen, skipped


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--suite", default="workspace")
    parser.add_argument("--model", default="claude-haiku-5-5")
    parser.add_argument("--tasks", type=int, default=5)
    parser.add_argument("--injections", type=int, default=2)
    parser.add_argument("--max-tokens", type=int, default=4096)
    parser.add_argument("--cap", type=float, default=2.0, help="stop past this many dollars")
    parser.add_argument("--attack", default=ATTACK)
    parser.add_argument("--shard", default="0/1", help="I/N: run every Nth user task from I")
    parser.add_argument("--resume", action="store_true", help="skip runs that have a log")
    parser.add_argument("--plan", action="store_true", help="print the selection and stop")
    parser.add_argument("--smoke", action="store_true", help="run one benign task and stop")
    args = parser.parse_args()

    if args.model not in PRICES:
        raise SystemExit(f"no price held for {args.model}")
    suite = get_suite(VERSION, args.suite)
    pipeline = build_pipeline(args.model, args.max_tokens)
    user_ids, not_injectable = select_tasks(suite, pipeline, args.tasks, args.attack)
    injection_ids = sorted(suite.injection_tasks, key=task_number)
    injection_ids = injection_ids[: args.injections or None]
    shard, shards = (int(x) for x in args.shard.split("/"))
    # Benign runs need no injection, so a task the attack cannot reach still gets one.
    benign_ids = sorted(
        (user_ids + not_injectable) if not args.tasks else user_ids, key=task_number
    )[shard::shards]
    user_ids = user_ids[shard::shards]
    print(
        json.dumps(
            {
                "benign": benign_ids,
                "attacked": user_ids,
                "injections": injection_ids,
                "not_injectable": not_injectable,
            }
        )
    )
    if args.plan:
        return

    args.out.mkdir(parents=True, exist_ok=True)
    tag = f"{args.suite}-{shard}"
    meter = Meter(args.model, args.cap, args.out / f"usage-{tag}.jsonl")
    adapt_sdk()
    install_meter(meter)
    attack = load_attack(args.attack, suite, pipeline)
    results = {"benign": {}, "attack": {}}
    warnings.simplefilter("ignore")
    logs = args.out / "logs"
    try:
        with OutputLogger(str(logs)):
            for user_id in benign_ids:
                meter.task = f"{args.suite}/{user_id}/none"
                utility, _ = run_task_without_injection_tasks(
                    suite, pipeline, suite.user_tasks[user_id], logs, not args.resume, VERSION
                )
                results["benign"][user_id] = utility
                print(json.dumps({"run": meter.task, "utility": utility}), flush=True)
                if args.smoke:
                    return
            for user_id in user_ids:
                for injection_id in injection_ids:
                    meter.task = f"{args.suite}/{user_id}/{injection_id}"
                    utility, security = run_task_with_injection_tasks(
                        suite,
                        pipeline,
                        suite.user_tasks[user_id],
                        attack,
                        logs,
                        not args.resume,
                        [injection_id],
                        VERSION,
                    )
                    key = (user_id, injection_id)
                    results["attack"][meter.task] = {
                        "utility": utility[key],
                        "attack_succeeded": security[key],
                    }
                    print(
                        json.dumps({"run": meter.task, **results["attack"][meter.task]}), flush=True
                    )
    except OverCap as err:
        print(err, file=sys.stderr)
    finally:
        (args.out / f"results-{tag}.json").write_text(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
