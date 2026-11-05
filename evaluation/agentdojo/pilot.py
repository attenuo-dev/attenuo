#!/usr/bin/env python3
"""AgentDojo baseline pilot: a stock agent with no attenuo, on a small fixed task set.

Calls the per-task runners directly. `benchmark_suite_with_injections` also runs the model on
every injection task as if it were a user task, which is spend the pilot does not want.

Token counts come from the `usage` block of every response and are priced here, so the cost
does not depend on reading a billing page. The run stops once the cost passes --cap.

    ANTHROPIC_API_KEY=... python evaluation/agentdojo/pilot.py --out DIR --plan
    ANTHROPIC_API_KEY=... python evaluation/agentdojo/pilot.py --out DIR

--plan prints the task selection and calls no model. The key is read from the environment by
the Anthropic client and never written anywhere by this script.
"""

import argparse
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
from agentdojo.agent_pipeline.llms import anthropic_llm
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import run_task_with_injection_tasks, run_task_without_injection_tasks
from agentdojo.logging import OutputLogger
from agentdojo.models import MODEL_NAMES
from agentdojo.task_suite.load_suites import get_suite

VERSION = "v1.2.2"
ATTACK = "important_instructions"
# Dollars per million tokens: input, output, cache read, cache write (5 minute).
PRICES = {"claude-haiku-5-5": (0.10, 0.50, None, None), "claude-sonnet-5-5": (2.0, 10.0, 0.20, None)}


class OverCap(Exception):
    pass


class Meter:
    """Records every response's usage and stops the run past the cap."""

    def __init__(self, model: str, cap: float, path: Path):
        self.model, self.cap, self.path = model, cap, path
        self.total = 0.0
        self.task = ""
        self.turns = 0

    def cost(self, usage) -> float:
        rate_in, rate_out, _, _ = PRICES[self.model]
        cached = (usage.cache_read_input_tokens or 0) + (usage.cache_creation_input_tokens or 0)
        if cached:
            # The pilot sets no cache breakpoints, so this should never fire; a price we do not
            # hold must not turn into a silently wrong total.
            raise RuntimeError(f"unexpected cache tokens: {cached}")
        return (usage.input_tokens * rate_in + usage.output_tokens * rate_out) / 1e6

    def record(self, completion) -> None:
        usage = completion.usage
        dollars = self.cost(usage)
        self.total += dollars
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
            "total_dollars": self.total,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line) + "\n")
        if self.total > self.cap:
            raise OverCap(f"spend ${self.total:.4f} passed the ${self.cap} cap")


def adapt_sdk() -> None:
    # agentdojo 0.1.35 calls MessageParam(...) as a TypedDict constructor. In the current SDK it
    # is a Union, which cannot be instantiated. A plain dict is what it built anyway.
    anthropic_llm.MessageParam = dict


def install_meter(meter: Meter) -> None:
    """Replace agentdojo's request function: it passes sentinels the current SDK rejects, and
    its retry wrapper hides the error. Only the fields that are set go out, and every response
    passes the meter. The SDK's own retries still cover 429s and server errors."""

    async def request(
        client, model, messages, tools, max_tokens, system_prompt=None, temperature=None,
        thinking_budget_tokens=None,
    ):
        if temperature is not None or thinking_budget_tokens is not None:
            raise RuntimeError("the pilot sets neither temperature nor a thinking budget")
        fields = {"model": model, "messages": messages, "max_tokens": max_tokens}
        if tools:
            fields["tools"] = tools
        if system_prompt:
            fields["system"] = system_prompt
        async with client.messages.stream(**fields) as stream:
            completion = await stream.get_final_message()
        meter.record(completion)
        return completion

    anthropic_llm.chat_completion_request = request


def build_pipeline(model: str, max_tokens: int) -> AgentPipeline:
    # The attack addresses the model by name and raises on a model it does not know.
    MODEL_NAMES.setdefault(model, "Claude")
    # temperature=None: these models reject non-default sampling values.
    llm = AnthropicLLM(anthropic.Anthropic(), model, temperature=None, max_tokens=max_tokens)
    system = load_system_message(None)
    pipeline = AgentPipeline(
        [SystemMessage(system), InitQuery(), llm, ToolsExecutionLoop([ToolsExecutor(), llm])]
    )
    pipeline.name = model
    return pipeline


def injectable_tasks(suite, pipeline, count: int) -> list[str]:
    """The first `count` user tasks, in id order, whose ground truth reads an injection."""
    attack = load_attack(ATTACK, suite, pipeline)
    chosen = []
    for task_id in sorted(suite.user_tasks, key=lambda t: int(t.rsplit("_", 1)[1])):
        if attack.get_injection_candidates(suite.user_tasks[task_id]):
            chosen.append(task_id)
        if len(chosen) == count:
            return chosen
    raise SystemExit(f"only {len(chosen)} injectable tasks")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--suite", default="workspace")
    parser.add_argument("--model", default="claude-haiku-5-5")
    parser.add_argument("--tasks", type=int, default=5)
    parser.add_argument("--injections", type=int, default=2)
    parser.add_argument("--max-tokens", type=int, default=4096)
    parser.add_argument("--cap", type=float, default=2.0, help="stop past this many dollars")
    parser.add_argument("--plan", action="store_true", help="print the selection and stop")
    parser.add_argument("--smoke", action="store_true", help="run one benign task and stop")
    args = parser.parse_args()

    if args.model not in PRICES:
        raise SystemExit(f"no price held for {args.model}")
    suite = get_suite(VERSION, args.suite)
    pipeline = build_pipeline(args.model, args.max_tokens)
    user_ids = injectable_tasks(suite, pipeline, args.tasks)
    injection_ids = sorted(suite.injection_tasks, key=lambda t: int(t.rsplit("_", 1)[1]))
    injection_ids = injection_ids[: args.injections]
    print(json.dumps({"user_tasks": user_ids, "injection_tasks": injection_ids}))
    if args.plan:
        return

    args.out.mkdir(parents=True, exist_ok=True)
    meter = Meter(args.model, args.cap, args.out / "usage.jsonl")
    adapt_sdk()
    install_meter(meter)
    attack = load_attack(ATTACK, suite, pipeline)
    results = {"benign": {}, "attack": {}}
    warnings.simplefilter("ignore")
    logs = args.out / "logs"
    try:
        with OutputLogger(str(logs)):
            for user_id in user_ids:
                meter.task = f"{user_id}/none"
                utility, _ = run_task_without_injection_tasks(
                    suite, pipeline, suite.user_tasks[user_id], logs, True, VERSION
                )
                results["benign"][user_id] = utility
                print(json.dumps({"run": meter.task, "utility": utility, "spend": meter.total}))
                if args.smoke:
                    return
            for user_id in user_ids:
                for injection_id in injection_ids:
                    meter.task = f"{user_id}/{injection_id}"
                    utility, security = run_task_with_injection_tasks(
                        suite,
                        pipeline,
                        suite.user_tasks[user_id],
                        attack,
                        logs,
                        True,
                        [injection_id],
                        VERSION,
                    )
                    key = (user_id, injection_id)
                    results["attack"][meter.task] = {
                        "utility": utility[key],
                        "attack_succeeded": security[key],
                    }
                    print(json.dumps({"run": meter.task, **results["attack"][meter.task], "spend": meter.total}))
    except OverCap as err:
        print(err, file=sys.stderr)
    finally:
        (args.out / "results.json").write_text(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
