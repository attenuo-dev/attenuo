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

--endpoint URL runs a local open-weight model behind an OpenAI-compatible server instead (Ollama,
llama.cpp, vLLM), with --model as that server names it:

    python evaluation/agentdojo/pilot.py --out DIR --endpoint http://127.0.0.1:11434/v1 \
        --model qwen2.5:14b --tasks 0 --injections 0 --resume

The endpoint must be on this machine: no price is held for a remote one, so the cap could not
hold. Requests go out with temperature 0 and seed 0. Token counts are still logged, at zero
dollars. A tool call whose arguments are not a JSON object is passed on with no arguments, so the
tool's own error reaches the model, and is counted in the usage log (`bad_tool_json`). A run
that raises is recorded under `errors` in the results file and the next one starts.
"""

import argparse
import asyncio
import contextlib
import json
import os
import sys
import warnings
from pathlib import Path
from urllib.parse import urlsplit

import anthropic
import openai
from agentdojo.agent_pipeline import (
    AgentPipeline,
    AnthropicLLM,
    InitQuery,
    OpenAILLM,
    SystemMessage,
    ToolsExecutionLoop,
    ToolsExecutor,
)
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.agent_pipeline.llms import anthropic_llm, openai_llm
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import run_task_with_injection_tasks, run_task_without_injection_tasks
from agentdojo.logging import OutputLogger
from agentdojo.models import MODEL_NAMES
from agentdojo.task_suite.load_suites import get_suite

VERSION = "v1.2.2"
ATTACK = "important_instructions"
# Dollars per million tokens, input and output. Haiku 5.5 costs more on a request whose prompt
# passes 100K tokens.
PRICES = {
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-sonnet-5-5": (2.0, 10.0),
    "claude-opus-5-5": (4.0, 20.0),
    "claude-fable-5-1": (10.0, 50.0),
    # What a refusal fallback can route to.
    "claude-sonnet-5": (2.0, 10.0),
    "claude-opus-5": (5.0, 25.0),
    "claude-opus-4-8": (5.0, 25.0),
}
FALLBACK_BETA = "server-side-fallback-2026-07-01"
RATE_LIMIT_RETRIES = 20
RATE_LIMIT_WAIT_SECONDS = 30
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")
# How the attack addresses a model AgentDojo has no name for.
LOCAL_ADDRESS = "AI assistant"
LOCAL_TIMEOUT_SECONDS = 900
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
                with contextlib.suppress(ValueError, KeyError):  # another process is mid-write
                    total += json.loads(line)["dollars"]
        return total

    def rates(self, model: str, input_tokens: int) -> tuple[float, float]:
        if model not in PRICES:
            raise RuntimeError(f"no price held for {model}")
        limit, long_in, long_out = LONG_PROMPT.get(model, (float("inf"), 0, 0))
        return (long_in, long_out) if input_tokens > limit else PRICES[model]

    def cost(self, usage, model: str) -> float:
        """With a fallback, `usage.iterations` lists each attempt and top-level usage covers only
        the last. Declined attempts are counted, so a fallback run's cost is an upper bound. Any
        cached tokens count at the input rate, also an upper bound; these runs set no breakpoints.
        """
        attempts = getattr(usage, "iterations", None) or [usage]
        total = 0.0
        for attempt in attempts:
            cached = (attempt.cache_read_input_tokens or 0) + (
                attempt.cache_creation_input_tokens or 0
            )
            tokens = attempt.input_tokens + cached
            rate_in, rate_out = self.rates(getattr(attempt, "model", None) or model, tokens)
            total += (tokens * rate_in + attempt.output_tokens * rate_out) / 1e6
        return total

    def record(self, completion) -> None:
        usage = completion.usage
        dollars = self.cost(usage, completion.model)
        attempts = getattr(usage, "iterations", None) or []
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
            "fallback": any(a.type == "fallback_message" for a in attempts),
            "attempts": [[a.type, a.model, a.input_tokens, a.output_tokens] for a in attempts],
            "refusal_category": getattr(
                getattr(completion, "stop_details", None), "category", None
            ),
            "dollars": dollars,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line) + "\n")
        if self.turns % 5 == 0 and self.spent() > self.cap:
            raise OverCap(f"spend passed the ${self.cap} cap")

    def record_local(self, completion, bad_tool_json: int) -> None:
        """A response from an OpenAI-compatible local server: tokens only, no dollars."""
        usage = completion.usage
        self.turns += 1
        line = {
            "task": self.task,
            "model": completion.model,
            "input_tokens": getattr(usage, "prompt_tokens", None),
            "output_tokens": getattr(usage, "completion_tokens", None),
            "stop_reason": completion.choices[0].finish_reason,
            "bad_tool_json": bad_tool_json,
            "dollars": 0.0,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line) + "\n")


def adapt_sdk() -> None:
    # agentdojo 0.1.35 calls MessageParam(...) as a TypedDict constructor. In the current SDK it
    # is a Union, which cannot be instantiated. A plain dict is what it built anyway.
    anthropic_llm.MessageParam = dict


def drop_fallback_blocks(completion) -> None:
    """AgentDojo replays what the model returned and has no case for a `fallback` block. The API
    treats that block as an audit marker, and before the last one only text may be echoed."""
    kinds = [block.type for block in completion.content]
    if "fallback" in kinds:
        last = len(kinds) - 1 - kinds[::-1].index("fallback")
        completion.content = [
            block
            for i, block in enumerate(completion.content)
            if i > last or (i < last and block.type == "text")
        ]


def install_meter(meter: Meter, fallback: bool = False) -> None:
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
                if fallback:
                    opener = client.beta.messages.stream(
                        **fields, betas=[FALLBACK_BETA], fallbacks="default"
                    )
                else:
                    opener = client.messages.stream(**fields)
                async with opener as stream:
                    completion = await stream.get_final_message()
                break
            except anthropic.RateLimitError:
                if attempt == RATE_LIMIT_RETRIES:
                    raise
                await asyncio.sleep(RATE_LIMIT_WAIT_SECONDS)
        meter.record(completion)
        drop_fallback_blocks(completion)
        return completion

    anthropic_llm.chat_completion_request = request


def check_endpoint(endpoint: str) -> None:
    """Only a server on this machine: a remote one could bill, and no price is held for it."""
    if urlsplit(endpoint).hostname not in LOCAL_HOSTS:
        raise SystemExit(f"--endpoint must be on this machine ({', '.join(LOCAL_HOSTS)})")


def blank_bad_tool_json(completion) -> int:
    """AgentDojo parses each tool call's arguments as JSON and raises on anything else, which
    would end the run. Arguments that are not a JSON object become `{}`: the call still
    happens, and the tool's own error tells the model what it left out."""
    bad = 0
    for call in completion.choices[0].message.tool_calls or []:
        try:
            ok = isinstance(json.loads(call.function.arguments), dict)
        except (TypeError, ValueError):
            ok = False
        if not ok:
            call.function.arguments = "{}"
            bad += 1
    return bad


def install_local_meter(meter: Meter, max_tokens: int) -> None:
    """Replace agentdojo's OpenAI request function: it drops a temperature of 0, so the server's
    default sampling would apply. Sends temperature 0, a fixed seed and the token limit, and
    passes every response to the meter."""

    def request(client, model, messages, tools, reasoning_effort=None, temperature=0.0):
        fields = {
            "model": model,
            "messages": messages,
            "temperature": 0,
            "seed": 0,
            "max_tokens": max_tokens,
        }
        if tools:
            fields |= {"tools": tools, "tool_choice": "auto"}
        completion = client.chat.completions.create(**fields)
        meter.record_local(completion, blank_bad_tool_json(completion))
        return completion

    openai_llm.chat_completion_request = request


def build_llm(model: str, max_tokens: int, endpoint: str | None = None, address: str | None = None):
    """The model element: Anthropic's API, or with `endpoint` an OpenAI-compatible local server.
    The attack addresses the model by name and raises on a model it does not know."""
    if endpoint is None:
        MODEL_NAMES.setdefault(model, "Claude")
        # temperature=None: these models reject non-default sampling values.
        client = anthropic.Anthropic(max_retries=8)
        return AnthropicLLM(client, model, temperature=None, max_tokens=max_tokens)
    check_endpoint(endpoint)
    MODEL_NAMES.setdefault(model, address or LOCAL_ADDRESS)
    # A local server ignores the key; the client refuses to start without one.
    key = os.environ.get("OPENAI_COMPATIBLE_API_KEY", "local")
    client = openai.OpenAI(
        base_url=endpoint, api_key=key, max_retries=2, timeout=LOCAL_TIMEOUT_SECONDS
    )
    return OpenAILLM(client, model, temperature=0.0)


def install_meters(meter: Meter, max_tokens: int, endpoint: str | None, fallback=False) -> None:
    if endpoint is None:
        adapt_sdk()
        install_meter(meter, fallback)
    else:
        install_local_meter(meter, max_tokens)


def build_pipeline(
    model: str, max_tokens: int, endpoint: str | None = None, address: str | None = None
) -> AgentPipeline:
    llm = build_llm(model, max_tokens, endpoint, address)
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


def select_tasks(
    suite, pipeline, count: int, attack_name: str = ATTACK
) -> tuple[list[str], list[str]]:
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
    parser.add_argument("--fallback", action="store_true", help='fallbacks: "default"')
    parser.add_argument("--shard", default="0/1", help="I/N: run every Nth user task from I")
    parser.add_argument("--resume", action="store_true", help="skip runs that have a log")
    parser.add_argument("--plan", action="store_true", help="print the selection and stop")
    parser.add_argument("--smoke", action="store_true", help="run one benign task and stop")
    parser.add_argument("--endpoint", help="OpenAI-compatible base URL of a local model server")
    parser.add_argument(
        "--address-as", help=f"the attack's name for a local model ({LOCAL_ADDRESS})"
    )
    args = parser.parse_args()

    if args.endpoint is None and args.model not in PRICES:
        raise SystemExit(f"no price held for {args.model}")
    if args.endpoint and args.fallback:
        raise SystemExit("--fallback is an Anthropic API option")
    suite = get_suite(VERSION, args.suite)
    pipeline = build_pipeline(args.model, args.max_tokens, args.endpoint, args.address_as)
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
    install_meters(meter, args.max_tokens, args.endpoint, args.fallback)
    attack = load_attack(args.attack, suite, pipeline)
    results = {"benign": {}, "attack": {}, "errors": {}}
    warnings.simplefilter("ignore")
    logs = args.out / "logs"
    try:
        with OutputLogger(str(logs)):
            for user_id in benign_ids:
                meter.task = f"{args.suite}/{user_id}/none"
                try:
                    utility, _ = run_task_without_injection_tasks(
                        suite, pipeline, suite.user_tasks[user_id], logs, not args.resume, VERSION
                    )
                except Exception as err:
                    if args.endpoint is None:
                        raise
                    results["errors"][meter.task] = repr(err)[:300]
                    print(json.dumps({"run": meter.task, "error": repr(err)[:300]}), flush=True)
                    continue
                results["benign"][user_id] = utility
                print(json.dumps({"run": meter.task, "utility": utility}), flush=True)
                if args.smoke:
                    return
            for user_id in user_ids:
                for injection_id in injection_ids:
                    meter.task = f"{args.suite}/{user_id}/{injection_id}"
                    try:
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
                    except Exception as err:
                        if args.endpoint is None:
                            raise
                        results["errors"][meter.task] = repr(err)[:300]
                        print(json.dumps({"run": meter.task, "error": repr(err)[:300]}), flush=True)
                        continue
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
