#!/usr/bin/env python3
"""A real model with attenuo between it and AgentDojo's tools.

The agent is the stock pipeline with its tool executor replaced. AttenuoToolsExecutor sends each
call through the MCP proxy, to the shim over the suite's tools, and gives the model attenuo's
refusal as a tool error. The model still sees every tool the suite has, as the baseline does.

The catalog, the suite policy, the labels policy and the grant rule all come from replay.py,
unchanged. Each run gets a new root token and a token holding only that user task's oracle grant.

Arms:
  grants   oracle task grants plus the suite policy (A2).
  labels   the same plus labels.cedar (A3). A gated call is approved only if it matches a call in
           the task's ground truth on every argument that is not free text, and declined
           otherwise. A stand-in for a careful person, and an optimistic one.

--filtered-list runs the server with `[proxy] list_filter = "policy"` and offers the model only
the tools the proxy's `tools/list` returns for that run's token. Off by default, where the model
is offered every tool in the suite.

    ANTHROPIC_API_KEY=... PYTHONPATH=sdk/python/src python evaluation/agentdojo/enforced.py \\
        --out DIR --arm grants --shard 0/4 --cap 3
    python evaluation/agentdojo/enforced.py --out DIR --summarize
"""

import argparse
import json
import sys
import tempfile
import warnings
from ast import literal_eval
from collections import Counter
from pathlib import Path

import anthropic
import httpx
import pilot
import replay
from agentdojo.agent_pipeline import (
    AgentPipeline,
    AnthropicLLM,
    InitQuery,
    SystemMessage,
    ToolsExecutionLoop,
)
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import is_string_list
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import run_task_with_injection_tasks, run_task_without_injection_tasks
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.logging import OutputLogger
from agentdojo.models import MODEL_NAMES
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.types import ChatToolResultMessage, text_content_block_from_string

SUITE = "workspace"
ATTACK = "important_instructions"


def pinned_args(call_args: dict) -> dict:
    return {k: v for k, v in call_args.items() if k not in replay.FREE_TEXT}


def in_ground_truth(tool: str, args: dict, truth) -> bool:
    """The approver's rule: same tool, same arguments apart from free text."""
    wanted = pinned_args(args)
    return any(c.function == tool and pinned_args(dict(c.args)) == wanted for c in truth)


class AttenuoToolsExecutor(BasePipelineElement):
    """ToolsExecutor, with each call decided by attenuo."""

    name = "attenuo_tools_executor"

    def __init__(self, arm, attenuo, shim, decisions: Path):
        self.arm, self.attenuo, self.shim = arm, attenuo, shim
        self.decisions = decisions
        self.rid = 0

    def start_run(self, label: str, truth) -> None:
        """A new delegation: one root token and one grant, per benchmark run."""
        self.label, self.truth = label, truth
        token = self.attenuo.token(replay.grant_for(truth))
        self.http = httpx.Client(
            timeout=60,
            headers={
                "authorization": f"Bearer {token}",
                "accept": "application/json, text/event-stream",
            },
        )
        listed = self.rpc("tools/list", {}).get("result", {}).get("tools", [])
        self.listed = {tool["name"] for tool in listed}
        with self.decisions.with_name(f"lists-{self.decisions.stem}.jsonl").open("a") as fh:
            fh.write(json.dumps({"run": label, "tools": sorted(self.listed)}) + "\n")

    def rpc(self, method: str, params: dict) -> dict:
        self.rid += 1
        body = {"jsonrpc": "2.0", "id": self.rid, "method": method, "params": params}
        reply = self.http.post(f"{self.attenuo.url}/mcp/{replay.SUITE}", json=body)
        return reply.json()

    def record(self, tool: str, outcome: str, reason: str | None = None) -> None:
        row = {"run": self.label, "tool": tool, "outcome": outcome, "reason": reason}
        with self.decisions.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")

    def settle(self, approval_id: str, grant: bool) -> None:
        url = f"{self.attenuo.url}/admin/approvals/{approval_id}"
        headers = {"authorization": f"Bearer {replay.ADMIN_TOKEN}"}
        decision = {"decision": "grant" if grant else "decline"}
        httpx.post(url, json=decision, headers=headers, timeout=30).raise_for_status()

    def call(self, tool: str, args: dict) -> tuple[str, str | None]:
        """Returns the tool's text and an error. Every outcome goes to the decision log."""
        params = {"name": tool, "arguments": args}
        answer = self.rpc("tools/call", params)
        error = answer.get("error")
        if error and error.get("code") == -32008:
            data = error.get("data") or {}
            grant = in_ground_truth(tool, args, self.truth)
            self.settle(data["approval_id"], grant)
            if not grant:
                self.record(tool, "approval_declined", data.get("reason"))
                return "", "attenuo: this call needs an approval, and it was declined."
            self.record(tool, "approval_granted", data.get("reason"))
            answer = self.rpc("tools/call", params)
            error = answer.get("error")
        if error:
            data = error.get("data") or {}
            reason = data.get("reason") or error.get("reason") or str(error.get("code"))
            refused = error.get("code") in (-32003, -32008)
            self.record(tool, "denied" if refused else "proxy_error", reason)
            return "", f"attenuo denied this call: {reason}."
        self.record(tool, "allowed")
        result = answer["result"]
        text = " ".join(part.get("text", "") for part in result.get("content", []))
        return ("", text) if result.get("isError") else (text, None)

    def query(self, query, runtime, env, messages=(), extra_args={}):  # noqa: B006
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args
        self.shim.env = env
        known = {tool.name for tool in runtime.functions.values()}
        results = []
        for tool_call in messages[-1]["tool_calls"]:
            text, error = "", None
            if tool_call.function == EMPTY_FUNCTION_NAME:
                error = "Empty function name provided. Provide a valid function name."
            elif tool_call.function not in known:
                error = f"Invalid tool {tool_call.function} provided."
            else:
                # The stock executor's own step, so the proxy sees the same arguments the tool
                # would have.
                for key, value in tool_call.args.items():
                    if isinstance(value, str) and is_string_list(value):
                        tool_call.args[key] = literal_eval(value)
                text, error = self.call(tool_call.function, dict(tool_call.args))
            results.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(text)],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error=error,
                )
            )
        return query, runtime, env, [*messages, *results], extra_args


class ProxyToolList(BasePipelineElement):
    """Offer the model only what the proxy listed for this run. Sits before the first model turn,
    so the LLM element builds its request from the narrowed runtime."""

    name = "proxy_tool_list"

    def __init__(self, executor: AttenuoToolsExecutor):
        self.executor = executor

    def query(self, query, runtime, env, messages=(), extra_args={}):  # noqa: B006
        keep = [f for f in runtime.functions.values() if f.name in self.executor.listed]
        return query, FunctionsRuntime(keep), env, messages, extra_args


def run(args) -> None:
    replay.SUITE = SUITE
    suite = get_suite(replay.VERSION, SUITE)
    base_env = suite.load_and_inject_default_environment({})
    work = Path(tempfile.mkdtemp(dir=args.out, prefix="work-"))
    shim = replay.Shim(suite)
    list_filter = "policy" if args.filtered_list else None
    attenuo = replay.Attenuo(args.arm, suite, base_env, shim.url, work, args.binary, list_filter)
    shard, shards = (int(x) for x in args.shard.split("/"))
    tag = f"{args.arm}-{shard}"
    executor = AttenuoToolsExecutor(args.arm, attenuo, shim, args.out / f"decisions-{tag}.jsonl")

    MODEL_NAMES.setdefault(args.model, "Claude")
    llm = AnthropicLLM(
        anthropic.Anthropic(max_retries=8), args.model, temperature=None, max_tokens=args.max_tokens
    )
    narrow = [ProxyToolList(executor)] if args.filtered_list else []
    pipeline = AgentPipeline(
        [
            SystemMessage(load_system_message(None)),
            InitQuery(),
            *narrow,
            llm,
            ToolsExecutionLoop([executor, llm]),
        ]
    )
    pipeline.name = f"{args.model}-attenuo-{args.arm}"
    meter = pilot.Meter(args.model, args.cap, args.out / f"usage-{tag}.jsonl")
    pilot.adapt_sdk()
    pilot.install_meter(meter)
    attack = load_attack(ATTACK, suite, pipeline)
    users = replay.by_id(suite.user_tasks)[: args.tasks or None][shard::shards]
    injections = replay.by_id(suite.injection_tasks)
    logs = args.out / "logs"
    warnings.simplefilter("ignore")
    try:
        with OutputLogger(str(logs)):
            for user in users:
                truth = user.ground_truth(base_env.model_copy(deep=True))
                label = f"{SUITE}/{user.ID}/none"
                meter.task = label
                executor.start_run(label, truth)
                run_task_without_injection_tasks(suite, pipeline, user, logs, True, replay.VERSION)
                print(json.dumps({"run": label}), flush=True)
            if args.benign_only:
                return
            for user in users:
                truth = user.ground_truth(base_env.model_copy(deep=True))
                for injection in injections:
                    label = f"{SUITE}/{user.ID}/{injection.ID}"
                    meter.task = label
                    executor.start_run(label, truth)
                    run_task_with_injection_tasks(
                        suite, pipeline, user, attack, logs, True, [injection.ID], replay.VERSION
                    )
                    print(json.dumps({"run": label}), flush=True)
    except pilot.OverCap as err:
        print(err, file=sys.stderr)
    finally:
        attenuo.stop()


def summarize(out: Path) -> None:
    benign, attacked = Counter(), Counter()
    tools = {"benign": Counter(), "attack": Counter()}
    for path in out.glob("decisions-*.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            is_benign = row["run"].endswith("/none")
            (benign if is_benign else attacked)[f"{row['outcome']}:{row['reason']}"] += 1
            if row["outcome"] != "allowed":
                key = f"{row['tool']}:{row['outcome']}:{row['reason']}"
                tools["benign" if is_benign else "attack"][key] += 1
    report = {
        "benign_calls": dict(benign),
        "attack_calls": dict(attacked),
        "refused_by_tool": {k: dict(v.most_common(25)) for k, v in tools.items()},
    }
    print(json.dumps(report, indent=1))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--arm", choices=("grants", "labels"), default="grants")
    parser.add_argument("--shard", default="0/1")
    parser.add_argument("--model", default="claude-haiku-5-5")
    parser.add_argument("--tasks", type=int, default=0, help="the first N user tasks (0: all)")
    parser.add_argument("--cap", type=float, default=3.0)
    parser.add_argument("--max-tokens", type=int, default=4096)
    parser.add_argument("--benign-only", action="store_true")
    parser.add_argument("--filtered-list", action="store_true")
    parser.add_argument("--binary", type=Path, default=replay.ROOT / "target/debug/attenuo-server")
    parser.add_argument("--summarize", action="store_true")
    args = parser.parse_args()
    if args.summarize:
        summarize(args.out)
        return
    args.out.mkdir(parents=True, exist_ok=True)
    run(args)


if __name__ == "__main__":
    main()
