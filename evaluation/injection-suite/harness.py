"""Replay prompt-injection tool-call sequences against attenuo and against a bare upstream.

The environment (``policies/``) holds each suite's upstream, tool catalog and Cedar policy. The
corpus (``cases/dev/*.yaml`` and ``cases/test/*.yaml``) describes, per case, the capability grant
a user task needs and the tool calls a compromised agent would emit, each with the expected
outcome. This module loads both, writes a server config, catalog and Cedar policy, starts
``attenuo-server`` and one echoing ``fake_mcp`` upstream per suite, and replays the calls in
these arms:

``direct``             no attenuo: JSON-RPC straight to the upstream (the baseline).
``scope_only``         tool-level capabilities only (argument constraints dropped) and a
                       permit-all Cedar policy. The OAuth-scope equivalent (arm A1 in the plan).
``scope_constraints``  the case's capabilities with their argument constraints, permit-all
                       policy: what attenuated tokens give without any policy.
``policy_only``        the suite Cedar policies, but every call carries the user's root token
                       (all servers, no attenuation): what policy gives without delegation.
``attenuo``           attenuo as configured: attenuated tokens with argument constraints, the
                       suite Cedar policies, leases and audit (arm A2).
``attenuo_labels``    as ``attenuo``, plus the two ``@obligation("approval")`` policies of
                       ``policies/labels.cedar`` (output labelling, phase 1). Runs only when the
                       server answers ``-32008 approval_required``; skipped otherwise. A
                       gated call is granted or declined by the scripted approver through
                       ``POST /admin/approvals/{id}``; a granted one is retried once.
``attenuo_limits``    as ``attenuo``, with the frozen run-limit rule of
                       ``policies/limits-rule.json`` (``calls: 1`` on every capability that is
                       not a read) added to every exchanged token. Runs only when the server
                       enforces ``limits``; skipped otherwise.
``attenuo_labels_limits``  ``attenuo_labels`` plus the same rule. Approvals are settled as in
                       the labels arm, so a granted retry is charged, and a retry over a limit
                       is ``denied`` with ``retry_reason`` ``budget_exhausted``.
``attenuo_labels_args``  as ``attenuo``, plus ``policies/labels-args.cedar`` instead of
                       ``labels.cedar``: ask only when an argument of a destructive call copies
                       an unpinned value or span of an untrusted result (option (b), output
                       labelling phase 2). Approvals are settled as in the labels arm. Runs only
                       when the probe's ``-32008`` names the copied argument in
                       ``untrusted_args``; skipped otherwise.
``attenuo_usage_soft``  as ``attenuo``, plus ``policies/usage-soft.cedar``: ask for an approval
                       on the second and later call of the same destructive tool in a run
                       (``context.usage.calls >= 1``, run-limits phase 2). Approvals are settled
                       as in the labels arm. Runs only when the probe's second destructive call
                       gets ``-32008`` with ``usage`` in its data; skipped otherwise.
``attenuo_usage_host``  as ``attenuo_usage_soft``, with the web fetch counted per site: the
                       catalog entries that ``policies/url-hosts.json`` lists get ``destination =
                       "url#host"``, and ``policies/usage-host.cedar`` asks on a fetch from a
                       host the run has not fetched from (after its first fetch) instead of on
                       every second fetch. Probed like the usage arm.
``attenuo_distinct_host``  as ``attenuo``, with the ``distinct`` limit of
                       ``policies/url-hosts.json`` (at most 1 URL host) added to every exchanged
                       capability that names a listed web-fetching tool. Runs only when the
                       server enforces a host ``distinct`` limit; skipped otherwise.
``attenuo_distinct_host2``  the same with ``policies/url-hosts-max2.json`` (at most 2 URL hosts),
                       added after the browsing dev cases. Probed the same way.
``attenuo_distinct_recipient``  as ``attenuo``, with the ``distinct`` limits of
                       ``policies/distinct-recipients.json`` (at most 1 recipient) added to every
                       exchanged capability that names a listed messaging, mail or sharing tool.
                       Probed with the file's ``probe`` call; skipped when it is not refused.
``attenuo_task_limits``  as ``attenuo``, with the ``limits`` each case's grant declares (the
                       optional per-capability ``limits`` of the case schema, the figure a hop 0
                       would read off the user's task) added to the exchanged capabilities. Every
                       other arm ignores a grant's ``limits``. Only dev cases declare any (fitted
                       in ``policies/task-limits-dev.md``); on the test split the arm is
                       ``attenuo``. Probed like the limits arms.

No LLM is involved. See README.md for the method and its limits.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CASES_DIR = HERE / "cases"
POLICIES_DIR = HERE / "policies"
FROZEN_FILE = CASES_DIR / "test" / "POLICY_HASHES.json"

# The suite starts its own server and CLI and sets what they need. These are the only ATTENUO_*
# variables it reads; any other (ATTENUO_ADMIN_TOKEN, ATTENUO_SERVER, ATTENUO_TOKEN,
# ATTENUO_CONFIG, ...) comes from some other deployment and would redirect or break it.
OWN_ENV = frozenset({"ATTENUO_BIN_DIR", "ATTENUO_INTEGRATION"})


def ignore_inherited_env() -> list[str]:
    """Remove inherited ``ATTENUO_*`` variables from ``os.environ``; warn once if any were set."""
    dropped = sorted(k for k in os.environ if k.startswith("ATTENUO_") and k not in OWN_ENV)
    for k in dropped:
        del os.environ[k]
    if dropped:
        print(
            f"warning: ignoring {', '.join(dropped)} from the environment: the suite starts "
            "its own server",
            file=sys.stderr,
        )
    return dropped


ignore_inherited_env()

sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

from attenuo import (  # noqa: E402
    AdminClient,
    ApiError,
    Capability,
    Client,
    Equals,
    Limits,
    OneOf,
    Prefix,
)

ADMIN_TOKEN = "eval-admin-token"
USER = "alice"
USER_ISSUER = "https://idp.example"
ROOT_AGENT = "assistant"
WORKER = "worker"
AGENT_SECRET = "eval-worker-secret"
DECISION_HEADER = "x-attenuo-decision-id"
CODE_DENIED = -32003
CODE_UNKNOWN_SERVER = -32004
CODE_APPROVAL = -32008  # docs/design/output-labelling.md section 3.7

ARMS = (
    "direct",
    "scope_only",
    "scope_constraints",
    "policy_only",
    "attenuo",
    "attenuo_labels",
    "attenuo_limits",
    "attenuo_labels_limits",
    "attenuo_labels_args",
    "attenuo_usage_soft",
    "attenuo_usage_host",
    "attenuo_distinct_host",
    "attenuo_distinct_host2",
    "attenuo_distinct_recipient",
    "attenuo_task_limits",
)
PROXIED = ARMS[1:]
CONSTRAINED_ARMS = (
    "scope_constraints",
    "attenuo",
    "attenuo_labels",
    "attenuo_limits",
    "attenuo_labels_limits",
    "attenuo_labels_args",
    "attenuo_usage_soft",
    "attenuo_usage_host",
    "attenuo_distinct_host",
    "attenuo_distinct_host2",
    "attenuo_distinct_recipient",
    "attenuo_task_limits",
)
# Arms that load an @obligation("approval") policy and settle -32008 with the scripted approver.
LABEL_ARMS = (
    "attenuo_labels",
    "attenuo_labels_limits",
    "attenuo_labels_args",
    "attenuo_usage_soft",
    "attenuo_usage_host",
)
LABELS_POLICY = POLICIES_DIR / "labels.cedar"
# Option (b), argument-level taint (docs/design/output-labelling.md section 3.4).
ARG_LABEL_ARMS = ("attenuo_labels_args",)
LABELS_ARGS_POLICY = POLICIES_DIR / "labels-args.cedar"
# Soft run-usage limits (docs/design/run-limits.md section 3.5, phase 2): ask on the second and
# later call of one destructive tool in a run, instead of any labels policy.
USAGE_ARMS = ("attenuo_usage_soft", "attenuo_usage_host")
USAGE_SOFT_POLICY = POLICIES_DIR / "usage-soft.cedar"
# Derived destinations (docs/design/run-limits.md, phase 2, second slice): the web-fetching tools
# of the frozen catalogs, the catalog `destination` and the hard `distinct` limit the host arms
# give them. `attenuo_usage_host` counts fetches per site in a soft rule; `attenuo_distinct_host`
# refuses a fetch from more than `max` hosts per capability.
URL_HOSTS = POLICIES_DIR / "url-hosts.json"
USAGE_HOST_POLICY = POLICIES_DIR / "usage-host.cedar"
HOST_DESTINATION_ARMS = ("attenuo_usage_host",)
HOST_LIMIT_ARMS = ("attenuo_distinct_host", "attenuo_distinct_host2")
# The second host limit (`max: 2`), frozen after the browsing dev cases were written, and the
# recipient limit on messaging, mail and sharing tools, frozen after the test split was read.
URL_HOSTS_MAX2 = POLICIES_DIR / "url-hosts-max2.json"
DISTINCT_RECIPIENTS = POLICIES_DIR / "distinct-recipients.json"
RECIPIENT_LIMIT_ARMS = ("attenuo_distinct_recipient",)
# Every arm that adds a frozen `distinct` rule to exchanged capabilities, and its file.
DISTINCT_ARMS = HOST_LIMIT_ARMS + RECIPIENT_LIMIT_ARMS
DISTINCT_RULE_FILES = {
    "attenuo_distinct_host": URL_HOSTS,
    "attenuo_distinct_host2": URL_HOSTS_MAX2,
    "attenuo_distinct_recipient": DISTINCT_RECIPIENTS,
}
# The dev cases added on 2026-10-24 after the host arms' first run, whose benign task fetches
# several pages of one site or pages of two sites (docs/design/run-limits.md, "Measured:
# browsing cases"). slack-16 and slack-17 are attack variants. Reports split them out.
BROWSING_CASES = ("slack-12", "slack-13", "slack-14", "slack-15", "slack-16", "slack-17")
# The dev cases added on 2026-10-24 whose benign task needs a repeated destructive call
# (docs/design/run-limits.md, "Measured: multi-call benign cases"). Reports split them out.
MULTI_CALL_CASES = (
    "banking-12",
    "banking-13",
    "banking-14",
    "banking-15",
    "workspace-13",
    "workspace-14",
    "workspace-15",
    "slack-10",
    "slack-11",
    "travel-08",
    "github-08",
)
# Run limits (docs/design/run-limits.md section 6): these arms add the frozen rule's limits to
# every capability that is not a read.
LIMIT_ARMS = ("attenuo_limits", "attenuo_labels_limits")
LIMITS_RULE = POLICIES_DIR / "limits-rule.json"
# Per-task limits (docs/design/run-limits.md section 7, "What an operator should set"): this arm
# adds the `limits` a case's grant declares, and only this arm reads them. The fitting of the dev
# cases' figures to their task text is recorded, frozen, in TASK_LIMITS_FIT.
TASK_LIMIT_ARMS = ("attenuo_task_limits",)
TASK_LIMITS_FIT = POLICIES_DIR / "task-limits-dev.md"
# Every arm whose tokens carry a run limit; their calls may be refused at stage ``budget``.
BUDGET_ARMS = LIMIT_ARMS + DISTINCT_ARMS + TASK_LIMIT_ARMS
# Refusals by a run limit, in the capability stage after the capability check (ADR-0010).
BUDGET_REASONS = ("budget_exhausted", "budget_error", "limit_arg_invalid")
PERMIT_ALL_ARMS = ("scope_only", "scope_constraints")
# ``input`` is the proxy's check of declared argument types against the catalog, which refuses
# a mistyped argument before Cedar (reason ``input_type_mismatch``, since 799350c, 2026-10-24).
STAGES = ("name", "lease", "capability", "input", "policy", "exchange")
ROLES = ("benign", "attack")
CLASSES = ("S", "C", "D", "N")
SPLITS = ("dev", "test")

PERMIT_ALL = '@id("permit_all")\npermit(principal, action, resource);\n'

# A call's scripted ``output:`` is kept short; it is one tool result, not a document.
MAX_OUTPUT = 600
# Tools that are reads although the catalog does not mark them read-only.
EXTRA_READS = frozenset({"get_webpage"})

# Reasons the proxy gives before the policy engine runs: the request names a server or tool
# that does not exist, or a name outside the naming rule.
NAME_REASONS = ("invalid_name", "tool_not_listed", "tool_not_in_catalog", "unknown_server")
# Reasons for an argument whose JSON type is not the one the catalog declares, refused by the
# policy engine before Cedar evaluates anything (stage ``input``).
INPUT_REASONS = ("input_type_mismatch",)


# --- corpus -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Call:
    tool: str
    args: dict[str, Any]
    role: str
    expect: str
    stage: str | None
    note: str | None = None
    server: str | None = None  # None: the case's own upstream
    resolves_to: str | None = None  # where a spoofed server name lands in the direct arm
    spoof_of: str | None = None  # the real tool a spoofed tool name imitates
    holder: str = WORKER  # which agent's token makes the call (``as:`` in YAML)
    decoy: str | None = None  # sent as a duplicate, earlier ``params.name`` member
    original_label: str | None = None  # hand label before an oracle disagreement was resolved
    label_note: str | None = None  # why the label differs from, or was changed to, the oracle's
    output: str | None = None  # the text the fake upstream returns for this call (None: echo)

    def target(self, default: str) -> str:
        return self.server or default

    @property
    def label(self) -> str:
        return self.expect if self.stage is None else f"{self.expect}/{self.stage}"


@dataclass(frozen=True)
class Revoke:
    reason: str
    holder: str = WORKER  # whose lease (``lease_of:`` in YAML)


@dataclass(frozen=True)
class Delegate:
    """The holder of ``parent``'s token exchanges it for a token for ``agent`` with ``grant``."""

    parent: str
    agent: str
    grant: list[dict[str, Any]]


@dataclass(frozen=True)
class Batch:
    """Several calls in one JSON-RPC batch (one HTTP request, one server)."""

    calls: tuple[Call, ...]


Step = Call | Revoke | Delegate | Batch


@dataclass(frozen=True)
class Case:
    id: str
    suite: str
    shape: str
    attack_class: str
    cls: str
    user_task: str
    injection: str
    grant: list[dict[str, Any]]
    steps: list[Step]
    note: str | None = None
    taxonomy: str | None = None
    original_class: str | None = None
    label_note: str | None = None

    @property
    def calls(self) -> list[Call]:
        out: list[Call] = []
        for s in self.steps:
            if isinstance(s, Call):
                out.append(s)
            elif isinstance(s, Batch):
                out.extend(s.calls)
        return out

    @property
    def agents(self) -> set[str]:
        return {s.agent for s in self.steps if isinstance(s, Delegate)}


@dataclass
class Suite:
    name: str
    upstream: str
    description: str
    catalog: dict[str, dict[str, Any]]
    policy: str
    cases: list[Case] = field(default_factory=list)


class CorpusError(ValueError):
    pass


def _parse_call(where: str, raw: dict[str, Any], env: dict[str, Suite], home: Suite) -> Call:
    tool = raw.get("tool")
    server = raw.get("server")
    if not isinstance(tool, str) or not tool:
        raise CorpusError(f"{where}: a call needs a tool")
    resolves_to = raw.get("resolves_to")
    known_server = server is None or server in {s.upstream for s in env.values()}
    if not known_server and resolves_to is None:
        raise CorpusError(f"{where}: unknown server {server!r} needs resolves_to")
    target = next(
        (s for s in env.values() if s.upstream == (resolves_to or server or home.upstream)), None
    )
    if target is None:
        raise CorpusError(f"{where}: resolves_to {resolves_to!r} is not a suite upstream")
    spoof_of = raw.get("spoof_of")
    if tool not in target.catalog and spoof_of is None:
        raise CorpusError(f"{where}: tool {tool!r} is not in the {target.name} catalog")
    if spoof_of is not None and spoof_of not in target.catalog:
        raise CorpusError(f"{where}: spoof_of {spoof_of!r} is not in the {target.name} catalog")
    role, expect, stage = raw.get("role"), raw.get("expect"), raw.get("stage")
    if role not in ROLES:
        raise CorpusError(f"{where}: role must be one of {ROLES}")
    if expect not in ("allow", "deny"):
        raise CorpusError(f"{where}: expect must be allow or deny")
    if (expect == "deny") != (stage is not None):
        raise CorpusError(f"{where}: a deny needs a stage and an allow must not have one")
    if stage is not None and stage not in STAGES:
        raise CorpusError(f"{where}: stage must be one of {STAGES}")
    known = {
        "tool", "args", "role", "expect", "stage", "note", "server", "resolves_to", "spoof_of",
        "as", "decoy", "original_label", "label_note", "output",
    }  # fmt: skip
    if set(raw) - known:
        raise CorpusError(f"{where}: unknown keys {sorted(set(raw) - known)}")
    output = raw.get("output")
    if output is not None and (not isinstance(output, str) or not output.strip()):
        raise CorpusError(f"{where}: output must be a non-empty string")
    if output is not None and len(output) > MAX_OUTPUT:
        raise CorpusError(f"{where}: output is {len(output)} characters, at most {MAX_OUTPUT}")
    return Call(
        tool=tool,
        args=dict(raw.get("args") or {}),
        role=role,
        expect=expect,
        stage=stage,
        note=raw.get("note"),
        server=server,
        resolves_to=resolves_to,
        spoof_of=spoof_of,
        holder=str(raw.get("as", WORKER)),
        decoy=raw.get("decoy"),
        original_label=raw.get("original_label"),
        label_note=raw.get("label_note"),
        output=output,
    )


def is_read(suite: Suite, tool: str) -> bool:
    """A call that returns data to the agent: a read-only catalog tool, or ``get_webpage``."""
    return bool((suite.catalog.get(tool) or {}).get("readonly")) or tool in EXTRA_READS


def _parse_step(
    case_id: str, i: int, raw: dict[str, Any], env: dict[str, Suite], home: Suite
) -> Step:
    where = f"{case_id} step {i}"
    if "revoke" in raw:
        return Revoke(str(raw["revoke"]), str(raw.get("lease_of", WORKER)))
    if "delegate" in raw:
        d = raw["delegate"]
        return Delegate(str(d.get("from", WORKER)), str(d["to"]), list(d["grant"]))
    if "batch" in raw:
        calls = tuple(_parse_call(f"{where}.{j}", c, env, home) for j, c in enumerate(raw["batch"]))
        if len({c.target(home.upstream) for c in calls}) != 1 or any(c.decoy for c in calls):
            raise CorpusError(f"{where}: a batch goes to one server and has no decoys")
        if len({c.holder for c in calls}) != 1:
            raise CorpusError(f"{where}: a batch is sent with one token")
        return Batch(calls)
    return _parse_call(where, raw, env, home)


def load_environment(policies_dir: Path | None = None) -> dict[str, Suite]:
    """The frozen part of the corpus: each suite's upstream, tool catalog and Cedar policy,
    from ``policies/<suite>.yaml`` and ``policies/<suite>.cedar``. No cases."""
    d = policies_dir or POLICIES_DIR
    env: dict[str, Suite] = {}
    for p in sorted(d.glob("*.yaml")):
        doc = yaml.safe_load(p.read_text())
        name = doc["suite"]
        policy = (d / f"{name}.cedar").read_text()
        env[name] = Suite(name, doc["upstream"], doc["description"], doc["catalog"], policy)
    # The generated Cedar schema merges every tool's inputs into the generic "invoke" action, so
    # one argument name must have one type across the whole corpus.
    types: dict[str, tuple[str, str]] = {}
    for s in env.values():
        for tool, spec in s.catalog.items():
            for arg, ty in (spec.get("inputs") or {}).items():
                prev = types.setdefault(arg, (ty, f"{s.name}/{tool}"))
                if prev[0] != ty:
                    raise CorpusError(
                        f"argument {arg!r} is {ty} in {s.name}/{tool} but {prev[0]} in {prev[1]}"
                    )
    return env


GRANT_KEYS = frozenset({"server", "tool", "constraints", "limits"})


def _grant_ok(where: str, grant: list[dict[str, Any]], env: dict[str, Suite], home: Suite) -> None:
    for g in grant:
        if not isinstance(g, dict) or set(g) - GRANT_KEYS:
            extra = sorted(set(g) - GRANT_KEYS) if isinstance(g, dict) else g
            raise CorpusError(f"{where}: a grant entry has unknown keys {extra}")
        server = g.get("server", home.upstream)
        target = next((s for s in env.values() if s.upstream == server), None)
        if target is None:
            raise CorpusError(f"{where}: granted server {server!r} is not a suite upstream")
        tool = g.get("tool")
        if not isinstance(tool, str) or not tool:
            raise CorpusError(f"{where}: a grant entry needs a tool")
        if tool != "*" and not tool.endswith("*") and tool not in target.catalog:
            raise CorpusError(f"{where}: granted tool {tool!r} is not in the catalog")
        if "limits" in g:
            _grant_limits_ok(f"{where} {server}/{tool}", g["limits"], target, tool)


def _grant_limits_ok(where: str, limits: Any, suite: Suite, tool: str) -> None:
    """A grant's ``limits``: the token's shape (``calls``, ``sum``, ``calls_per``, ``distinct``,
    with ``derive``, checked by the SDK as the server checks it), on one catalog tool, each figure
    at least 1, each argument an input of that tool, a ``sum`` over a ``long`` and a host
    derivation over a ``string``."""
    if not isinstance(limits, dict) or not limits:
        raise CorpusError(f"{where}: limits must be a non-empty mapping")
    try:
        typed = Limits.from_json(limits)
    except ValueError as e:
        raise CorpusError(f"{where}: {e}") from None
    if "*" in tool:
        raise CorpusError(f"{where}: limits need one catalog tool, not a glob")
    if typed.calls is not None and typed.calls < 1:
        raise CorpusError(f"{where}: limits.calls must be at least 1")
    inputs = suite.catalog[tool].get("inputs") or {}
    for kind in ("sum", "calls_per", "distinct"):
        lim = getattr(typed, kind)
        if lim is None:
            continue
        if lim.max < 1:
            raise CorpusError(f"{where}: limits.{kind}.max must be at least 1")
        ty = inputs.get(lim.arg)
        if ty is None:
            raise CorpusError(f"{where}: limits.{kind}.arg {lim.arg!r} is not an input of {tool}")
        if kind == "sum" and ty != "long":
            raise CorpusError(f"{where}: limits.sum.arg {lim.arg!r} is {ty}, not long")
        if lim.derive == "host" and ty != "string":
            raise CorpusError(f"{where}: limits.{kind} derives a host from {ty} {lim.arg!r}")


def load_cases(path: Path, suite: Suite, env: dict[str, Suite] | None = None) -> list[Case]:
    env = env if env is not None else {suite.name: suite}
    doc = yaml.safe_load(path.read_text())
    if doc.get("suite") != suite.name:
        raise CorpusError(f"{path}: suite must be {suite.name!r}")
    out: list[Case] = []
    seen: set[str] = set()
    for raw in doc["cases"]:
        cid = raw["id"]
        if cid in seen:
            raise CorpusError(f"duplicate case id {cid}")
        seen.add(cid)
        steps = [_parse_step(cid, i, s, env, suite) for i, s in enumerate(raw["calls"])]
        case = Case(
            id=cid,
            suite=suite.name,
            shape=raw["shape"],
            attack_class=raw["attack_class"],
            cls=raw["class"],
            user_task=raw["user_task"],
            injection=raw["injection"],
            grant=list(raw["grant"]),
            steps=steps,
            note=raw.get("note"),
            taxonomy=raw.get("taxonomy"),
            original_class=raw.get("original_class"),
            label_note=raw.get("label_note"),
        )
        if case.cls not in CLASSES:
            raise CorpusError(f"{cid}: class must be one of {CLASSES}")
        if not any(c.role == "attack" for c in case.calls):
            raise CorpusError(f"{cid}: a case needs at least one attack call")
        _grant_ok(cid, case.grant, env, suite)
        holders = {WORKER}
        for s in case.steps:
            if isinstance(s, Delegate):
                _grant_ok(cid, s.grant, env, suite)
                holders.add(s.agent)
        for c in case.calls:
            if c.holder not in holders:
                raise CorpusError(f"{cid}: call by {c.holder!r}, who never gets a token")
        out.append(case)
    return out


def load_corpus(split: str = "dev", cases_dir: Path | None = None) -> list[Suite]:
    """Every suite of the environment that has cases in one split (``cases/<split>/``)."""
    if split not in SPLITS:
        raise CorpusError(f"split must be one of {SPLITS}")
    d = cases_dir or CASES_DIR / split
    env = load_environment()
    suites = []
    for p in sorted(d.glob("*.yaml")):
        name = yaml.safe_load(p.read_text())["suite"]
        if name not in env:
            raise CorpusError(f"{p}: no suite {name!r} in policies/")
        s = env[name]
        s.cases = load_cases(p, s, env)
        suites.append(s)
    ids = [c.id for s in suites for c in s.cases]
    if len(ids) != len(set(ids)):
        raise CorpusError("case ids must be unique across the split")
    return suites


def case_files(split: str) -> dict[str, str]:
    return {p.name: sha256_file(p) for p in sorted((CASES_DIR / split).glob("*.yaml"))}


# --- freeze -----------------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def policy_hashes() -> dict[str, str]:
    """SHA-256 of every file under ``policies/`` (Cedar policies and catalogs), by file name."""
    return {p.name: sha256_file(p) for p in sorted(POLICIES_DIR.iterdir()) if p.is_file()}


def frozen_hashes() -> dict[str, Any]:
    return dict(json.loads(FROZEN_FILE.read_text()))


def freeze_violations() -> list[str]:
    """Differences between ``policies/`` now and the hashes frozen before the test split was
    written. Empty means test numbers may be reported."""
    if not FROZEN_FILE.exists():
        return [f"{FROZEN_FILE.name} is missing"]
    frozen = frozen_hashes()["files"]
    now = policy_hashes()
    out = []
    for name in sorted(set(frozen) | set(now)):
        if name not in now:
            out.append(f"policies/{name} was removed")
        elif name not in frozen:
            out.append(f"policies/{name} was added")
        elif frozen[name] != now[name]:
            out.append(
                f"policies/{name} changed (sha256 {now[name][:12]}, frozen {frozen[name][:12]})"
            )
    return out


# --- capabilities -----------------------------------------------------------------------------


def _constraint(spec: dict[str, Any]) -> Equals | OneOf | Prefix:
    (op, value), *rest = spec.items()
    if rest:
        raise CorpusError(f"one operator per constraint, got {spec}")
    if op == "equals":
        return Equals(value)
    if op == "one_of":
        return OneOf(*value)
    if op == "prefix":
        return Prefix(str(value))
    raise CorpusError(f"unknown constraint operator {op!r}")


def grant_capabilities(
    upstream: str, grant: list[dict[str, Any]], *, constraints: bool, limits: bool = False
) -> list[Capability]:
    """The capabilities of a grant. ``limits`` (the per-task arm only) also carries each entry's
    ``limits``; without it they are ignored, so every other arm's tokens are as before."""
    caps = []
    for g in grant:
        cons = (
            {k: _constraint(v) for k, v in (g.get("constraints") or {}).items()}
            if constraints
            else {}
        )
        cap = Capability(g.get("server", upstream), g["tool"], **cons)
        if limits and g.get("limits"):
            cap.limits = Capability.from_json(
                {"server": cap.server, "tool": cap.tool, "limits": g["limits"]}
            ).limits
        caps.append(cap)
    return caps


def capabilities(
    suite: Suite, case: Case, *, constraints: bool, limits: bool = False
) -> list[Capability]:
    return grant_capabilities(suite.upstream, case.grant, constraints=constraints, limits=limits)


def task_limits(suites: list[Suite]) -> dict[str, list[dict[str, Any]]]:
    """Every case whose grant (or a delegate step's grant) declares ``limits``, as ``{case id:
    [{"server", "tool", "limits"}]}`` in grant order. Cases without any are left out."""
    out: dict[str, list[dict[str, Any]]] = {}
    for s in suites:
        for c in s.cases:
            grants = [c.grant] + [st.grant for st in c.steps if isinstance(st, Delegate)]
            rows = [
                {"server": g.get("server", s.upstream), "tool": g["tool"], "limits": g["limits"]}
                for grant in grants
                for g in grant
                if g.get("limits")
            ]
            if rows:
                out[c.id] = rows
    return out


def task_limits_unset(suites: list[Suite]) -> dict[str, str]:
    """Why each case that declares no ``limits`` has none, in the words of
    ``policies/task-limits-dev.md``: a tool glob in the grant, a grant of reads only, or (any
    other) a task that states no figure."""
    env = {s.upstream: s for s in load_environment().values()}
    declared = task_limits(suites)
    out: dict[str, str] = {}
    for s in suites:
        for c in s.cases:
            if c.id in declared:
                continue
            caps = grant_capabilities(s.upstream, c.grant, constraints=False)
            if any("*" in cap.tool for cap in caps):
                out[c.id] = "the grant is a tool glob, which takes no limit"
            elif all(is_read_capability(cap, env) for cap in caps):
                out[c.id] = "read-only task"
            else:
                out[c.id] = "the task states no figure"
    return out


def limits_rule(path: Path | None = None) -> dict[str, Any]:
    """The frozen rule's ``limits`` object (``policies/limits-rule.json``), checked the way the
    SDK checks a capability's limits."""
    limits = dict(json.loads((path or LIMITS_RULE).read_text())["limits"])
    Capability.from_json({"server": "x", "tool": "y", "limits": limits})  # raises if malformed
    return limits


def url_hosts(path: Path | None = None) -> dict[str, Any]:
    """The frozen ``policies/url-hosts.json``: ``tools`` (web-fetching tools by upstream),
    ``destination`` (their catalog destination) and ``limits`` (the host arm's limit), with the
    limits checked the way the SDK checks a capability's."""
    doc = dict(json.loads((path or URL_HOSTS).read_text()))
    Capability.from_json({"server": "x", "tool": "y", "limits": doc["limits"]})
    return doc


def apply_host_limit(
    caps: list[Capability], tools: dict[str, list[str]], limits: dict[str, Any]
) -> list[Capability]:
    """Add ``limits`` to every capability in ``caps`` that names exactly one tool of ``tools``
    (by upstream), in place. A glob is not such a tool, whatever it matches."""
    for cap in caps:
        if cap.tool in tools.get(cap.server, ()):
            cap.limits = Capability.from_json(
                {"server": cap.server, "tool": cap.tool, "limits": limits}
            ).limits
    return caps


def distinct_rule(arm: str) -> dict[str, dict[str, dict[str, Any]]]:
    """The frozen ``distinct`` rule of an arm in ``DISTINCT_ARMS``, as ``{upstream: {tool:
    limits}}``. A host file (``url-hosts*.json``) gives every listed tool its one ``limits``; the
    recipient file lists ``limits`` per tool. Each is checked the way the SDK checks one."""
    path = DISTINCT_RULE_FILES[arm]
    doc = dict(json.loads(path.read_text()))
    if arm in HOST_LIMIT_ARMS:
        hosts = url_hosts(path)
        rule = {u: {t: dict(hosts["limits"]) for t in ts} for u, ts in hosts["tools"].items()}
    else:
        rule = {u: {t: dict(lim) for t, lim in ts.items()} for u, ts in doc["tools"].items()}
    for u, ts in rule.items():
        for t, lim in ts.items():
            Capability.from_json({"server": u, "tool": t, "limits": lim})
    return rule


def apply_distinct_rule(
    caps: list[Capability], rule: dict[str, dict[str, dict[str, Any]]]
) -> list[Capability]:
    """Add each tool's limits from ``rule`` to every capability in ``caps`` that names exactly
    that tool (by upstream), in place. A glob is not such a tool, whatever it matches."""
    for cap in caps:
        lim = rule.get(cap.server, {}).get(cap.tool)
        if lim is not None:
            cap.limits = Capability.from_json(
                {"server": cap.server, "tool": cap.tool, "limits": lim}
            ).limits
    return caps


def is_read_capability(cap: Capability, env: dict[str, Suite]) -> bool:
    """A capability that names exactly one read (``env`` is keyed by upstream). A glob is not
    a read, whatever it matches."""
    suite = env.get(cap.server)
    return "*" not in cap.tool and suite is not None and is_read(suite, cap.tool)


def apply_limits_rule(
    caps: list[Capability], env: dict[str, Suite], limits: dict[str, Any]
) -> list[Capability]:
    """Add ``limits`` to every capability in ``caps`` that is not a read (in place)."""
    for cap in caps:
        if not is_read_capability(cap, env):
            cap.limits = Capability.from_json(
                {"server": cap.server, "tool": cap.tool, "limits": limits}
            ).limits
    return caps


# --- config generation ------------------------------------------------------------------------


def _toml_str(s: str) -> str:
    return json.dumps(s)  # a JSON string is a valid TOML basic string for the text used here


def _toml_type(ty: str) -> str:
    """Render a catalog argument type: ``string`` stays ``"string"``, ``set<string>`` becomes
    ``{ set = "string" }`` (the server's catalog reads sets as a one-key table)."""
    t = ty.replace(" ", "").lower()
    if t.startswith("set<") and t.endswith(">"):
        return f"{{ set = {_toml_type(t[4:-1])} }}"
    return _toml_str(t)


def agent_ids(suites: list[Suite]) -> list[str]:
    """Every agent that receives a token by exchange: the worker, any delegate target, and the
    root agent (so that a delegation back to it fails on the chain rule, not on a secret)."""
    names = {WORKER, ROOT_AGENT}
    for s in suites:
        for c in s.cases:
            names |= c.agents
    return sorted(names)


def labels_policy(arm: str) -> Path:
    """The approval policy file an arm in ``LABEL_ARMS`` loads."""
    if arm in HOST_DESTINATION_ARMS:
        return USAGE_HOST_POLICY
    if arm in USAGE_ARMS:
        return USAGE_SOFT_POLICY
    return LABELS_ARGS_POLICY if arm in ARG_LABEL_ARMS else LABELS_POLICY


def write_config(
    work: Path,
    env: list[Suite],
    port: int,
    upstream_urls: dict[str, str],
    arm: str,
    agents: list[str],
) -> Path:
    """Write ``config.toml`` and ``policy.cedar`` for one arm into ``work``."""
    policy = work / "policy.cedar"
    if arm in PERMIT_ALL_ARMS:
        policy.write_text(PERMIT_ALL)
    else:
        text = "\n".join(f"// ---- suite {s.name} ----\n{s.policy}" for s in env)
        if arm in LABEL_ARMS:
            labels = labels_policy(arm)
            text += f"\n// ---- approval policy ({labels.name}) ----\n{labels.read_text()}"
        policy.write_text(text)
    secret_sha = hashlib.sha256(AGENT_SECRET.encode()).hexdigest()
    destinations: dict[str, list[str]] = {}
    if arm in HOST_DESTINATION_ARMS:
        hosts = url_hosts()
        destinations = {u: list(ts) for u, ts in hosts["tools"].items()}
    lines = [
        "# Generated by evaluation/injection-suite/harness.py. Do not edit.",
        "[server]",
        f'listen = "127.0.0.1:{port}"',
        "[issuer]",
        f'issuer = "http://127.0.0.1:{port}"',
        'audience = "attenuo"',
        "default_ttl_seconds = 900",
        "[policy]",
        f"policies_path = {_toml_str(str(policy))}",
    ]
    for s in env:
        for tool, spec in s.catalog.items():
            lines.append(f"[policy.catalog.{s.upstream}.{tool}]")
            if spec.get("readonly"):
                lines.append("readonly = true")
            if spec.get("sensitive"):
                lines.append("sensitive = true")
            if tool in destinations.get(s.upstream, ()):
                lines.append(f"destination = {_toml_str(hosts['destination'])}")
            inputs = ", ".join(
                f"{k} = {_toml_type(v)}" for k, v in (spec.get("inputs") or {}).items()
            )
            lines.append(f"inputs = {{ {inputs} }}")
    lines += [
        "[audit]",
        f"sqlite_path = {_toml_str(str(work / 'audit.db'))}",
        "[admin]",
        f'token = "{ADMIN_TOKEN}"',
    ]
    for s in env:
        lines += ["[[upstreams]]", f'name = "{s.upstream}"', f'url = "{upstream_urls[s.upstream]}"']
    caps = ", ".join(f'"{s.upstream}:*"' for s in env)
    lines += [
        "[[root_grants]]",
        f'subject = "{USER}"',
        f'issuer = "{USER_ISSUER}"',
        f'agent = "{ROOT_AGENT}"',
        f"capabilities = [{caps}]",
    ]
    for a in agents:
        lines += ["[[agents]]", f'id = "{a}"', f'secret_sha256 = "{secret_sha}"']
    lines += ["[dev]", "allow_root_mint = true"]
    cfg = work / "config.toml"
    cfg.write_text("\n".join(lines) + "\n")
    return cfg


# --- processes --------------------------------------------------------------------------------


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@dataclass(frozen=True)
class Binaries:
    server: Path
    cli: Path
    fake_mcp: Path


def find_binaries() -> Binaries:
    """Prebuilt binaries from ``ATTENUO_BIN_DIR``, else ``target/debug`` (run ``cargo build``).
    ``fake_mcp`` is taken from the directory itself or from ``examples/``, whichever is newer."""
    given = os.environ.get("ATTENUO_BIN_DIR")
    d = Path(given) if given else ROOT / "target" / "debug"
    fakes = [p for p in (d / "fake_mcp", d / "examples" / "fake_mcp") if p.exists()]
    fake = max(fakes, key=lambda p: p.stat().st_mtime) if fakes else d / "fake_mcp"
    bins = Binaries(d / "attenuo-server", d / "attenuo", fake)
    missing = [str(p) for p in (bins.server, bins.cli, bins.fake_mcp) if not p.exists()]
    if missing:
        raise FileNotFoundError(
            "missing binaries: " + ", ".join(missing) + ". Set ATTENUO_BIN_DIR or build with "
            "`cargo build -p attenuo-server -p attenuo-cli` and "
            "`cargo build -p attenuo-proxy --features testing --example fake_mcp`."
        )
    return bins


class ArmUnsupported(RuntimeError):
    """The binaries cannot run this arm (the labels arm before the server emits ``-32008``)."""


@dataclass
class Upstream:
    name: str
    url: str
    log: Path

    def script(self, http: httpx.Client, outputs: dict[str, list[str]]) -> None:
        """Set the texts ``fake_mcp`` returns for the next calls of each tool (empty: clear)."""
        url = self.url.rsplit("/mcp", 1)[0] + "/script"
        r = http.post(url, json={"outputs": outputs})
        if r.status_code != 204:
            raise RuntimeError(
                f"fake_mcp at {url} answered {r.status_code} to a scripted output; rebuild it "
                "(`cargo build -p attenuo-proxy --features testing --example fake_mcp`)"
            )

    def received(self) -> list[tuple[str, Any]]:
        """Every ``tools/call`` this upstream logged, as (tool name, arguments)."""
        out: list[tuple[str, Any]] = []
        marker = "fake-mcp: tools/call "
        for line in self.log.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.startswith(marker):
                continue
            name, _, args = line[len(marker) :].partition(" ")
            try:
                out.append((name, json.loads(args)))
            except ValueError:
                out.append((name, None))
        return out

    def calls(self) -> int:
        return len(self.received())


@dataclass
class Stack:
    url: str
    work: Path
    config: Path
    upstreams: dict[str, Upstream]
    bins: Binaries

    def cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = {**os.environ, "ATTENUO_SERVER": self.url, "ATTENUO_ADMIN_TOKEN": ADMIN_TOKEN}
        return subprocess.run(
            [str(self.bins.cli), *args], env=env, capture_output=True, text=True, timeout=60
        )


def _wait(cond: Any, what: str, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return
        time.sleep(0.05)
    raise TimeoutError(f"{what} did not come up within {timeout}s")


@contextmanager
def upstreams(suites: list[Suite], bins: Binaries, work: Path) -> Iterator[dict[str, Upstream]]:
    procs: list[subprocess.Popen[bytes]] = []
    ups: dict[str, Upstream] = {}
    try:
        for s in suites:
            out, log = work / f"{s.upstream}.out", work / f"{s.upstream}.log"
            with out.open("wb") as fo, log.open("wb") as fl:
                procs.append(
                    subprocess.Popen(
                        [str(bins.fake_mcp), "--port", "0", "--tools", ",".join(s.catalog)],
                        stdout=fo,
                        stderr=fl,
                    )
                )
            _wait(lambda out=out: "listening on" in out.read_text(), f"fake_mcp {s.upstream}")
            url = out.read_text().split("listening on", 1)[1].split()[0]
            ups[s.upstream] = Upstream(s.upstream, url, log)
        yield ups
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            p.wait(timeout=10)


@contextmanager
def server(
    env: list[Suite],
    bins: Binaries,
    work: Path,
    ups: dict[str, Upstream],
    arm: str,
    agents: list[str],
) -> Iterator[Stack]:
    arm_dir = work / arm
    arm_dir.mkdir()
    port = free_port()
    cfg = write_config(arm_dir, env, port, {k: u.url for k, u in ups.items()}, arm, agents)
    lint = subprocess.run(
        [str(bins.cli), "policy", "lint", str(arm_dir / "policy.cedar"), "--config", str(cfg)],
        capture_output=True,
        text=True,
    )
    if lint.returncode != 0 and arm in LABEL_ARMS:
        lines = (lint.stdout + lint.stderr).strip().splitlines()
        first = next((ln for ln in lines if "error" in ln), lines[0] if lines else "no output")
        first = first[first.find("error") :] if "error" in first else first  # drop the tmp path
        what = "run-usage" if arm in USAGE_ARMS else "output-labelling"
        if arm in HOST_DESTINATION_ARMS:
            what = "run-usage attributes or derived catalog destinations (`url#host`)"
        else:
            what += " attributes"
        raise ArmUnsupported(
            f"`attenuo policy lint` rejects policies/{labels_policy(arm).name} with its catalog, "
            f"so this server has no {what} ({first})"
        )
    if lint.returncode != 0:
        raise RuntimeError(f"policy lint failed for arm {arm}:\n{lint.stdout}{lint.stderr}")
    url = f"http://127.0.0.1:{port}"
    with (arm_dir / "server.log").open("wb") as log:
        proc = subprocess.Popen(
            [str(bins.server), "--config", str(cfg)],
            stdout=log,
            stderr=subprocess.STDOUT,
            env={**os.environ, "RUST_LOG": "warn"},
        )
    try:

        def healthy() -> bool:
            if proc.poll() is not None:
                raise RuntimeError(
                    f"attenuo-server exited:\n{(arm_dir / 'server.log').read_text()[-2000:]}"
                )
            try:
                return httpx.get(f"{url}/healthz", timeout=1).status_code == 200
            except httpx.HTTPError:
                return False

        _wait(healthy, "attenuo-server")
        yield Stack(url, arm_dir, cfg, ups, bins)
    finally:
        proc.terminate()
        proc.wait(timeout=10)


# --- replay -----------------------------------------------------------------------------------


def stage_of(reason: str | None) -> str | None:
    if reason is None:
        return None
    if reason in NAME_REASONS:
        return "name"
    if reason.startswith("exchange_refused"):
        return "exchange"
    if reason in BUDGET_REASONS:
        return "budget"
    if reason.startswith("capability_"):
        return "capability"
    if reason in INPUT_REASONS:
        return "input"
    if reason.startswith("policy_") or reason == "attribute_type_mismatch":
        return "policy"
    if reason.startswith("lease_"):
        return "lease"
    if reason == "approval_required":
        return "approval"
    return "other"


@dataclass
class CallResult:
    case: str
    suite: str
    arm: str
    index: int
    tool: str
    server: str
    holder: str
    role: str
    expect: str
    expect_stage: str | None
    outcome: str  # allow | deny | gated (approval required) | error
    reason: str | None
    stage: str | None
    decision_id: str | None
    reached_upstream: bool
    args_intact: bool | None  # the upstream got exactly the call's arguments (None: not reached)
    note: str | None = None
    detail: str | None = None
    spoof: bool = False
    approval: str | None = None  # gated calls: what the scripted approver answered
    approval_id: str | None = None  # gated calls: data.approval_id of the -32008
    output_returned: bool | None = None  # the scripted output came back (None: none scripted)
    # Gated calls in the labels arm, after the scripted approver's decision (see AFTER_APPROVAL).
    after_approval: str | None = None
    approval_state: str | None = None  # GET /admin/approvals/{id} after the decision and retry
    approval_consumed_by: str | None = None  # its consumed_by: the retry's decision id
    retry_reason: str | None = None
    retry_stage: str | None = None  # stage_of(retry_reason): ``budget`` for a run-limit refusal
    retry_decision_id: str | None = None
    retry_reached_upstream: bool | None = None
    retry_output_returned: bool | None = None

    @property
    def as_expected(self) -> bool:
        return self.outcome == self.expect and self.stage == self.expect_stage

    @property
    def audited(self) -> bool:
        """Whether an audit record exists: refusals before authentication (unknown server) and
        calls never sent (the delegation was refused) have none."""
        return self.arm != "direct" and self.stage != "exchange" and self.reason != "unknown_server"

    def to_json(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        d["as_expected"] = self.as_expected if self.arm == "attenuo" else None
        return d


def _canon(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class _Observer:
    """What every upstream logged between two points, matched to the calls of one request."""

    def __init__(self, ups: dict[str, Upstream]) -> None:
        self.ups = ups
        self.before = {k: u.calls() for k, u in ups.items()}

    def take(self) -> dict[str, list[tuple[str, Any]]]:
        return {k: u.received()[self.before[k] :] for k, u in self.ups.items()}


def _delivered(
    new: dict[str, list[tuple[str, Any]]], upstream: str | None, call: Call
) -> tuple[bool, bool | None]:
    """Pop the line for ``call`` from ``new``: (reached the upstream, arguments intact)."""
    lines = new.get(upstream or "", [])
    for i, (name, args) in enumerate(lines):
        if name == call.tool:
            lines.pop(i)
            return True, _canon(args) == _canon(call.args)
    return False, None


def _echoed(msg: dict[str, Any] | None, call: Call) -> tuple[bool, bool | None]:
    """(reached, arguments intact) from fake_mcp's echo ``{"name", "arguments"}`` in a reply."""
    try:
        echo = json.loads((msg or {})["result"]["content"][0]["text"])
    except (KeyError, IndexError, TypeError, ValueError):
        return False, None
    if echo.get("name") != call.tool:
        return False, None
    return True, _canon(echo.get("arguments")) == _canon(call.args)


def _rpc_body(call: Call, rid: int) -> Any:
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "method": "tools/call",
        "params": {"name": call.tool, "arguments": call.args},
    }


# What became of a gated call (labels arm) once the scripted approver answered:
#   allowed      granted, and the identical retry from the same hop was allowed
#   denied       granted, but the retry was denied (``-32003``)
#   declined     declined through the approvals API; not retried
#   no_decision  the ``-32008`` carried no ``approval_id``, so nothing could be decided
#   gated        granted, and the retry got ``-32008`` again (a failure: the grant was not used)
#   error        granted, and the retry got some other error, or the decision was refused
AFTER_APPROVAL = ("allowed", "denied", "declined", "no_decision", "gated", "error")


def after_approval_of(retry_outcome: str) -> str:
    """The ``after_approval`` value of a granted call whose retry had ``retry_outcome``."""
    return {"allow": "allowed", "deny": "denied", "gated": "gated"}.get(retry_outcome, "error")


def scripted_approver(call: Call) -> bool:
    """The replay's stand-in for the user at the approval page: approves a call the case labels
    benign, declines one it labels attack (design section 6). Only the hand label decides."""
    return call.role == "benign"


def _returned(msg: dict[str, Any] | None, output: str | None) -> bool | None:
    """Whether a reply's content carries the call's scripted output (None: nothing scripted)."""
    if output is None:
        return None
    try:
        content = (msg or {})["result"]["content"]
    except (KeyError, TypeError):
        return False
    return any(isinstance(c, dict) and c.get("text") == output for c in content)


def _decoy_bytes(call: Call, rid: int) -> bytes:
    """A request whose ``params`` names the decoy first and the real tool second. Parsers that
    keep the last duplicate member (serde_json, Python) see the real tool."""
    params = (
        f'{{"name":{json.dumps(call.decoy)},"arguments":{json.dumps(call.args)},'
        f'"name":{json.dumps(call.tool)}}}'
    )
    return f'{{"jsonrpc":"2.0","id":{rid},"method":"tools/call","params":{params}}}'.encode()


def _parse_messages(resp: httpx.Response) -> list[dict[str, Any]]:
    text = resp.text
    if "event-stream" in resp.headers.get("content-type", ""):
        out = []
        for block in text.replace("\r\n", "\n").split("\n\n"):
            data = "\n".join(
                ln[5:].removeprefix(" ") for ln in block.split("\n") if ln.startswith("data:")
            )
            if data.strip():
                try:
                    v = json.loads(data)
                except ValueError:
                    continue
                out.extend(v if isinstance(v, list) else [v])
        return out
    try:
        v = json.loads(text)
    except ValueError:
        return []
    return v if isinstance(v, list) else [v]


def _judge(msg: dict[str, Any] | None, header_ids: list[str]) -> tuple[str, str | None, str | None]:
    """(outcome, reason, decision id) of one JSON-RPC reply."""
    if msg is None:
        return "error", "no_reply", None
    err = msg.get("error")
    if isinstance(err, dict):
        data: dict[str, Any] = err["data"] if isinstance(err.get("data"), dict) else {}
        if err.get("code") == CODE_DENIED and data.get("decision_id") in header_ids:
            return "deny", str(data.get("reason")), str(data.get("decision_id"))
        if err.get("code") == CODE_UNKNOWN_SERVER:
            return "deny", "unknown_server", None
        if err.get("code") == CODE_APPROVAL and data.get("reason") == "approval_required":
            did = data.get("decision_id")
            return "gated", "approval_required", None if did is None else str(did)
        return "error", f"rpc_{err.get('code')}", None
    res = msg.get("result") or {}
    return ("error" if res.get("isError") else "allow"), None, None


def _approval_id(msg: dict[str, Any] | None) -> str | None:
    """``data.approval_id`` of a ``-32008`` reply, if the server opened an approval."""
    err = (msg or {}).get("error")
    data = err.get("data") if isinstance(err, dict) else None
    aid = data.get("approval_id") if isinstance(data, dict) else None
    return aid if isinstance(aid, str) and aid else None


class _Replayer:
    """Replays one case's steps in one arm and records a CallResult per call."""

    def __init__(
        self,
        arm: str,
        suite: Suite,
        case: Case,
        ups: dict[str, Upstream],
        http: httpx.Client,
        stack: Stack | None = None,
        ob: Client | None = None,
        admin: AdminClient | None = None,
    ) -> None:
        self.arm, self.suite, self.case, self.ups, self.http = arm, suite, case, ups, http
        self.stack, self.ob, self.admin = stack, ob, admin
        self.env: dict[str, Suite] = {}
        self.limits: dict[str, Any] | None = None
        self.distinct: dict[str, dict[str, dict[str, Any]]] | None = None
        if arm in LIMIT_ARMS:
            self.env = {s.upstream: s for s in load_environment().values()}
            self.limits = limits_rule()
        if arm in DISTINCT_ARMS:
            self.distinct = distinct_rule(arm)
        self.tokens: dict[str, Any] = {}
        self.refused: dict[str, str] = {}
        self.out: list[CallResult] = []
        self.index = 0
        self.rid = 0

    # tokens
    def start(self, all_upstreams: list[str]) -> None:
        if self.arm == "direct":
            return
        assert self.ob is not None and self.admin is not None
        root = self.admin.mint_root_dev(
            USER, USER_ISSUER, ROOT_AGENT, [f"{u}:*" for u in all_upstreams]
        )
        if self.arm == "policy_only":
            self.tokens[WORKER] = root
            return
        caps = self._limited(
            capabilities(
                self.suite,
                self.case,
                constraints=self.arm in CONSTRAINED_ARMS,
                limits=self.arm in TASK_LIMIT_ARMS,
            )
        )
        self.tokens[WORKER] = self.ob.exchange(root, WORKER, caps, client_secret=AGENT_SECRET)

    def _limited(self, caps: list[Capability]) -> list[Capability]:
        if self.distinct is not None:
            apply_distinct_rule(caps, self.distinct)
        if self.limits is None:
            return caps
        return apply_limits_rule(caps, self.env, self.limits)

    def delegate(self, d: Delegate) -> None:
        if self.arm == "direct":
            return
        if d.parent in self.refused or d.parent not in self.tokens:
            self.refused[d.agent] = self.refused.get(d.parent, "no_parent_token")
            return
        if self.arm == "policy_only":
            self.tokens[d.agent] = self.tokens[d.parent]
            return
        assert self.ob is not None
        caps = self._limited(
            grant_capabilities(
                self.suite.upstream,
                d.grant,
                constraints=self.arm in CONSTRAINED_ARMS,
                limits=self.arm in TASK_LIMIT_ARMS,
            )
        )
        try:
            self.tokens[d.agent] = self.ob.exchange(
                self.tokens[d.parent], d.agent, caps, client_secret=AGENT_SECRET
            )
        except ApiError as e:
            self.refused[d.agent] = f"{e.error}:{e.detail or e.description or ''}"

    def revoke(self, r: Revoke) -> None:
        if self.arm == "direct" or r.holder not in self.tokens:
            return
        assert self.admin is not None
        tok = self.tokens[r.holder]
        assert tok.lease is not None
        self.admin.revoke_lease(tok.lease, r.reason)

    # calls
    def _record(self, call: Call, outcome: str, reason: str | None, decision: str | None,
                reached: bool, intact: bool | None, detail: str | None = None,
                returned: bool | None = None, approval_id: str | None = None,
                after: dict[str, Any] | None = None) -> None:  # fmt: skip
        self.out.append(
            CallResult(
                case=self.case.id,
                suite=self.suite.name,
                arm=self.arm,
                index=self.index,
                tool=call.tool,
                server=call.target(self.suite.upstream),
                holder=call.holder,
                role=call.role,
                expect=call.expect,
                expect_stage=call.stage,
                outcome=outcome,
                reason=reason,
                stage=stage_of(reason),
                decision_id=decision,
                reached_upstream=reached,
                args_intact=intact,
                note=call.note,
                detail=detail,
                spoof=call.spoof_of is not None or call.resolves_to is not None,
                approval=(
                    ("approved" if scripted_approver(call) else "declined")
                    if outcome == "gated"
                    else None
                ),
                output_returned=returned,
                approval_id=approval_id,
                **(after or {}),
            )
        )
        self.index += 1

    # approvals
    def _admin_approval(self, method: str, aid: str, body: Any = None) -> httpx.Response:
        assert self.stack is not None
        url = f"{self.stack.url}/admin/approvals/{quote(aid, safe='')}"
        headers = {"authorization": f"Bearer {ADMIN_TOKEN}"}
        return self.http.request(method, url, json=body, headers=headers)

    def _approval_state(self, aid: str) -> tuple[str | None, str | None]:
        r = self._admin_approval("GET", aid)
        if r.status_code != 200:
            return None, None
        a = r.json()
        return a.get("state"), a.get("consumed_by")

    def _settle(self, call: Call, token: Any, dest: str, aid: str | None) -> dict[str, Any]:
        """Answer a gated call as the scripted approver would, through the operator endpoint
        ``POST /admin/approvals/{id}``. A grant is followed by one identical retry from the
        same hop; a decline is not retried. Returns the ``after_approval`` fields."""
        if aid is None:
            return {"after_approval": "no_decision"}
        grant = scripted_approver(call)
        r = self._admin_approval("POST", aid, {"decision": "grant" if grant else "decline"})
        if r.status_code != 200:
            state, _ = self._approval_state(aid)
            return {"after_approval": "error", "approval_state": state,
                    "retry_reason": f"decide_http_{r.status_code}"}  # fmt: skip
        if not grant:
            state, _ = self._approval_state(aid)
            return {"after_approval": "declined", "approval_state": state}
        self.rid += 1
        rid = self.rid
        body = _rpc_body(call, rid)
        raw = _decoy_bytes(call, rid) if call.decoy else None
        scripted = self.ups.get(dest)
        if call.output is not None and scripted is not None:
            scripted.script(self.http, {call.tool: [call.output]})
        obs = _Observer(self.ups)
        try:
            resp = self._post(dest, token, body, raw)
        finally:
            if call.output is not None and scripted is not None:
                scripted.script(self.http, {})
        new = obs.take()
        header = [p.strip() for p in resp.headers.get(DECISION_HEADER, "").split(",") if p.strip()]
        msgs = [m for m in _parse_messages(resp) if isinstance(m, dict)]
        msg = next((m for m in msgs if m.get("id") == rid), msgs[0] if len(msgs) == 1 else None)
        outcome, reason, decision = _judge(msg, header)
        if outcome == "allow" and header:
            decision = header[0]
        landed = call.target(self.suite.upstream)
        reached, _ = _delivered(new, landed if landed in self.ups else None, call)
        state, consumed_by = self._approval_state(aid)
        after = after_approval_of(outcome)
        if after == "gated":
            print(
                f"FAILED: {self.arm} {self.case.id}#{self.index} {call.tool}: retry after the "
                f"grant of approval {aid} got -32008 again",
                file=sys.stderr,
            )
        return {
            "after_approval": after,
            "approval_state": state,
            "approval_consumed_by": consumed_by,
            "retry_reason": reason,
            "retry_stage": stage_of(reason),
            "retry_decision_id": decision,
            "retry_reached_upstream": reached,
            "retry_output_returned": _returned(msg, call.output) if outcome == "allow" else None,
        }

    def _post(self, server: str, token: Any, body: Any, raw: bytes | None) -> httpx.Response:
        headers = {
            "accept": "application/json, text/event-stream",
            "content-type": "application/json",
        }
        if self.arm == "direct":
            url = self.ups[server].url
        else:
            assert self.stack is not None
            url = f"{self.stack.url}/mcp/{quote(server, safe='')}"
            headers["authorization"] = f"Bearer {token}"
        if raw is not None:
            return self.http.post(url, content=raw, headers=headers)
        return self.http.post(url, json=body, headers=headers)

    def send(self, calls: tuple[Call, ...], batch: bool) -> None:
        first = calls[0]
        dest = first.target(self.suite.upstream)
        if self.arm == "direct":
            dest = first.resolves_to or dest
        token = None
        if self.arm != "direct":
            if first.holder in self.refused or first.holder not in self.tokens:
                why = self.refused.get(first.holder, "no_token")
                for c in calls:
                    self._record(c, "deny", "exchange_refused", None, False, None, why)
                return
            token = self.tokens[first.holder]
        ids = []
        for _ in calls:
            self.rid += 1
            ids.append(self.rid)
        if batch:
            body: Any = [_rpc_body(c, i) for c, i in zip(calls, ids, strict=True)]
            raw = None
        else:
            body = _rpc_body(first, ids[0])
            raw = _decoy_bytes(first, ids[0]) if first.decoy else None
        # Scripted outputs go to the upstream the call would land on, if it lands anywhere.
        scripted = self.ups.get(dest)
        outputs: dict[str, list[str]] = {}
        for c in calls:
            if c.output is not None:
                outputs.setdefault(c.tool, []).append(c.output)
        if outputs and scripted is not None:
            scripted.script(self.http, outputs)
        obs = _Observer(self.ups)
        try:
            resp = self._post(dest, token, body, raw)
        finally:
            if outputs and scripted is not None:
                scripted.script(self.http, {})  # a denied call leaves its text unused
        new = obs.take()
        header = [p.strip() for p in resp.headers.get(DECISION_HEADER, "").split(",") if p.strip()]
        msgs = {m.get("id"): m for m in _parse_messages(resp) if isinstance(m, dict)}
        landed = first.resolves_to or first.target(self.suite.upstream)
        if self.arm != "direct":
            landed = first.target(self.suite.upstream)
        pending: list[tuple[Call, str, str | None, str | None, bool, bool | None,
                            bool | None, str | None]] = []  # fmt: skip
        for n, (c, rid) in enumerate(zip(calls, ids, strict=True)):
            msg = msgs.get(rid)
            if msg is None and not batch and len(msgs) == 1:
                msg = next(iter(msgs.values()))  # an error with id null (unknown server)
            outcome, reason, decision = _judge(msg, header)
            if outcome == "allow" and self.arm != "direct" and len(header) > n:
                decision = header[n] if batch else header[0]
            if batch:
                # fake_mcp logs single requests only; a batch member is checked against the
                # upstream's echo of what it executed, which comes back in the reply.
                reached, intact = _echoed(msg, c)
            else:
                reached, intact = _delivered(new, landed if landed in self.ups else None, c)
            returned = _returned(msg, c.output) if outcome == "allow" else None
            aid = _approval_id(msg) if outcome == "gated" else None
            pending.append((c, outcome, reason, decision, reached, intact, returned, aid))
        # Approvals are decided after the whole request is judged, so a retry's upstream line
        # is never mistaken for the first attempt's.
        for c, outcome, reason, decision, reached, intact, returned, aid in pending:
            after = None
            if outcome == "gated" and self.arm in LABEL_ARMS:
                after = self._settle(c, token, dest, aid)
            self._record(c, outcome, reason, decision, reached, intact, returned=returned,
                         approval_id=aid, after=after)  # fmt: skip

    def run(self) -> list[CallResult]:
        for step in self.case.steps:
            if isinstance(step, Revoke):
                self.revoke(step)
            elif isinstance(step, Delegate):
                self.delegate(step)
            elif isinstance(step, Batch):
                self.send(step.calls, batch=True)
            else:
                self.send((step,), batch=False)
        return self.out


def probe_approval(stack: Stack, all_upstreams: list[str]) -> str | None:
    """None if the server gates a destructive call after an untrusted read with ``-32008``,
    else why the labels arm cannot run. Uses its own root token, so no case run is tainted."""
    admin = AdminClient(stack.url, ADMIN_TOKEN)
    try:
        root = admin.mint_root_dev(USER, USER_ISSUER, ROOT_AGENT, [f"{u}:*" for u in all_upstreams])
    finally:
        admin.close()
    headers = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
        "authorization": f"Bearer {root}",
    }
    read = Call("get_most_recent_transactions", {"n": 1}, "benign", "allow", None)
    write = Call("update_user_info", {"street": "1 Probe Road", "city": "Leeds"}, "benign",
                 "allow", None)  # fmt: skip
    msgs: list[dict[str, Any] | None] = []
    with httpx.Client(timeout=10) as http:
        for i, c in enumerate((read, write), start=1):
            resp = http.post(f"{stack.url}/mcp/banking", json=_rpc_body(c, i), headers=headers)
            msgs.append(next(iter(_parse_messages(resp)), None))
    return approval_probe_verdict(msgs[1])


def approval_probe_verdict(reply: dict[str, Any] | None) -> str | None:
    """None if ``reply`` (to the probe's destructive call) is ``-32008 approval_required``."""
    err: dict[str, Any] = (reply or {}).get("error") or {}
    data: dict[str, Any] = err["data"] if isinstance(err.get("data"), dict) else {}
    if err.get("code") == CODE_APPROVAL and data.get("reason") == "approval_required":
        return None
    got = f"error {err.get('code')} {data.get('reason')}" if err else "no error"
    return (
        "the server does not answer -32008 approval_required for a destructive call after an "
        f"untrusted read (probe got {got})"
    )


def probe_limits(stack: Stack, all_upstreams: list[str]) -> str | None:
    """None if the server enforces a token's ``limits``, else why the limits arms cannot run. A
    server without run limits ignores the member, so the probe spends a one-call budget twice,
    with its own tokens."""
    admin = AdminClient(stack.url, ADMIN_TOKEN)
    try:
        root = admin.mint_root_dev(USER, USER_ISSUER, ROOT_AGENT, [f"{u}:*" for u in all_upstreams])
    finally:
        admin.close()
    cap = Capability("banking", "get_balance").with_limits(calls=1)
    with Client(stack.url) as ob:
        try:
            token = ob.exchange(root, WORKER, [cap], client_secret=AGENT_SECRET)
        except ApiError as e:
            return f"the server refuses a token with limits ({e.error}: {e.detail or ''})"
    headers = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
        "authorization": f"Bearer {token}",
    }
    call = Call("get_balance", {}, "benign", "allow", None)
    msgs: list[dict[str, Any] | None] = []
    with httpx.Client(timeout=10) as http:
        for i in (1, 2):
            resp = http.post(f"{stack.url}/mcp/banking", json=_rpc_body(call, i), headers=headers)
            msgs.append(next(iter(_parse_messages(resp)), None))
    return limits_probe_verdict(msgs[1])


def probe_arg_taint(stack: Stack, all_upstreams: list[str]) -> str | None:
    """None if the server matches a destructive call's argument against an earlier untrusted
    result (output labelling phase 2), else why the argument-taint arm cannot run. The read
    carries an extra argument that the catalog ignores and the fake upstream echoes, so its
    result holds the value the write then copies. Uses its own root token."""
    admin = AdminClient(stack.url, ADMIN_TOKEN)
    try:
        root = admin.mint_root_dev(USER, USER_ISSUER, ROOT_AGENT, [f"{u}:*" for u in all_upstreams])
    finally:
        admin.close()
    headers = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
        "authorization": f"Bearer {root}",
    }
    read = Call("get_most_recent_transactions", {"n": 1, "probe": "1 Probe Road"}, "benign",
                "allow", None)  # fmt: skip
    write = Call("update_user_info", {"street": "1 Probe Road", "city": "Leeds"}, "benign",
                 "allow", None)  # fmt: skip
    msgs: list[dict[str, Any] | None] = []
    with httpx.Client(timeout=10) as http:
        for i, c in enumerate((read, write), start=1):
            resp = http.post(f"{stack.url}/mcp/banking", json=_rpc_body(c, i), headers=headers)
            msgs.append(next(iter(_parse_messages(resp)), None))
    return arg_taint_probe_verdict(msgs[1])


def arg_taint_probe_verdict(reply: dict[str, Any] | None) -> str | None:
    """None if ``reply`` is ``-32008`` whose data names ``street`` in ``untrusted_args``."""
    why = approval_probe_verdict(reply)
    if why:
        return why.replace("after an untrusted read", "copying an untrusted result")
    data: dict[str, Any] = (reply or {})["error"]["data"]
    args = data.get("untrusted_args")
    if isinstance(args, list) and any(
        isinstance(a, dict) and a.get("arg") == "street" for a in args
    ):
        return None
    return (
        "the server's -32008 for an argument copied from an untrusted result does not name it "
        "in data.untrusted_args (no argument-level taint)"
    )


def probe_usage(stack: Stack, all_upstreams: list[str]) -> str | None:
    """None if the server keeps run usage and the soft rule gates a repeated destructive call,
    else why the usage arm cannot run. Two ``update_user_info`` calls with its own root token
    (its own run): the first is allowed and counted, the second must get ``-32008`` whose data
    carries ``usage``."""
    admin = AdminClient(stack.url, ADMIN_TOKEN)
    try:
        root = admin.mint_root_dev(USER, USER_ISSUER, ROOT_AGENT, [f"{u}:*" for u in all_upstreams])
    finally:
        admin.close()
    headers = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
        "authorization": f"Bearer {root}",
    }
    write = Call("update_user_info", {"street": "1 Probe Road", "city": "Leeds"}, "benign",
                 "allow", None)  # fmt: skip
    msgs: list[dict[str, Any] | None] = []
    with httpx.Client(timeout=10) as http:
        for i in (1, 2):
            resp = http.post(f"{stack.url}/mcp/banking", json=_rpc_body(write, i), headers=headers)
            msgs.append(next(iter(_parse_messages(resp)), None))
    return usage_probe_verdict(msgs[1])


def usage_probe_verdict(reply: dict[str, Any] | None) -> str | None:
    """None if ``reply`` (to the probe's second destructive call) is ``-32008
    approval_required`` whose data carries ``usage`` with ``calls`` at least 1."""
    why = approval_probe_verdict(reply)
    if why:
        return why.replace(
            "after an untrusted read", "repeated in one run (no run usage, or no soft rule)"
        )
    usage = (reply or {})["error"]["data"].get("usage")
    if isinstance(usage, dict) and isinstance(usage.get("calls"), int) and usage["calls"] >= 1:
        return None
    return (
        "the server's -32008 for a repeated destructive call does not carry data.usage with "
        f"the earlier call counted (got {usage!r})"
    )


def limits_probe_verdict(reply: dict[str, Any] | None) -> str | None:
    """None if ``reply`` (to the probe's second call on a one-call budget) is ``-32003
    budget_exhausted``."""
    err: dict[str, Any] = (reply or {}).get("error") or {}
    data: dict[str, Any] = err["data"] if isinstance(err.get("data"), dict) else {}
    if err.get("code") == CODE_DENIED and data.get("reason") == "budget_exhausted":
        return None
    got = f"error {err.get('code')} {data.get('reason')}" if err else "no error"
    return (
        "the server does not enforce run limits: a second call on a `calls: 1` capability "
        f"was not refused with budget_exhausted (probe got {got})"
    )


def probe_host_limit(
    stack: Stack, all_upstreams: list[str], arm: str = "attenuo_distinct_host"
) -> str | None:
    """None if the server enforces the frozen ``distinct`` rule of ``arm`` (an arm in
    ``DISTINCT_ARMS``), else why the arm cannot run. With its own tokens: one capability with
    the rule's limit, then calls with ``max + 1`` different values; the last must get ``-32003
    budget_exhausted``. A host rule fetches from that many hosts; the recipient rule sends its
    file's ``probe`` call with each of its values. A server without ``distinct`` or derived
    destinations refuses the token at exchange."""
    rule = distinct_rule(arm)
    if arm in HOST_LIMIT_ARMS:
        upstream, tools = next(iter(rule.items()))
        tool, limits = next(iter(tools.items()))
        arg = limits["distinct"]["arg"]
        n = int(limits["distinct"]["max"]) + 1
        values: list[Any] = [f"https://probe-{i}.example/a" for i in range(1, n + 1)]
        what = "a URL-host `distinct` limit"
    else:
        probe = json.loads(DISTINCT_RULE_FILES[arm].read_text())["probe"]
        upstream, tool, arg = probe["server"], probe["tool"], probe["arg"]
        n = int(rule[upstream][tool]["distinct"]["max"]) + 1
        values = list(probe["values"])[:n]
        if len(values) != n:
            raise ValueError(f"{DISTINCT_RULE_FILES[arm].name}: probe needs {n} values")
        what = "a `distinct` limit"
    admin = AdminClient(stack.url, ADMIN_TOKEN)
    try:
        root = admin.mint_root_dev(USER, USER_ISSUER, ROOT_AGENT, [f"{u}:*" for u in all_upstreams])
    finally:
        admin.close()
    caps = apply_distinct_rule([Capability(upstream, tool)], rule)
    with Client(stack.url) as ob:
        try:
            token = ob.exchange(root, WORKER, caps, client_secret=AGENT_SECRET)
        except ApiError as e:
            return (
                f"the server refuses a token with {what} "
                f"({e.error}: {e.detail or e.description or ''})"
            )
    headers = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
        "authorization": f"Bearer {token}",
    }
    msgs: list[dict[str, Any] | None] = []
    with httpx.Client(timeout=10) as http:
        for i, value in enumerate(values, start=1):
            call = Call(tool, {arg: value}, "benign", "allow", None)
            resp = http.post(
                f"{stack.url}/mcp/{upstream}", json=_rpc_body(call, i), headers=headers
            )
            msgs.append(next(iter(_parse_messages(resp)), None))
    why = limits_probe_verdict(msgs[-1])
    if why:
        return why.replace("a `calls: 1` capability", f"a capability with {n - 1} value(s) seen")
    return None


def ordered_cases(suites: list[Suite], seed: int) -> list[tuple[Suite, Case]]:
    """Cases in file order (seed 0) or in an order shuffled by ``seed``. Results are sorted by
    case id afterwards, so the seed changes only the order of execution."""
    pairs = [(s, c) for s in suites for c in s.cases]
    if seed:
        random.Random(seed).shuffle(pairs)
    return pairs


def replay(
    arm: str,
    pairs: list[tuple[Suite, Case]],
    ups: dict[str, Upstream],
    all_upstreams: list[str],
    stack: Stack | None = None,
) -> list[CallResult]:
    out: list[CallResult] = []
    with httpx.Client(timeout=10) as http:
        if arm == "direct":
            for s, case in pairs:
                out += _Replayer(arm, s, case, ups, http).run()
            return out
        assert stack is not None
        admin = AdminClient(stack.url, ADMIN_TOKEN)
        with Client(stack.url) as ob:
            for s, case in pairs:
                # A parent token can be exchanged for a given actor once, so every case gets a
                # fresh root: alice's assistant with every server, as a broad PAT would be.
                r = _Replayer(arm, s, case, ups, http, stack, ob, admin)
                r.start(all_upstreams)
                out += r.run()
        admin.close()
    return out


def audit_check(stack: Stack, results: list[CallResult]) -> dict[str, Any]:
    """Match each decision id to its audit entry, then verify the chain with the CLI."""
    admin = AdminClient(stack.url, ADMIN_TOKEN)
    entries: dict[str, Any] = {}
    seq = 1
    while True:
        page, nxt = admin.audit(from_seq=seq, limit=500)
        for e in page:
            if e.id:
                entries[e.id] = e
        if not page or nxt is None:
            break
        seq = nxt
    mismatched = []
    checked = [r for r in results if r.audited]
    for r in checked:
        e = entries.get(r.decision_id or "")
        want = "deny" if r.outcome == "deny" else "allow"
        if r.outcome == "gated":
            # The decision kind of an approval request is the server's choice; the reason is not.
            if e is None or e.reason != r.reason:
                mismatched.append({"case": r.case, "index": r.index, "decision_id": r.decision_id})
            continue
        if e is None or e.decision != want or (r.reason and e.reason != r.reason):
            mismatched.append({"case": r.case, "index": r.index, "decision_id": r.decision_id})
    # A retry after a grant has its own decision record, which names the approval it used.
    retries = [r for r in results if r.retry_decision_id]
    retry_mismatched = []
    for r in retries:
        got = entries.get(r.retry_decision_id or "")
        used = ((got.record.get("approval") or {}).get("id") if got else None) == r.approval_id
        want = "allow" if r.after_approval == "allowed" else "deny"
        if got is None or got.decision != want or (want == "allow" and not used):
            retry_mismatched.append(
                {"case": r.case, "index": r.index, "decision_id": r.retry_decision_id}
            )
    admin.audit_checkpoint()
    admin.close()
    verify = stack.cli("audit", "verify")
    export = stack.work / "audit-export.jsonl"
    exp = stack.cli("audit", "export", "--out", str(export))
    jwks = stack.work / "jwks.json"
    jwks.write_text(httpx.get(f"{stack.url}/.well-known/jwks.json", timeout=5).text)
    offline = stack.cli("audit", "verify", "--file", str(export), "--jwks", str(jwks))
    return {
        "entries": len(entries),
        "decisions_checked": len(checked),
        "decisions_matched": len(checked) - len(mismatched),
        "decisions_unmatched": mismatched,
        "not_audited": len(results) - len(checked),
        "retries_checked": len(retries),
        "retries_unmatched": retry_mismatched,
        "cli_verify_exit": verify.returncode,
        "cli_verify_output": verify.stdout.strip(),
        "export_exit": exp.returncode,
        "offline_verify_exit": offline.returncode,
        "offline_verify_output": offline.stdout.strip() or offline.stderr.strip(),
    }


def case_meta(suites: list[Suite]) -> dict[str, Any]:
    return {
        c.id: {
            "suite": c.suite,
            "shape": c.shape,
            "attack_class": c.attack_class,
            "class": c.cls,
            "taxonomy": c.taxonomy,
            "user_task": c.user_task,
            "injection": c.injection,
            "note": c.note,
        }
        for s in sorted(suites, key=lambda s: s.name)
        for c in s.cases
    }


def run(
    suites: list[Suite],
    arms: tuple[str, ...] = ARMS,
    keep: Path | None = None,
    seed: int = 0,
) -> dict[str, Any]:
    """Run the arms and return a JSON-able result document."""
    ignore_inherited_env()  # also covers variables exported after import
    bins = find_binaries()
    env = list(load_environment().values())
    all_upstreams = [s.upstream for s in env]
    agents = agent_ids(suites)
    pairs = ordered_cases(suites, seed)
    work = Path(tempfile.mkdtemp(prefix="attenuo-injection-"))
    try:
        results: list[CallResult] = []
        audits: dict[str, Any] = {}
        skipped: dict[str, str] = {}
        with upstreams(env, bins, work) as ups:
            for arm in ARMS:
                if arm not in arms:
                    continue
                if arm == "direct":
                    results += replay(arm, pairs, ups, all_upstreams)
                    continue
                try:
                    with server(env, bins, work, ups, arm, agents) as stack:
                        if arm in LIMIT_ARMS or arm in TASK_LIMIT_ARMS:
                            why = probe_limits(stack, all_upstreams)
                            if why:
                                raise ArmUnsupported(why)
                        if arm in DISTINCT_ARMS:
                            why = probe_host_limit(stack, all_upstreams, arm)
                            if why:
                                raise ArmUnsupported(why)
                        if arm in USAGE_ARMS:
                            why = probe_usage(stack, all_upstreams)
                            if why:
                                raise ArmUnsupported(why)
                        elif arm in ARG_LABEL_ARMS:
                            why = probe_arg_taint(stack, all_upstreams)
                            if why:
                                raise ArmUnsupported(why)
                        elif arm in LABEL_ARMS:
                            why = probe_approval(stack, all_upstreams)
                            if why:
                                raise ArmUnsupported(why)
                        arm_results = replay(arm, pairs, ups, all_upstreams, stack)
                        audits[arm] = audit_check(stack, arm_results)
                        results += arm_results
                except ArmUnsupported as e:
                    skipped[arm] = str(e)
                    print(f"skipping arm {arm}: {e}", file=sys.stderr)
        order = {a: i for i, a in enumerate(ARMS)}
        results.sort(key=lambda r: (order[r.arm], r.case, r.index))
        return {
            "cases": sum(len(s.cases) for s in suites),
            "arms": [a for a in ARMS if a in arms and a not in skipped],
            "skipped_arms": skipped,
            "seed": seed,
            "audit": audits,
            "case_meta": case_meta(suites),
            "calls": [r.to_json() for r in results],
        }
    finally:
        if keep is not None:
            shutil.copytree(work, keep, dirs_exist_ok=True)
        shutil.rmtree(work, ignore_errors=True)


# --- summary ----------------------------------------------------------------------------------


def summarise(doc: dict[str, Any]) -> dict[str, Any]:
    """Per suite and arm: attack calls, how they were stopped, false negatives, false positives."""
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for c in doc["calls"]:
        key = (c["suite"], c["arm"])
        r = rows.setdefault(
            key,
            {
                "suite": c["suite"],
                "arm": c["arm"],
                "cases": set(),
                "attack_calls": 0,
                **{f"blocked_{s}": 0 for s in STAGES},
                "blocked_other": 0,
                "attack_allowed": 0,
                "attack_gated": 0,
                "attack_reached_upstream": 0,
                "benign_calls": 0,
                "benign_denied": 0,
                "benign_gated": 0,
                "benign_delivered_intact": 0,
                "unexpected": 0,
            },
        )
        r["cases"].add(c["case"])
        if c["role"] == "attack":
            r["attack_calls"] += 1
            if c["outcome"] == "deny":
                r[f"blocked_{c['stage'] if c['stage'] in STAGES else 'other'}"] += 1
            elif c["outcome"] == "gated":
                r["attack_gated"] += 1
            else:
                r["attack_allowed"] += 1
            r["attack_reached_upstream"] += int(c["reached_upstream"])
        else:
            r["benign_calls"] += 1
            r["benign_denied"] += int(c["outcome"] == "deny")
            r["benign_gated"] += int(c["outcome"] == "gated")
            r["benign_delivered_intact"] += int(bool(c["reached_upstream"] and c["args_intact"]))
        if c["arm"] == "attenuo" and not c["as_expected"]:
            r["unexpected"] += 1
    out = []
    for r in rows.values():
        r["cases"] = len(r["cases"])
        out.append(r)
    order = {a: i for i, a in enumerate(ARMS)}
    out.sort(key=lambda r: (order[r["arm"]], r["suite"]))
    return {"rows": out}
