"""Replay prompt-injection tool-call sequences against onbehalf and against a bare upstream.

The corpus (``cases/*.yaml``) describes, per case, the capability grant a user task needs and
the tool calls a compromised agent would emit, each with the expected outcome. This module
loads the corpus, writes a server config, catalog and Cedar policy from it, starts
``onbehalf-server`` and one echoing ``fake_mcp`` upstream per suite, and replays the calls in
three arms:

``direct``      no onbehalf: JSON-RPC straight to the upstream (the baseline).
``scope_only``  onbehalf with tool-level capabilities only (argument constraints dropped) and a
                permit-all Cedar policy. The OAuth-scope equivalent (arm A1 in the plan).
``onbehalf``    onbehalf as configured: attenuated tokens with argument constraints, the suite
                Cedar policies, leases and audit (arm A2).

No LLM is involved. See README.md for the method and its limits.
"""

from __future__ import annotations

import hashlib
import json
import os
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

import httpx
import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CASES_DIR = HERE / "cases"
POLICIES_DIR = HERE / "policies"
FROZEN_FILE = CASES_DIR / "test" / "POLICY_HASHES.json"

sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

from onbehalf import (  # noqa: E402
    AdminClient,
    Capability,
    Client,
    Denied,
    Equals,
    OneOf,
    Prefix,
)

ADMIN_TOKEN = "eval-admin-token"
USER = "alice"
USER_ISSUER = "https://idp.example"
ROOT_AGENT = "assistant"
WORKER = "worker"
WORKER_SECRET = "eval-worker-secret"

ARMS = ("direct", "scope_only", "onbehalf")
STAGES = ("capability", "policy", "lease")
ROLES = ("benign", "attack")
CLASSES = ("S", "C", "D", "N")
SPLITS = ("dev", "test")

PERMIT_ALL = '@id("permit_all")\npermit(principal, action, resource);\n'


# --- corpus -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Call:
    tool: str
    args: dict[str, Any]
    role: str
    expect: str
    stage: str | None
    note: str | None = None


@dataclass(frozen=True)
class Revoke:
    reason: str


Step = Call | Revoke


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

    @property
    def calls(self) -> list[Call]:
        return [s for s in self.steps if isinstance(s, Call)]


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


def _parse_step(case_id: str, i: int, raw: dict[str, Any], catalog: dict[str, Any]) -> Step:
    where = f"{case_id} step {i}"
    if "revoke" in raw:
        return Revoke(str(raw["revoke"]))
    tool = raw.get("tool")
    if tool not in catalog:
        raise CorpusError(f"{where}: tool {tool!r} is not in the suite catalog")
    role, expect, stage = raw.get("role"), raw.get("expect"), raw.get("stage")
    if role not in ROLES:
        raise CorpusError(f"{where}: role must be one of {ROLES}")
    if expect not in ("allow", "deny"):
        raise CorpusError(f"{where}: expect must be allow or deny")
    if (expect == "deny") != (stage is not None):
        raise CorpusError(f"{where}: a deny needs a stage and an allow must not have one")
    if stage is not None and stage not in STAGES:
        raise CorpusError(f"{where}: stage must be one of {STAGES}")
    return Call(str(tool), dict(raw.get("args") or {}), role, expect, stage, raw.get("note"))


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


def load_cases(path: Path, suite: Suite) -> list[Case]:
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
        steps = [_parse_step(cid, i, s, suite.catalog) for i, s in enumerate(raw["calls"])]
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
        )
        if case.cls not in CLASSES:
            raise CorpusError(f"{cid}: class must be one of {CLASSES}")
        if not any(c.role == "attack" for c in case.calls):
            raise CorpusError(f"{cid}: a case needs at least one attack call")
        for g in case.grant:
            if g["tool"] != "*" and g["tool"] not in suite.catalog:
                raise CorpusError(f"{cid}: granted tool {g['tool']!r} is not in the catalog")
        out.append(case)
    return out


def load_corpus(split: str = "dev", cases_dir: Path | None = None) -> list[Suite]:
    """Every suite of the environment, with the cases of one split (``cases/<split>/``).
    Suites without cases in the split are left out."""
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
        s.cases = load_cases(p, s)
        suites.append(s)
    ids = [c.id for s in suites for c in s.cases]
    if len(ids) != len(set(ids)):
        raise CorpusError("case ids must be unique across the split")
    return suites


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


def capabilities(suite: Suite, case: Case, *, constraints: bool) -> list[Capability]:
    caps = []
    for g in case.grant:
        cons = (
            {k: _constraint(v) for k, v in (g.get("constraints") or {}).items()}
            if constraints
            else {}
        )
        caps.append(Capability(suite.upstream, g["tool"], **cons))
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


def write_config(
    work: Path, suites: list[Suite], port: int, upstream_urls: dict[str, str], arm: str
) -> Path:
    """Write ``config.toml`` and ``policy.cedar`` for one arm into ``work``."""
    policy = work / "policy.cedar"
    if arm == "scope_only":
        policy.write_text(PERMIT_ALL)
    else:
        policy.write_text("\n".join(f"// ---- suite {s.name} ----\n{s.policy}" for s in suites))
    secret_sha = hashlib.sha256(WORKER_SECRET.encode()).hexdigest()
    lines = [
        "# Generated by evaluation/injection-suite/harness.py. Do not edit.",
        "[server]",
        f'listen = "127.0.0.1:{port}"',
        "[issuer]",
        f'issuer = "http://127.0.0.1:{port}"',
        'audience = "onbehalf"',
        "default_ttl_seconds = 900",
        "[policy]",
        f"policies_path = {_toml_str(str(policy))}",
    ]
    for s in suites:
        for tool, spec in s.catalog.items():
            lines.append(f"[policy.catalog.{s.upstream}.{tool}]")
            if spec.get("readonly"):
                lines.append("readonly = true")
            if spec.get("sensitive"):
                lines.append("sensitive = true")
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
    for s in suites:
        lines += ["[[upstreams]]", f'name = "{s.upstream}"', f'url = "{upstream_urls[s.upstream]}"']
    caps = ", ".join(f'"{s.upstream}:*"' for s in suites)
    lines += [
        "[[root_grants]]",
        f'subject = "{USER}"',
        f'issuer = "{USER_ISSUER}"',
        f'agent = "{ROOT_AGENT}"',
        f"capabilities = [{caps}]",
        "[[agents]]",
        f'id = "{WORKER}"',
        f'secret_sha256 = "{secret_sha}"',
        "[dev]",
        "allow_root_mint = true",
    ]
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
    """Prebuilt binaries from ``ONBEHALF_BIN_DIR``, else ``target/debug`` (run ``cargo build``)."""
    given = os.environ.get("ONBEHALF_BIN_DIR")
    d = Path(given) if given else ROOT / "target" / "debug"
    fake = d / "examples" / "fake_mcp"
    bins = Binaries(
        d / "onbehalf-server", d / "onbehalf", fake if fake.exists() else d / "fake_mcp"
    )
    missing = [str(p) for p in (bins.server, bins.cli, bins.fake_mcp) if not p.exists()]
    if missing:
        raise FileNotFoundError(
            "missing binaries: " + ", ".join(missing) + ". Set ONBEHALF_BIN_DIR or build with "
            "`cargo build -p onbehalf-server -p onbehalf-cli` and "
            "`cargo build -p onbehalf-proxy --features testing --example fake_mcp`."
        )
    return bins


@dataclass
class Upstream:
    name: str
    url: str
    log: Path

    def calls(self) -> int:
        return sum(1 for line in self.log.read_text().splitlines() if "tools/call" in line)


@dataclass
class Stack:
    url: str
    work: Path
    config: Path
    upstreams: dict[str, Upstream]
    bins: Binaries

    def cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = {**os.environ, "ONBEHALF_SERVER": self.url, "ONBEHALF_ADMIN_TOKEN": ADMIN_TOKEN}
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
    suites: list[Suite], bins: Binaries, work: Path, ups: dict[str, Upstream], arm: str
) -> Iterator[Stack]:
    arm_dir = work / arm
    arm_dir.mkdir()
    port = free_port()
    cfg = write_config(arm_dir, suites, port, {k: u.url for k, u in ups.items()}, arm)
    lint = subprocess.run(
        [str(bins.cli), "policy", "lint", str(arm_dir / "policy.cedar"), "--config", str(cfg)],
        capture_output=True,
        text=True,
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
                    f"onbehalf-server exited:\n{(arm_dir / 'server.log').read_text()[-2000:]}"
                )
            try:
                return httpx.get(f"{url}/healthz", timeout=1).status_code == 200
            except httpx.HTTPError:
                return False

        _wait(healthy, "onbehalf-server")
        yield Stack(url, arm_dir, cfg, ups, bins)
    finally:
        proc.terminate()
        proc.wait(timeout=10)


# --- replay -----------------------------------------------------------------------------------


def stage_of(reason: str | None) -> str | None:
    if reason is None:
        return None
    if reason.startswith("capability_"):
        return "capability"
    if reason.startswith("policy_"):
        return "policy"
    if reason.startswith("lease_"):
        return "lease"
    return "other"


@dataclass
class CallResult:
    case: str
    suite: str
    arm: str
    index: int
    tool: str
    role: str
    expect: str
    expect_stage: str | None
    outcome: str  # allow | deny | error
    reason: str | None
    stage: str | None
    decision_id: str | None
    reached_upstream: bool
    note: str | None = None

    @property
    def as_expected(self) -> bool:
        return self.outcome == self.expect and self.stage == self.expect_stage

    def to_json(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        d["as_expected"] = self.as_expected if self.arm == "onbehalf" else None
        return d


def replay_direct(suites: list[Suite], ups: dict[str, Upstream]) -> list[CallResult]:
    """Baseline: every call straight to the upstream. Revocation means nothing here."""
    out: list[CallResult] = []
    with httpx.Client(timeout=10) as http:
        for s in suites:
            up = ups[s.upstream]
            for case in s.cases:
                for i, call in enumerate(case.calls):
                    before = up.calls()
                    r = http.post(
                        up.url,
                        json={
                            "jsonrpc": "2.0",
                            "id": i,
                            "method": "tools/call",
                            "params": {"name": call.tool, "arguments": call.args},
                        },
                        headers={"accept": "application/json, text/event-stream"},
                    )
                    body = r.json()
                    ok = "result" in body and not body["result"].get("isError", False)
                    out.append(
                        CallResult(
                            case.id, s.name, "direct", i, call.tool, call.role, call.expect,
                            call.stage, "allow" if ok else "error", None, None, None,
                            up.calls() > before, call.note,
                        )
                    )  # fmt: skip
    return out


def replay_proxy(suites: list[Suite], stack: Stack, arm: str) -> list[CallResult]:
    out: list[CallResult] = []
    admin = AdminClient(stack.url, ADMIN_TOKEN)
    with Client(stack.url) as ob:
        for s in suites:
            up = stack.upstreams[s.upstream]
            for case in s.cases:
                # A parent token can be exchanged for a given actor once, so every case gets a
                # fresh root: alice's assistant with the whole suite, as a broad PAT would be.
                root = admin.mint_root_dev(USER, USER_ISSUER, ROOT_AGENT, [f"{s.upstream}:*"])
                caps = capabilities(s, case, constraints=(arm == "onbehalf"))
                tok = ob.exchange(root, WORKER, caps, client_secret=WORKER_SECRET)
                i = 0
                for step in case.steps:
                    if isinstance(step, Revoke):
                        assert tok.lease is not None
                        admin.revoke_lease(tok.lease, step.reason)
                        continue
                    before = up.calls()
                    try:
                        res = ob.call_tool(tok, s.upstream, step.tool, step.args)
                        outcome = "error" if res.is_error else "allow"
                        reason, decision = None, res.decision_id
                    except Denied as d:
                        outcome, reason, decision = "deny", d.reason, d.decision_id
                    out.append(
                        CallResult(
                            case.id, s.name, arm, i, step.tool, step.role, step.expect,
                            step.stage, outcome, reason, stage_of(reason), decision,
                            up.calls() > before, step.note,
                        )
                    )  # fmt: skip
                    i += 1
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
    for r in results:
        e = entries.get(r.decision_id or "")
        want = "deny" if r.outcome == "deny" else "allow"
        if e is None or e.decision != want or (r.reason and e.reason != r.reason):
            mismatched.append({"case": r.case, "index": r.index, "decision_id": r.decision_id})
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
        "decisions_matched": len(results) - len(mismatched),
        "decisions_unmatched": mismatched,
        "cli_verify_exit": verify.returncode,
        "cli_verify_output": verify.stdout.strip(),
        "export_exit": exp.returncode,
        "offline_verify_exit": offline.returncode,
        "offline_verify_output": offline.stdout.strip() or offline.stderr.strip(),
    }


def run(
    suites: list[Suite], arms: tuple[str, ...] = ARMS, keep: Path | None = None
) -> dict[str, Any]:
    """Run the arms and return a JSON-able result document."""
    bins = find_binaries()
    work = Path(tempfile.mkdtemp(prefix="onbehalf-injection-"))
    try:
        results: list[CallResult] = []
        audits: dict[str, Any] = {}
        with upstreams(suites, bins, work) as ups:
            if "direct" in arms:
                results += replay_direct(suites, ups)
            for arm in arms:
                if arm == "direct":
                    continue
                with server(suites, bins, work, ups, arm) as stack:
                    arm_results = replay_proxy(suites, stack, arm)
                    audits[arm] = audit_check(stack, arm_results)
                    results += arm_results
        return {
            "cases": sum(len(s.cases) for s in suites),
            "arms": list(arms),
            "audit": audits,
            "case_meta": {
                c.id: {
                    "suite": c.suite,
                    "shape": c.shape,
                    "attack_class": c.attack_class,
                    "class": c.cls,
                    "user_task": c.user_task,
                    "injection": c.injection,
                    "note": c.note,
                }
                for s in suites
                for c in s.cases
            },
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
                "blocked_capability": 0,
                "blocked_policy": 0,
                "blocked_lease": 0,
                "blocked_other": 0,
                "attack_allowed": 0,
                "attack_reached_upstream": 0,
                "benign_calls": 0,
                "benign_denied": 0,
                "unexpected": 0,
            },
        )
        r["cases"].add(c["case"])
        if c["role"] == "attack":
            r["attack_calls"] += 1
            if c["outcome"] == "deny":
                r[f"blocked_{c['stage'] if c['stage'] in STAGES else 'other'}"] += 1
            else:
                r["attack_allowed"] += 1
            r["attack_reached_upstream"] += int(c["reached_upstream"])
        else:
            r["benign_calls"] += 1
            r["benign_denied"] += int(c["outcome"] == "deny")
        if c["arm"] == "onbehalf" and not c["as_expected"]:
            r["unexpected"] += 1
    out = []
    for r in rows.values():
        r["cases"] = len(r["cases"])
        out.append(r)
    order = {a: i for i, a in enumerate(ARMS)}
    out.sort(key=lambda r: (order[r["arm"]], r["suite"]))
    return {"rows": out}
