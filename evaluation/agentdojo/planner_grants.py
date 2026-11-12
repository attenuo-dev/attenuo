#!/usr/bin/env python3
"""Planner grant files: format, validator, freeze and conversion to SDK capabilities.

A grant directory holds one JSON file per suite, `<suite>.json`:

    {
      "user_task_0": {
        "capabilities": [
          {"tool": "search_items"},
          {"tool": "send_message",
           "constraints": {"to": {"op": "equals", "value": "someone@example.com"}},
           "limits": {"calls": 1}}
        ],
        "rationale": "One sentence."
      }
    }

`constraints` and `limits` are optional and use the wire form of the Python SDK's
`Capability.to_json()` (`attenuo.capability`): a constraint is `{"op": "equals" | "one_of" |
"prefix" | "range", "value": ...}`, and `limits` is what `Limits.from_json` reads (`calls`,
`sum`, `calls_per`, `distinct`). The server is the suite's name and is not written.

    python3 planner_grants.py validate GRANTS_DIR [--bundle BUNDLE_DIR] [--suites ...]
    python3 planner_grants.py freeze GRANTS_DIR --source LABEL --out FROZEN.json [--bundle ...]
    python3 planner_grants.py fixture OUT_DIR --bundle BUNDLE_DIR

`validate` exits 1 and lists every problem. The tool catalogue comes from a planner bundle
(`--bundle`, the `tools.json` and `tasks.json` that `planner_bundle.py` writes); without it,
from the tool definitions themselves, through `planner_bundle.py`. The checks need only the
standard library, so the copy of this file in a bundle runs on its own. `freeze` validates,
then writes the SHA-256 of each suite's file, which `replay.py --planner-grants` checks before
it runs. `fixture` writes a synthetic grant set, labelled `fixture-reads-only`, that grants
every read tool and nothing else: for testing the pipeline only, never a measured result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SUITES = ("workspace", "travel", "banking", "slack")
OPS = ("equals", "one_of", "prefix", "range")
LIMIT_KINDS = ("calls", "sum", "calls_per", "distinct")
ENTRY_KEYS = {"capabilities", "rationale"}
CAP_KEYS = {"tool", "constraints", "limits"}
FIXTURE_SOURCE = "fixture-reads-only"
FROZEN_FORMAT = "attenuo-planner-grants-frozen/1"
MAX_LONG = 2**63 - 1


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- the catalogue ----------------------------------------------------------------------------


def catalog_from_bundle(bundle: Path, suite: str) -> dict[str, Any]:
    """`{"tasks": [id, ...], "tools": {name: {"parameters": schema, "read": bool}}}`."""
    tasks = json.loads((bundle / suite / "tasks.json").read_text())
    tools = json.loads((bundle / suite / "tools.json").read_text())
    return {
        "tasks": [t["id"] for t in tasks],
        "tools": {t["name"]: {"parameters": t["parameters"], "read": t["read"]} for t in tools},
    }


def catalog_from_definitions(suite: str) -> dict[str, Any]:
    """The same catalogue, built by the bundle exporter's own functions."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import planner_bundle

    return planner_bundle.catalog(suite)


# --- JSON schema checks (the subset the tool schemas use) ------------------------------------


def _resolve(schema: dict, defs: dict) -> dict:
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/$defs/"):
        return defs.get(ref.split("/")[-1], {})
    return schema


def value_fits(schema: dict, value: Any, defs: dict) -> bool:
    """Does `value` fit the argument schema? Handles anyOf, $ref, enum, and the JSON types."""
    schema = _resolve(schema, defs)
    if "anyOf" in schema:
        return any(value_fits(s, value, defs) for s in schema["anyOf"])
    if "enum" in schema and value not in schema["enum"]:
        return False
    kind = schema.get("type")
    if kind is None:
        return True
    if kind == "string":
        return isinstance(value, str)
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "null":
        return value is None
    if kind == "object":
        return isinstance(value, dict)
    if kind == "array":
        items = schema.get("items", {})
        return isinstance(value, list) and all(value_fits(items, v, defs) for v in value)
    return False


def types_of(schema: dict, defs: dict) -> set[str]:
    """Every JSON type an argument schema accepts."""
    schema = _resolve(schema, defs)
    if "anyOf" in schema:
        out: set[str] = set()
        for s in schema["anyOf"]:
            out |= types_of(s, defs)
        return out
    kind = schema.get("type")
    return {kind} if isinstance(kind, str) else set()


def _is_long(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and -(2**63) <= v <= MAX_LONG


# --- validation -------------------------------------------------------------------------------


def check_constraint(where: str, arg: str, c: Any, schema: dict, defs: dict) -> list[str]:
    if not isinstance(c, dict) or set(c) != {"op", "value"}:
        return [f'{where}: constraint on {arg!r} must be {{"op": ..., "value": ...}}']
    op, value = c["op"], c["value"]
    kinds = types_of(schema, defs)
    if op == "equals":
        if not value_fits(schema, value, defs):
            return [f"{where}: equals value {value!r} does not fit {arg!r} ({_shape(kinds)})"]
    elif op == "one_of":
        if not isinstance(value, list) or not value:
            return [f"{where}: one_of on {arg!r} needs a non-empty list of values"]
        bad = [v for v in value if not value_fits(schema, v, defs)]
        if bad:
            return [f"{where}: one_of values {bad!r} do not fit {arg!r} ({_shape(kinds)})"]
    elif op == "prefix":
        if "string" not in kinds:
            return [f"{where}: prefix needs a string argument; {arg!r} is {_shape(kinds)}"]
        if not isinstance(value, str) or not value:
            return [f"{where}: prefix on {arg!r} needs a non-empty string"]
    elif op == "range":
        if not kinds & {"integer", "number"}:
            return [f"{where}: range needs a number argument; {arg!r} is {_shape(kinds)}"]
        if not isinstance(value, dict) or not value or not set(value) <= {"min", "max"}:
            return [f'{where}: range on {arg!r} must be {{"min"?: int, "max"?: int}}']
        if not all(_is_long(v) for v in value.values()):
            return [f"{where}: range bounds on {arg!r} must be integers"]
        if "min" in value and "max" in value and value["min"] > value["max"]:
            return [f"{where}: range on {arg!r} has min greater than max"]
    else:
        return [f"{where}: unknown op {op!r} on {arg!r} (one of {', '.join(OPS)})"]
    return []


def _shape(kinds: set[str]) -> str:
    return "/".join(sorted(kinds)) or "untyped"


def check_limits(where: str, limits: Any, props: dict, defs: dict) -> list[str]:
    if not isinstance(limits, dict) or not limits:
        return [f"{where}: limits must be a non-empty object when present"]
    problems = []
    for kind, value in limits.items():
        if kind not in LIMIT_KINDS:
            problems.append(f"{where}: unknown limit kind {kind!r} (one of {LIMIT_KINDS})")
        elif kind == "calls":
            if not _is_long(value) or value < 0:
                problems.append(f"{where}: limits.calls must be an integer >= 0")
        else:
            allowed = {"arg", "max"} if kind == "sum" else {"arg", "max", "derive"}
            if not isinstance(value, dict) or not {"arg", "max"} <= set(value) <= allowed:
                problems.append(f"{where}: limits.{kind} must have arg and max only")
                continue
            arg, top = value["arg"], value["max"]
            if arg not in props:
                problems.append(f"{where}: limits.{kind} names unknown argument {arg!r}")
                continue
            if not _is_long(top) or top < 0:
                problems.append(f"{where}: limits.{kind}.max must be an integer >= 0")
            kinds = types_of(props[arg], defs)
            if kind == "sum" and not kinds & {"integer", "number"}:
                problems.append(f"{where}: limits.sum needs a number argument, not {arg!r}")
            if "derive" in value and (value["derive"] != "host" or "string" not in kinds):
                problems.append(f'{where}: limits.{kind}.derive must be "host" on a string')
    return problems


def check_suite(grants: Any, catalog: dict[str, Any], suite: str) -> list[str]:
    """Every problem in one suite's grant file, as readable lines. Empty means valid."""
    if not isinstance(grants, dict):
        return [f"{suite}: the file must hold a JSON object keyed by user task id"]
    problems = []
    tasks, tools = catalog["tasks"], catalog["tools"]
    for tid in tasks:
        if tid not in grants:
            problems.append(f"{suite}/{tid}: no entry")
    for tid in grants:
        if tid not in tasks:
            problems.append(f"{suite}/{tid}: not a user task of this suite")
    for tid, entry in grants.items():
        where = f"{suite}/{tid}"
        if not isinstance(entry, dict):
            problems.append(f"{where}: entry must be an object")
            continue
        extra = set(entry) - ENTRY_KEYS
        if extra:
            problems.append(f"{where}: unknown keys {sorted(extra)}")
        rationale = entry.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            problems.append(f"{where}: rationale must be a non-empty string")
        caps = entry.get("capabilities")
        if not isinstance(caps, list) or not caps:
            problems.append(f"{where}: capabilities must be a non-empty list")
            continue
        for i, cap in enumerate(caps):
            here = f"{where}/capabilities[{i}]"
            if not isinstance(cap, dict):
                problems.append(f"{here}: must be an object")
                continue
            extra = set(cap) - CAP_KEYS
            if extra:
                problems.append(f"{here}: unknown keys {sorted(extra)}")
            tool = cap.get("tool")
            if tool not in tools:
                problems.append(f"{here}: unknown tool {tool!r} in {suite}")
                continue
            schema = tools[tool]["parameters"]
            props, defs = schema.get("properties", {}), schema.get("$defs", {})
            constraints = cap.get("constraints", {})
            if not isinstance(constraints, dict):
                problems.append(f"{here}: constraints must be an object")
                constraints = {}
            for arg, c in constraints.items():
                if arg not in props:
                    problems.append(f"{here}: {tool} has no argument {arg!r}")
                    continue
                problems += check_constraint(f"{here} {tool}", arg, c, props[arg], defs)
            if "limits" in cap:
                problems += check_limits(f"{here} {tool}", cap["limits"], props, defs)
    return problems


def load_dir(grants_dir: Path, suites, bundle: Path | None = None):
    """`(grants by suite, problems)`. A suite whose file is missing is a problem."""
    out, problems = {}, []
    for suite in suites:
        path = grants_dir / f"{suite}.json"
        if not path.exists():
            problems.append(f"{suite}: missing {path.name}")
            continue
        try:
            grants = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            problems.append(f"{suite}: {path.name} is not JSON: {e}")
            continue
        cat = catalog_from_bundle(bundle, suite) if bundle else catalog_from_definitions(suite)
        problems += check_suite(grants, cat, suite)
        out[suite] = grants
    return out, problems


# --- conversion -------------------------------------------------------------------------------


def to_capabilities(entry: dict, suite: str) -> list:
    """An entry as the SDK `Capability` list that `Client.exchange` takes, through the SDK's own
    `Capability.from_json`, so the token carries exactly what the file says."""
    from attenuo import Capability

    caps = []
    for cap in entry["capabilities"]:
        wire: dict[str, Any] = {"server": suite, "tool": cap["tool"]}
        if cap.get("constraints"):
            wire["constraints"] = cap["constraints"]
        if cap.get("limits"):
            wire["limits"] = cap["limits"]
        caps.append(Capability.from_json(wire))
    return caps


# --- freeze -----------------------------------------------------------------------------------


def freeze(grants_dir: Path, suites, source: str) -> dict[str, Any]:
    return {
        "format": FROZEN_FORMAT,
        "source": source,
        "frozen_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": {f"{s}.json": sha256_file(grants_dir / f"{s}.json") for s in suites},
    }


def check_frozen(frozen: dict, grants_dir: Path, suites) -> list[str]:
    """Problems with `grants_dir` against a FROZEN record: a format, a missing or changed file."""
    if frozen.get("format") != FROZEN_FORMAT:
        return [f"FROZEN format is {frozen.get('format')!r}, expected {FROZEN_FORMAT!r}"]
    if not isinstance(frozen.get("source"), str) or not frozen["source"]:
        return ["FROZEN has no source label"]
    problems = []
    for suite in suites:
        name = f"{suite}.json"
        want = frozen.get("files", {}).get(name)
        path = grants_dir / name
        if want is None:
            problems.append(f"FROZEN has no hash for {name}")
        elif not path.exists():
            problems.append(f"{name} is missing from {grants_dir}")
        elif sha256_file(path) != want:
            problems.append(f"{name} does not match its frozen SHA-256 {want}")
    return problems


# --- the synthetic fixture --------------------------------------------------------------------


def fixture(catalog: dict[str, Any]) -> dict[str, Any]:
    """Every read tool for every task, nothing else. Synthetic: not a planner's grant."""
    reads = [{"tool": name} for name, t in sorted(catalog["tools"].items()) if t["read"]]
    note = "SYNTHETIC FIXTURE (fixture-reads-only): every read tool, no writes; not a grant."
    return {tid: {"capabilities": reads, "rationale": note} for tid in catalog["tasks"]}


# --- command line -----------------------------------------------------------------------------


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("validate", "freeze", "fixture"):
        p = sub.add_parser(name)
        p.add_argument("dir", type=Path)
        p.add_argument("--bundle", type=Path, help="planner bundle holding the tool catalogue")
        p.add_argument("--suites", nargs="+", default=list(SUITES), choices=SUITES)
        if name == "freeze":
            p.add_argument("--source", required=True, help='label, e.g. "G1" or a fixture name')
            p.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    if args.cmd == "fixture":
        if not args.dir.name.startswith(FIXTURE_SOURCE):
            parser.error(f"a fixture directory's name must start with {FIXTURE_SOURCE!r}")
        args.dir.mkdir(parents=True, exist_ok=True)
        for suite in args.suites:
            cat = catalog_from_bundle(args.bundle, suite) if args.bundle else None
            cat = cat or catalog_from_definitions(suite)
            text = json.dumps(fixture(cat), indent=2) + "\n"
            (args.dir / f"{suite}.json").write_text(text)
        print(f"wrote synthetic fixture for {', '.join(args.suites)} to {args.dir}")
        return 0

    grants, problems = load_dir(args.dir, args.suites, args.bundle)
    if problems:
        print(f"{len(problems)} problem(s):", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    count = sum(len(g) for g in grants.values())
    print(f"ok: {count} task entries in {', '.join(args.suites)}")
    if args.cmd == "freeze":
        record = freeze(args.dir, args.suites, args.source)
        args.out.write_text(json.dumps(record, indent=2) + "\n")
        print(f"froze {len(record['files'])} file(s) as {args.source!r} in {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
