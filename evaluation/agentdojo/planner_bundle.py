#!/usr/bin/env python3
"""Export the blinded bundle a planner writes task grants from (grant source G1).

For each suite `replay.py` uses, the bundle holds what a planner in a deployment would have
before the run starts, and nothing else:

  <out>/<suite>/tasks.json      each user task's id and the user's prompt text
  <out>/<suite>/tools.json      each tool's name, description and parameter schema, as the
                                model sees them in AgentDojo, and whether replay.py's
                                `is_read()` treats it as a read
  <out>/<suite>/principal.json  the user's own identifiers (email address or IBAN), only where
                                the environment makes them unambiguous (not slack)
  <out>/INSTRUCTIONS.md         planner/INSTRUCTIONS.md
  <out>/planner_grants.py       the validator, so the planner can check its files
  <out>/MANIFEST.json           benchmark version and the SHA-256 of every file above

No ground truth, injection task, attack text or environment content is written: each file is
built from an allowlist of fields (TASK_FIELDS, TOOL_FIELDS, PRINCIPAL_FIELDS). After writing,
`leak_check` reads the bundle back and fails (exit 1) if it finds any of these anywhere in it:

- a user task's ground-truth argument value that is not literally in that task's own prompt
  (values the principal file declares are reported, not failed);
- an injection task's goal, or an argument value of its ground truth;
- a line of the attack templates;
- a string of the default environment (other than the principal's identifiers);
- a word that names the benchmark's attacks.

A value found inside another task's prompt is public task text: it is reported as a prompt
coincidence and does not fail. So is a value listed in CATALOG_COINCIDENCES, found only in a
tool description, which was reviewed by hand. Short values (MIN_LEN) are skipped, since they
match anywhere.
The check's report is printed as counts; `--verbose` prints the reported values, which name
task values, so that output must never reach the planner. Nothing is written beside the bundle.

    PYTHONPATH=sdk/python/src python3 evaluation/agentdojo/planner_bundle.py --out DIR
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from agentdojo.attacks.important_instructions_attacks import (  # noqa: E402
    ImportantInstructionsAttack,
    ToolKnowledgeAttack,
)
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
from replay import SUITES, VERSION, by_id, is_read  # noqa: E402

TASK_FIELDS = ("id", "prompt")
TOOL_FIELDS = ("name", "description", "parameters", "read")
PRINCIPAL_FIELDS = {"workspace": ("email",), "travel": ("email",), "banking": ("iban",)}
INSTRUCTIONS = HERE / "planner" / "INSTRUCTIONS.md"
VALIDATOR = HERE / "planner_grants.py"
# A string shorter than this, or a number written in fewer characters, is not searched for.
MIN_LEN = 4
ENV_MIN_LEN = 12
# Values a tool description itself contains, reviewed one by one: a hit for these in a
# tools.json is reported, not failed, since removing them would change what the model sees.
CATALOG_COINCIDENCES = {
    "2022-01-01": "get_current_day's description gives it as an example of the date format",
}
FORBIDDEN_WORDS = ("inject", "attack", "adversar", "agentdojo", "ground truth", "ground_truth")


def task_entry(task) -> dict[str, Any]:
    return {"id": task.ID, "prompt": task.PROMPT}


def tool_entry(tool) -> dict[str, Any]:
    return {
        "name": tool.name,
        "description": tool.description,
        "parameters": tool.parameters.model_json_schema(),
        "read": is_read(tool.name),
    }


def principal(suite_name: str, env) -> dict[str, str] | None:
    """The user's own identifiers, or None where the environment names no single user."""
    if suite_name == "workspace":
        return {"email": env.inbox.account_email}
    if suite_name == "travel":
        if env.user.email != env.inbox.account_email:
            return None
        return {"email": env.user.email}
    if suite_name == "banking":
        return {"iban": env.bank_account.iban}
    return None


def catalog(suite_name: str) -> dict[str, Any]:
    """The catalogue planner_grants.py validates against, built as the bundle is."""
    suite = get_suite(VERSION, suite_name)
    return {
        "tasks": [t.ID for t in by_id(suite.user_tasks)],
        "tools": {
            t.name: {"parameters": e["parameters"], "read": e["read"]}
            for t in suite.tools
            for e in [tool_entry(t)]
        },
    }


def _dump(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def export(out: Path, suites=SUITES) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {"benchmark_version": VERSION, "suites": {}, "files": {}}
    for name in suites:
        suite = get_suite(VERSION, name)
        env = suite.load_and_inject_default_environment({})
        tasks = [task_entry(t) for t in by_id(suite.user_tasks)]
        tools = [tool_entry(t) for t in suite.tools]
        _dump(out / name / "tasks.json", tasks)
        _dump(out / name / "tools.json", tools)
        who = principal(name, env)
        if who is not None:
            assert set(who) == set(PRINCIPAL_FIELDS[name])
            _dump(out / name / "principal.json", who)
        manifest["suites"][name] = {"tasks": len(tasks), "tools": len(tools)}
    shutil.copyfile(INSTRUCTIONS, out / "INSTRUCTIONS.md")
    shutil.copyfile(VALIDATOR, out / "planner_grants.py")
    for path in sorted(out.rglob("*")):
        if path.is_file() and path.name != "MANIFEST.json":
            rel = path.relative_to(out).as_posix()
            manifest["files"][rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    _dump(out / "MANIFEST.json", manifest)
    return manifest


# --- allowlist check --------------------------------------------------------------------------


def allowlist_problems(out: Path, suites=SUITES) -> list[str]:
    """Every file and field in the bundle that the allowlist does not name."""
    allowed = {"INSTRUCTIONS.md", "planner_grants.py", "MANIFEST.json"}
    for s in suites:
        allowed |= {f"{s}/tasks.json", f"{s}/tools.json", f"{s}/principal.json"}
    problems = []
    for path in sorted(out.rglob("*")):
        rel = path.relative_to(out).as_posix()
        if path.is_file() and rel not in allowed:
            problems.append(f"unexpected file {rel}")
    for s in suites:
        for t in json.loads((out / s / "tasks.json").read_text()):
            if tuple(t) != TASK_FIELDS:
                problems.append(f"{s}/tasks.json: fields {list(t)}")
        for t in json.loads((out / s / "tools.json").read_text()):
            if tuple(t) != TOOL_FIELDS:
                problems.append(f"{s}/tools.json: fields {list(t)}")
        p = out / s / "principal.json"
        if p.exists() and tuple(json.loads(p.read_text())) != PRINCIPAL_FIELDS.get(s):
            problems.append(f"{s}/principal.json: fields not {PRINCIPAL_FIELDS.get(s)}")
    return problems


# --- leak check -------------------------------------------------------------------------------


def leaves(value, keys: bool = False) -> list[str]:
    """Every searchable scalar in a value, as text: strings and numbers, never booleans. With
    `keys`, an object's keys too (to search a file; never for the values being looked for, whose
    keys are argument and field names)."""
    if isinstance(value, dict):
        return [x for k, v in value.items() for x in (leaves(k) if keys else []) + leaves(v, keys)]
    if isinstance(value, (list, tuple, set)):
        return [x for v in value for x in leaves(v, keys)]
    if isinstance(value, bool) or value is None:
        return []
    if isinstance(value, (int, float, str)):
        text = str(value).strip()
        return [text] if len(text) >= MIN_LEN else []
    if hasattr(value, "model_dump"):
        return leaves(value.model_dump(mode="json"), keys)
    return [str(value)] if len(str(value)) >= MIN_LEN else []


def bundle_texts(out: Path) -> tuple[list[tuple[str, str]], dict[str, list[tuple[str, str]]]]:
    """`(texts outside prompts, prompts by suite)`: each a list of (where, lowercased text)."""
    other, prompts = [], {}
    for path in sorted(out.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(out).as_posix()
        if rel.endswith("/tasks.json"):
            suite = rel.split("/")[0]
            for t in json.loads(path.read_text()):
                prompts.setdefault(suite, []).append((f"{rel}#{t['id']}", t["prompt"].lower()))
                other.append((f"{rel}#{t['id']}.id", t["id"].lower()))
        elif path.suffix == ".json":
            strings = leaves(json.loads(path.read_text()), keys=True)
            other.append((rel, "\n".join(strings).lower()))
        else:
            other.append((rel, path.read_text().lower()))
    return other, prompts


def forbidden_values(suite_name: str, who: dict | None):
    """`[(kind, owner, value)]` that must not appear, and the principal values allowed."""
    suite = get_suite(VERSION, suite_name)
    env = suite.load_and_inject_default_environment({})
    mine = {v.lower() for v in (who or {}).values()}
    found = []
    for user in by_id(suite.user_tasks):
        pre = suite.load_and_inject_default_environment({})
        for call in user.ground_truth(pre):
            for value in leaves(dict(call.args)):
                found.append(("user_ground_truth", user.ID, value))
    for task in by_id(suite.injection_tasks):
        found.append(("injection_goal", task.ID, task.GOAL))
        pre = suite.load_and_inject_default_environment({})
        for call in task.ground_truth(pre):
            for value in leaves(dict(call.args)):
                found.append(("injection_ground_truth", task.ID, value))
    for template in (ImportantInstructionsAttack._JB_STRING, ToolKnowledgeAttack._JB_STRING):
        for line in template.splitlines():
            line = line.strip()
            if len(line) >= 20 and "{" not in line:
                found.append(("attack_template", "", line))
    for value in leaves(env.model_dump(mode="json")):
        if len(value) >= ENV_MIN_LEN:
            found.append(("environment", "", value))
    return found, mine


def leak_check(out: Path, suites=SUITES) -> dict[str, Any]:
    """Search the written bundle for everything `forbidden_values` lists. `failures` must be
    empty; `principal_values` and `prompt_coincidences` are reported for the record."""
    other, prompts = bundle_texts(out)
    report: dict[str, Any] = {
        "checked": 0,
        "failures": [],
        "principal_values": [],
        "prompt_coincidences": [],
        "catalog_coincidences": [],
        "forbidden_words": [],
    }
    seen = set()
    for where, text in other:
        for word in FORBIDDEN_WORDS:
            if word in text:
                report["forbidden_words"].append([where, word])
    for name in suites:
        p = out / name / "principal.json"
        who = json.loads(p.read_text()) if p.exists() else None
        values, mine = forbidden_values(name, who)
        own = {w: t for w, t in prompts.get(name, [])}
        for kind, owner, value in values:
            v = value.lower()
            if (name, kind, owner, v) in seen:
                continue
            seen.add((name, kind, owner, v))
            report["checked"] += 1
            if kind == "user_ground_truth" and v in own.get(f"{name}/tasks.json#{owner}", ""):
                continue  # the task's own prompt says it
            if v in mine:
                if any(v in t for _, t in other):
                    report["principal_values"].append([name, kind, owner, value])
                continue
            hits = [w for w, t in other if v in t]
            if (
                hits
                and value in CATALOG_COINCIDENCES
                and all(h.endswith("/tools.json") for h in hits)
            ):
                report["catalog_coincidences"].append([name, kind, owner, value, hits])
            elif hits:
                report["failures"].append([name, kind, owner, value, hits])
            in_prompts = [w for s in prompts.values() for w, t in s if v in t]
            if in_prompts:
                report["prompt_coincidences"].append([name, kind, owner, value, in_prompts])
    report["ok"] = not report["failures"] and not report["forbidden_words"]
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--suites", nargs="+", default=list(SUITES), choices=SUITES)
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="print the principal values and prompt coincidences (they name task values: "
        "never show this output to the planner)",
    )
    args = parser.parse_args()
    if args.out.exists() and any(args.out.iterdir()):
        raise SystemExit(f"{args.out} is not empty; export into a new directory")
    manifest = export(args.out, args.suites)
    problems = allowlist_problems(args.out, args.suites)
    report = leak_check(args.out, args.suites)
    print(json.dumps(manifest["suites"]))
    print(
        f"leak check: {report['checked']} values checked, {len(report['failures'])} failures, "
        f"{len(report['forbidden_words'])} forbidden words, "
        f"{len(report['principal_values'])} principal values (allowed), "
        f"{len(report['prompt_coincidences'])} prompt coincidences (reported), "
        f"{len(report['catalog_coincidences'])} catalogue coincidences (reported)"
    )
    for value, why in CATALOG_COINCIDENCES.items():
        print(f"  catalogue coincidence allowed by review: {value!r}: {why}")
    if args.verbose:
        for row in report["principal_values"]:
            print("  principal value:", json.dumps(row, ensure_ascii=False))
        for row in report["prompt_coincidences"] + report["catalog_coincidences"]:
            print("  coincidence:", json.dumps(row, ensure_ascii=False)[:300])
    for row in report["failures"] + report["forbidden_words"]:
        print("  FAIL:", json.dumps(row, ensure_ascii=False)[:300])
    if problems:
        for p in problems:
            print("  ALLOWLIST:", p)
    if problems or not report["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
