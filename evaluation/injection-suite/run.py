"""Run the injection suite and write ``results/<date>[-<tag>].json`` and ``.md``.

    ATTENUO_BIN_DIR=/path/to/bins python3 evaluation/injection-suite/run.py --split all

Options: ``--split dev|test|all`` (default dev), ``--seed N`` to shuffle the order of execution,
``--cases id,id`` or ``--suite name`` to run a subset, ``--arms direct,attenuo`` to skip arms,
``--date`` and ``--tag`` to name the output files, ``--out DIR``, ``--keep DIR`` to keep the
generated configs, logs and audit export.

Exit status 1 if any attenuo-arm call does not match its expected outcome, if a denied call
reached the upstream, if an allowed call did not return its scripted ``output:``, or if the audit
check fails. The ``attenuo_labels`` arm is skipped, with a message, when the server does not
answer ``-32008 approval_required``. In that arm a gated call is decided by the scripted approver
through ``POST /admin/approvals/{id}`` and, when granted, retried once; the run also fails if a
retry gets ``-32008`` again or if the retry did not consume the approval. The ``attenuo_limits``
and ``attenuo_labels_limits`` arms are skipped when the server does not enforce run limits
(ADR-0010). The ``attenuo_labels_args`` arm (option (b), argument-level taint) settles approvals
like ``attenuo_labels`` and is skipped when the probe's ``-32008`` does not name the copied
argument in ``untrusted_args``. Exit status 2,
before anything runs, if the test split is requested while ``policies/`` differs from its frozen
hashes or while the labelling oracle (``label_rules.py``) disagrees with a hand label that has no
``label_note``.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import subprocess
import sys
from pathlib import Path
from typing import Any

import harness
import label_rules

STAGE_NOTE = {
    "capability": "the delegation token does not cover the call",
    "policy": "the suite's Cedar policy refuses it",
    "lease": "the session was revoked",
}


def _git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args], cwd=harness.ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _bin_version(path: Path) -> str:
    try:
        out = subprocess.run([str(path), "--version"], capture_output=True, text=True, timeout=10)
        return (out.stdout or out.stderr).strip().splitlines()[0]
    except (OSError, IndexError, subprocess.SubprocessError):
        return "unknown"


def select(
    suites: list[harness.Suite], cases: str | None, suite: str | None, missing_ok: bool = False
) -> list[harness.Suite]:
    wanted = set(cases.split(",")) if cases else None
    out = []
    for s in suites:
        if suite and s.name != suite:
            continue
        s.cases = [c for c in s.cases if wanted is None or c.id in wanted]
        if s.cases:
            out.append(s)
    if wanted and not missing_ok:
        missing = wanted - {c.id for s in out for c in s.cases}
        if missing:
            raise SystemExit(f"unknown case ids: {', '.join(sorted(missing))}")
    return out


def problems(doc: dict[str, Any]) -> list[str]:
    """Everything that should fail the run: unexpected outcomes, leaks past a deny, audit."""
    out = []
    for c in doc["calls"]:
        where = f"{c['arm']} {c['case']}#{c['index']} {c['tool']}"
        if c["arm"] == "attenuo" and not c["as_expected"]:
            out.append(
                f"{where}: expected {c['expect']}/{c['expect_stage']}, "
                f"got {c['outcome']}/{c['reason']}"
            )
        if c["arm"] in harness.LIMIT_ARMS:
            if not limits_consistent(c):
                out.append(
                    f"{where}: attenuo expects {c['expect']}/{c['expect_stage']}, limits arm "
                    f"got {c['outcome']}/{c['reason']}"
                )
        elif c["arm"] in harness.LABEL_ARMS and not labels_consistent(c):
            out.append(
                f"{where}: attenuo expects {c['expect']}/{c['expect_stage']}, labels arm got "
                f"{c['outcome']}/{c['reason']}"
            )
        if c["outcome"] in ("deny", "gated") and c["reached_upstream"]:
            out.append(f"{where}: {c['outcome']} but reached the upstream")
        if c.get("output_returned") is False:
            out.append(f"{where}: allowed, but the reply lacks the scripted output")
        if c["arm"] != "attenuo" and c["outcome"] == "error":
            out.append(f"{where}: upstream returned an error")
        if c["arm"] in harness.LABEL_ARMS and c["outcome"] == "gated":
            out += [f"{where}: {p}" for p in approval_problems(c)]
    for arm, a in doc["audit"].items():
        if a["decisions_unmatched"]:
            out.append(
                f"{arm}: {len(a['decisions_unmatched'])} decisions not found in the audit log"
            )
        if a.get("retries_unmatched"):
            out.append(
                f"{arm}: {len(a['retries_unmatched'])} retries after a grant whose audit record "
                "does not show the decision or the approval it used"
            )
        if a["cli_verify_exit"] != 0 or a["offline_verify_exit"] != 0 or a["export_exit"] != 0:
            out.append(f"{arm}: audit verification failed")
    return out


def approval_problems(c: dict[str, Any]) -> list[str]:
    """What went wrong with a gated call's decision and retry (labels arm)."""
    after = c.get("after_approval")
    aid = c.get("approval_id")
    state = c.get("approval_state")
    if after is None:
        return []
    if after == "gated":
        return [f"granted approval {aid}, but the identical retry got -32008 again"]
    if after == "no_decision":
        return ["-32008 without an approval_id, so the approver could not answer"]
    if after == "error":
        return [f"approval {aid}: decision or retry failed ({c.get('retry_reason')})"]
    out = []
    if after == "declined" and state != "declined":
        out.append(f"declined approval {aid}, but it is {state}")
    if after == "denied" and c.get("retry_reached_upstream"):
        out.append("retry after the grant was denied but reached the upstream")
    if after == "allowed":
        if state != "consumed" or c.get("approval_consumed_by") != c.get("retry_decision_id"):
            out.append(
                f"retry allowed, but approval {aid} is {state}, consumed by "
                f"{c.get('approval_consumed_by')}, not by the retry {c.get('retry_decision_id')}"
            )
        if not c.get("retry_reached_upstream"):
            out.append("allowed after approval, but the retry did not reach the upstream")
        if c.get("retry_output_returned") is False:
            out.append("allowed after approval, but the reply lacks the scripted output")
    return out


def labels_consistent(c: dict[str, Any]) -> bool:
    """A call in the labels arm keeps its attenuo label, except that an allowed call may be
    gated: an approval obligation can only ask, and a deny stays a deny at the same stage."""
    if c["expect"] == "deny":
        return bool(c["outcome"] == "deny" and c["stage"] == c["expect_stage"])
    return c["outcome"] in ("allow", "gated")


def limits_consistent(c: dict[str, Any]) -> bool:
    """A call in a limits arm keeps its attenuo label, except that a run limit may refuse it
    (stage ``budget``): an allowed call, or one the policy would deny, since the limit check
    comes before the policy. In the combined arm an allowed call may also be gated."""
    if c["outcome"] == "deny" and c["stage"] == "budget":
        return c["expect"] == "allow" or c["expect_stage"] == "policy"
    if c["expect"] == "deny":
        return bool(c["outcome"] == "deny" and c["stage"] == c["expect_stage"])
    return c["outcome"] in (("allow", "gated") if c["arm"] in harness.LABEL_ARMS else ("allow",))


def _pct(n: int, d: int) -> str:
    return f"{n}/{d} ({100 * n / d:.0f}%)" if d else "0/0"


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float] | None:
    """Wilson score interval for k successes in n trials (95% by default); None for n = 0."""
    if n == 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def _ci(k: int, n: int) -> str:
    w = wilson(k, n)
    if w is None:
        return "0/0"
    return f"{k}/{n} ({100 * k / n:.0f}%, {100 * w[0]:.0f}-{100 * w[1]:.0f}%)"


ARM_NAMES = {
    "direct": "No attenuo (direct to upstream)",
    "scope_only": "Scope-only tokens (tool names, no argument constraints, permit-all policy)",
    "scope_constraints": "Tokens with argument constraints, permit-all policy",
    "policy_only": "Suite policy with the root token (no attenuation)",
    "attenuo": "attenuo full",
    "attenuo_labels": "attenuo full plus output labels (scripted approver)",
    "attenuo_limits": "attenuo full plus the frozen run-limit rule",
    "attenuo_labels_limits": "attenuo full plus output labels and the run-limit rule",
    "attenuo_labels_args": "attenuo full plus argument-level labels (scripted approver)",
}


def arm_rates(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Per arm: attack calls allowed and benign calls denied, with Wilson 95% intervals.

    ``attack_allowed`` counts calls allowed on the first attempt, without an approval. A gated
    call (``-32008 approval_required``, labels arm only) was answered by the scripted approver
    and, if granted, retried; ``*_after`` counts what became of them (``harness.AFTER_APPROVAL``),
    ``attack_allowed_final`` adds attack calls allowed after a grant, and
    ``benign_completed_after_approval`` the benign calls that went through on the retry.
    ``attack_allowed_approve_all`` is the bound for an approver who grants everything. Arms
    without approvals have no gated calls, so their numbers are as before.
    """
    out: dict[str, dict[str, Any]] = {}
    for arm in doc["arms"]:
        calls = [c for c in doc["calls"] if c["arm"] == arm]
        att = [c for c in calls if c["role"] == "attack"]
        ben = [c for c in calls if c["role"] == "benign"]
        aa = sum(c["outcome"] not in ("deny", "gated") for c in att)
        ag = sum(c["outcome"] == "gated" for c in att)
        bd = sum(c["outcome"] == "deny" for c in ben)
        bg = sum(c["outcome"] == "gated" for c in ben)
        att_after = _after_counts(att)
        ben_after = _after_counts(ben)
        budget = [c for c in calls if c["outcome"] == "deny" and c["stage"] == "budget"]
        out[arm] = {
            "attack_calls": len(att),
            "attack_allowed": aa,
            "attack_allowed_wilson95": wilson(aa, len(att)),
            "attack_reached_upstream": sum(
                bool(c["reached_upstream"] or c.get("retry_reached_upstream")) for c in att
            ),
            "benign_calls": len(ben),
            "benign_denied": bd,
            "benign_denied_wilson95": wilson(bd, len(ben)),
            "attack_gated": ag,
            "benign_gated": bg,
            "approval_requests": ag + bg,
            "attack_allowed_approve_all": aa + ag,
            "attack_allowed_approve_all_wilson95": wilson(aa + ag, len(att)),
            "attack_after": att_after,
            "benign_after": ben_after,
            "attack_allowed_final": aa + att_after["allowed"],
            "attack_allowed_final_wilson95": wilson(aa + att_after["allowed"], len(att)),
            "benign_completed_after_approval": ben_after["allowed"],
            "attack_budget_denied": sum(c["role"] == "attack" for c in budget),
            "benign_budget_denied": sum(c["role"] == "benign" for c in budget),
            # Granted calls whose retry a run limit refused (``after_approval`` ``denied``).
            "retry_budget_denied": sum(
                c.get("after_approval") == "denied" and c.get("retry_stage") == "budget"
                for c in calls
            ),
        }
    return out


def _after_counts(calls: list[dict[str, Any]]) -> dict[str, int]:
    """How many gated calls ended each way (``harness.AFTER_APPROVAL``); ``None`` for gated
    calls with no ``after_approval`` field (results written before the runner retried)."""
    out = dict.fromkeys(harness.AFTER_APPROVAL, 0)
    for c in calls:
        if c["outcome"] == "gated":
            k = c.get("after_approval")
            if k in out:
                out[k] += 1
    return out


def taxonomy_rows(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Per taxonomy class (test split) or plan class (dev, which has no taxonomy), attenuo arm:
    attack calls, how they were stopped, which got through."""
    cm = doc["case_meta"]
    rows: dict[str, dict[str, Any]] = {}
    for c in doc["calls"]:
        if c["arm"] != "attenuo":
            continue
        key = cm[c["case"]]["taxonomy"] or f"class {cm[c['case']]['class']}"
        r = rows.setdefault(
            key,
            {"taxonomy": key, "cases": set(), "attack_calls": 0, "attack_allowed": 0,
             "benign_calls": 0, "benign_denied": 0, "missed_in": set(),
             **{f"blocked_{s}": 0 for s in harness.STAGES}, "blocked_other": 0},
        )  # fmt: skip
        r["cases"].add(c["case"])
        if c["role"] == "attack":
            r["attack_calls"] += 1
            if c["outcome"] == "deny":
                st = c["stage"] if c["stage"] in harness.STAGES else "other"
                r[f"blocked_{st}"] += 1
            else:
                r["attack_allowed"] += 1
                r["missed_in"].add(c["case"])
        else:
            r["benign_calls"] += 1
            r["benign_denied"] += int(c["outcome"] == "deny")
    out = []
    for r in sorted(rows.values(), key=lambda r: r["taxonomy"]):
        r["cases"] = sorted(r["cases"])
        r["missed_in"] = sorted(r["missed_in"])
        out.append(r)
    return out


def render_split(doc: dict[str, Any], split: str) -> list[str]:
    rows = harness.summarise(doc)["rows"]
    by_arm: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        by_arm.setdefault(r["arm"], []).append(r)

    def total(arm: str) -> dict[str, Any]:
        t: dict[str, Any] = {"suite": "**all**"}
        for r in by_arm.get(arm, []):
            for k, v in r.items():
                if isinstance(v, int):
                    t[k] = t.get(k, 0) + v
        return t

    ob = by_arm.get("attenuo", [])
    n_calls = sum(r["attack_calls"] + r["benign_calls"] for r in ob)
    lab = doc["labels"]
    L = [
        f"## Split `{split}`",
        "",
        f"- Cases: {doc['cases']} in {len({r['suite'] for r in rows})} suites; calls per arm: "
        f"{n_calls}; execution order seed: {doc['seed']}",
        f"- Labelling oracle vs hand labels: {lab['call_agreement']}/{lab['calls']} call labels "
        f"agree (Cohen's kappa {_kappa(lab['kappa_calls'])}), {lab['class_agreement']}/"
        f"{lab['cases']} case classes agree (kappa {_kappa(lab['kappa_class'])}); "
        f"{len(lab['disagreements'])} disagreements, {len(lab['unresolved'])} unresolved.",
        "",
        "### Arms compared",
        "",
        "Rates with Wilson 95% intervals. Calls within a case are not independent, so the "
        "intervals are narrower than they should be.",
        "",
        "| Arm | Attack calls allowed | Attack calls that reached the upstream "
        "| Benign calls denied |",
        "|---|---:|---:|---:|",
    ]
    for arm, r in doc["rates"].items():
        L.append(
            f"| {ARM_NAMES[arm]} | {_ci(r['attack_allowed'], r['attack_calls'])} "
            f"| {_pct(r['attack_reached_upstream'], r['attack_calls'])} "
            f"| {_ci(r['benign_denied'], r['benign_calls'])} |"
        )
    if any(a in harness.LABEL_ARMS for a in doc["rates"]):
        L.append("")
        L.append(
            "For the labels arm, the attack column counts calls allowed without an approval. "
            "Gated calls were answered by the scripted approver and, when granted, retried; see "
            "the next table."
        )
    L += render_labels(doc)
    L += render_limits(doc)
    L += [
        "",
        "### attenuo by suite and stage",
        "",
        "| Suite | Cases | Attack calls | Name | Capability | Policy | Exchange | Lease "
        "| Allowed | Benign calls | Benign denied |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in [*ob, total("attenuo")] if ob else []:
        L.append(
            f"| {r['suite']} | {r['cases']} | {r['attack_calls']} | {r['blocked_name']} "
            f"| {r['blocked_capability']} | {r['blocked_policy']} | {r['blocked_exchange']} "
            f"| {r['blocked_lease']} | {r['attack_allowed']} | {r['benign_calls']} "
            f"| {r['benign_denied']} |"
        )
    if ob:
        t = total("attenuo")
        L += [
            "",
            f"Calls that did not match the corpus's expected outcome: {t['unexpected']}. "
            f"{t['blocked_lease']} attack calls were refused only because the case scripted a "
            "revocation by the user.",
        ]

    tax = doc["taxonomy"]
    L += [
        "",
        "### attenuo by attack class",
        "",
        "Rows are the `taxonomy:` classes of [TAXONOMY.md](../cases/test/TAXONOMY.md) where cases "
        "have one, else the plan's S/C/D/N class.",
        "",
        "| Class | Cases | Attack calls | Name | Capability | Policy | Exchange | Lease | Allowed "
        "| Benign denied |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in tax:
        L.append(
            f"| {r['taxonomy']} | {len(r['cases'])} | {r['attack_calls']} | {r['blocked_name']} "
            f"| {r['blocked_capability']} | {r['blocked_policy']} | {r['blocked_exchange']} "
            f"| {r['blocked_lease']} | {r['attack_allowed']} "
            f"| {r['benign_denied']}/{r['benign_calls']} |"
        )

    calls = [c for c in doc["calls"] if c["arm"] == "attenuo"]
    cm = doc["case_meta"]
    missed = [r for r in tax if r["attack_allowed"]]
    L += ["", "### What attenuo cannot block", ""]
    if missed:
        L += [
            "Classes with at least one attack call that attenuo allowed. Each of these calls "
            "uses a tool and arguments the token and the frozen policy permit.",
            "",
            "| Class | Allowed of attack calls | Cases |",
            "|---|---:|---|",
        ]
        for r in missed:
            L.append(
                f"| {r['taxonomy']} | {r['attack_allowed']}/{r['attack_calls']} "
                f"| {', '.join(r['missed_in'])} |"
            )
    else:
        L.append("No attack call was allowed.")
    fn = [c for c in calls if c["role"] == "attack" and c["outcome"] != "deny"]
    fp = [c for c in calls if c["role"] == "benign" and c["outcome"] == "deny"]
    L += ["", "### Attack calls attenuo allowed", ""]
    if fn:
        L += ["| Case | Class | Call | Why it got through |", "|---|---|---|---|"]
        for c in fn:
            why = c["note"] or cm[c["case"]]["note"] or "The token and the frozen policy permit it."
            L.append(f"| {c['case']} | {cm[c['case']]['class']} | `{c['tool']}` | {why} |")
    else:
        L.append("None.")
    L += ["", "### Benign calls attenuo denied", ""]
    if fp:
        L += ["| Case | Call | Reason | Why |", "|---|---|---|---|"]
        for c in fp:
            why = c["note"] or cm[c["case"]]["note"] or ""
            L.append(f"| {c['case']} | `{c['tool']}` | `{c['reason']}` | {why} |")
    else:
        L.append("None.")

    by_class: dict[str, list[int]] = {}
    case_attacks: dict[str, list[bool]] = {}
    for c in calls:
        if c["role"] == "attack":
            case_attacks.setdefault(c["case"], []).append(c["outcome"] == "deny")
    for cid, blocked in case_attacks.items():
        b = by_class.setdefault(cm[cid]["class"], [0, 0, 0, 0])
        b[0] += 1
        b[1] += int(all(blocked))
        b[2] += len(blocked)
        b[3] += sum(blocked)
    L += [
        "",
        "### By case class (S/C/D/N)",
        "",
        "| Class | Cases | Cases with every attack call blocked | Attack calls | Blocked |",
        "|---|---:|---:|---:|---:|",
    ]
    for k in harness.CLASSES:
        if k in by_class:
            n, full, calls_n, calls_b = by_class[k]
            L.append(f"| {k} | {n} | {_pct(full, n)} | {calls_n} | {_pct(calls_b, calls_n)} |")

    L += ["", "### Audit", ""]
    for arm, a in doc["audit"].items():
        L.append(
            f"- {arm}: {a['entries']} audit entries; {a['decisions_matched']} of "
            f"{a['decisions_matched'] + len(a['decisions_unmatched'])} call decisions found by id "
            f"with the same decision and reason; `attenuo audit verify` exit "
            f"{a['cli_verify_exit']}, offline `audit verify --file` on the export exit "
            f"{a['offline_verify_exit']}."
        )
    probs = problems(doc)
    L += ["", "### Problems", ""]
    L += [f"- {p}" for p in probs] if probs else ["None."]
    return L


def render_labels(doc: dict[str, Any]) -> list[str]:
    """The approval columns of the labels arm, or why it did not run."""
    L: list[str] = []
    for arm, why in (doc.get("skipped_arms") or {}).items():
        L += ["", f"Arm `{arm}` was not run: {why}."]
    for arm in harness.LABEL_ARMS:
        r = doc["rates"].get(arm)
        if r is None:
            continue
        aa, ba = r["attack_after"], r["benign_after"]
        a_other = r["attack_gated"] - aa["allowed"] - aa["declined"]
        b_other = r["benign_gated"] - ba["allowed"] - ba["declined"]
        L += [
            "",
            f"### Approvals in `{arm}`",
            "",
            'A gated call got JSON-RPC `-32008` with `data.reason = "approval_required"` and an '
            "`approval_id`. The scripted approver stands in for the user: it grants a call "
            "labelled benign and declines one labelled attack, as the operator, through "
            "`POST /admin/approvals/{id}`. A granted call is retried once, identically, from the "
            "same hop. An attack call allowed after a grant would be the approver's decision, "
            "not something attenuo let through on its own. The approve-all bound treats every "
            "request as granted.",
            "",
            "| Attack allowed without approval | Attack gated | Gated, approved, allowed "
            "| Gated, declined | Gated, other | Attack allowed in the end | Approve-all bound |",
            "|---:|---:|---:|---:|---:|---:|---:|",
            f"| {_ci(r['attack_allowed'], r['attack_calls'])} "
            f"| {_pct(r['attack_gated'], r['attack_calls'])} "
            f"| {aa['allowed']} | {aa['declined']} | {a_other} "
            f"| {_ci(r['attack_allowed_final'], r['attack_calls'])} "
            f"| {_ci(r['attack_allowed_approve_all'], r['attack_calls'])} |",
            "",
            "| Benign gated | Completed after approval | Gated, declined | Gated, other "
            "| Benign denied | Approval requests |",
            "|---:|---:|---:|---:|---:|---:|",
            f"| {_pct(r['benign_gated'], r['benign_calls'])} "
            f"| {ba['allowed']}/{r['benign_gated']} | {ba['declined']} | {b_other} "
            f"| {_pct(r['benign_denied'], r['benign_calls'])} "
            f"| {r['approval_requests']} |",
            "",
            '"Gated, other" is a grant whose retry was denied, failed or was gated again, or a '
            "`-32008` without an `approval_id`; any of these except a denied retry also fails "
            "the run.",
        ]
        if arm in harness.LIMIT_ARMS:
            L += [
                "",
                f"With run limits, a granted retry is charged like any allowed call; "
                f"{r['retry_budget_denied']} granted retries were denied by a run limit "
                "(`retry_reason` `budget_exhausted`, stage `budget`), which is expected and "
                "not a problem when the retry did not reach the upstream.",
            ]
    return L


def render_limits(doc: dict[str, Any]) -> list[str]:
    """What the run-limit rule refused in the limits arms."""
    L: list[str] = []
    for arm in harness.LIMIT_ARMS:
        r = doc["rates"].get(arm)
        if r is None:
            continue
        L += [
            "",
            f"### Run limits in `{arm}`",
            "",
            "The frozen rule in [`policies/limits-rule.json`](../policies/limits-rule.json) adds "
            "`calls: 1` to every capability that is not a read. A refused call got JSON-RPC "
            "`-32003` with a `budget_*` or `limit_arg_invalid` reason (stage `budget`).",
            "",
            "| Attack allowed | Attack refused by a limit | Benign refused by a limit "
            "| Benign denied (any stage) |",
            "|---:|---:|---:|---:|",
            f"| {_ci(r['attack_allowed'], r['attack_calls'])} "
            f"| {_pct(r['attack_budget_denied'], r['attack_calls'])} "
            f"| {_pct(r['benign_budget_denied'], r['benign_calls'])} "
            f"| {_ci(r['benign_denied'], r['benign_calls'])} |",
        ]
    return L


def _kappa(k: float | None) -> str:
    return "n/a" if k is None else f"{k:.2f}"


def render_markdown(full: dict[str, Any], name: str) -> str:
    meta = full["meta"]
    L = [
        f"# Injection suite results, {name}",
        "",
        "Generated by `evaluation/injection-suite/run.py`; do not edit by hand. Method, corpus and "
        "limits: [README](../README.md). Summary: "
        "[docs/evaluation/injection-suite.md](../../../docs/evaluation/injection-suite.md).",
        "",
        f"- Repository HEAD when run: `{meta['commit']}`; binaries report {meta['server_version']}",
        f"- Splits: {', '.join(full['splits'])}. Policies match their frozen hashes: "
        f"{'yes' if not meta['freeze_violations'] else 'NO'}. SHA-256 of every case file, "
        "policy file and binary is in the JSON under `meta.sha256`.",
        "- Synthetic tool-call sequences, no LLM in the loop. Upstreams are echo servers. The "
        "test cases were written by someone who had read the frozen policies.",
        "",
    ]
    for split, doc in full["splits"].items():
        L += [*render_split(doc, split), ""]
    return "\n".join(L).rstrip("\n") + "\n"


# --- gate -------------------------------------------------------------------------------------


def gate(split: str) -> list[str]:
    """Reasons not to report numbers for ``split``: for the test split, a policy file that
    differs from its frozen hash, or an oracle disagreement without a ``label_note``."""
    if split != "test":
        return []
    out = [f"freeze: {v}" for v in harness.freeze_violations()]
    if out:
        return out  # the oracle's policy model is only valid for the frozen policies
    for d in label_rules.report("test")["unresolved"]:
        where = d["case"] if d["index"] is None else f"{d['case']}#{d['index']} {d['tool']}"
        out.append(
            f"label: {where} ({d['kind']}) hand {d['hand']} vs oracle {d['oracle']}, no label_note"
        )
    return out


def sha256_meta(splits: list[str], bins: harness.Binaries) -> dict[str, Any]:
    return {
        "cases": {sp: harness.case_files(sp) for sp in splits},
        "policies": harness.policy_hashes(),
        "binaries": {
            p.name: harness.sha256_file(p) for p in (bins.server, bins.cli, bins.fake_mcp)
        },
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--split", choices=("dev", "test", "all"), default="dev")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--cases")
    ap.add_argument("--suite")
    ap.add_argument("--arms", default=",".join(harness.ARMS))
    ap.add_argument("--date", default=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d"))
    ap.add_argument("--tag", help="appended to the output file names: <date>-<tag>")
    ap.add_argument("--out", type=Path, default=harness.HERE / "results")
    ap.add_argument("--keep", type=Path)
    a = ap.parse_args(argv)

    arms = tuple(x for x in a.arms.split(",") if x)
    if any(x not in harness.ARMS for x in arms):
        raise SystemExit(f"--arms takes {','.join(harness.ARMS)}")
    splits = list(harness.SPLITS) if a.split == "all" else [a.split]
    refusals = [r for sp in splits for r in gate(sp)]
    if refusals:
        for r in refusals:
            print("REFUSED:", r, file=sys.stderr)
        print(
            "Not reporting test-split numbers. Restore policies/ to the frozen hashes, or "
            "resolve each label disagreement with a label_note in the case file.",
            file=sys.stderr,
        )
        return 2

    bins = harness.find_binaries()
    docs: dict[str, Any] = {}
    for sp in splits:
        suites = select(harness.load_corpus(sp), a.cases, a.suite, missing_ok=len(splits) > 1)
        if not suites:
            continue
        keep = a.keep / sp if a.keep else None
        doc = harness.run(suites, arms, keep=keep, seed=a.seed)
        doc["labels"] = label_rules.agreement(suites, label_rules.label(suites))
        doc["rates"] = arm_rates(doc)
        doc["taxonomy"] = taxonomy_rows(doc)
        doc["summary"] = harness.summarise(doc)
        docs[sp] = doc
    if not docs:
        raise SystemExit("no cases selected")
    name = f"{a.date}-{a.tag}" if a.tag else a.date
    full = {
        "meta": {
            "date": a.date,
            "commit": _git("rev-parse", "--short", "HEAD"),
            "server_version": _bin_version(bins.server),
            "seed": a.seed,
            "freeze_violations": harness.freeze_violations(),
            "sha256": sha256_meta(list(docs), bins),
        },
        "splits": docs,
    }
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / f"{name}.json").write_text(json.dumps(full, indent=1, sort_keys=False) + "\n")
    md = render_markdown(full, name)
    (a.out / f"{name}.md").write_text(md)
    print(md)
    probs = [f"{sp}: {p}" for sp, d in docs.items() for p in problems(d)]
    for p in probs:
        print("PROBLEM:", p, file=sys.stderr)
    return 1 if probs else 0


if __name__ == "__main__":
    sys.exit(main())
