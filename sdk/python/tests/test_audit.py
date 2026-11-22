"""Offline export verification (`attenuo.audit.verify_export`)."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from attenuo.audit import (
    EXPORT_FORMAT,
    GENESIS_HASH,
    PRUNE_TOOL,
    SHIPPED_FORMAT,
    CrossCheckReport,
    ExportError,
    ExportsReport,
    LinkProblem,
    cross_check,
    entry_hash,
    parse_shipped,
    verify_export,
    verify_exports,
)

from .helpers import b64

KEY = Ed25519PrivateKey.generate()
KID = "k1"
JWKS = {
    "keys": [
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": KID,
            "x": b64(KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
        }
    ]
}

# The same record and hash are asserted by the Rust test `entry_hash_golden_vector`.
GOLDEN_RECORD = {
    "agents": ["agent:planner"],
    "arguments_digest": "ab" * 32,
    "chain_depth": 1,
    "chain_digest": "cd" * 32,
    "chain_id": "l1",
    "decision": "allow",
    "id": "00000000-0000-4000-8000-000000000001",
    "kind": "decision",
    "leases": ["l1"],
    "originating_subject": "user:mudit",
    "reason": "policy_allow",
    "server": "github",
    "tool": "read_file",
    "at": "2026-10-23T12:00:00Z",
}
GOLDEN_HASH = "e8ababad86538918f6eee2d5edb7e6aa4bfa8f8f6ea032f2b5fde00dfe52d693"


def record(i: int, kind: str = "decision") -> dict[str, Any]:
    return {**GOLDEN_RECORD, "kind": kind, "reason": f"r{i}", "tool": f"t{i}"}


def sign(seq: int, head_hash: str, kid: str = KID, key: Ed25519PrivateKey = KEY) -> dict[str, Any]:
    at = "2026-10-23T12:00:00Z"
    payload = rfc8785.dumps([seq, head_hash, at, kid])
    ctx = b"attenuo-checkpoint-v1"
    sig = key.sign(struct.pack(">I", len(ctx)) + ctx + payload)
    return {"seq": seq, "head_hash": head_hash, "at": at, "kid": kid, "signature": b64(sig)}


def make_export(
    n: int = 6, *, start: int = 1, cps: tuple[int, ...] = (3, 6), end: int | None = None
) -> list[dict[str, Any]]:
    """Header, entries `start..start+n-1` (a window of a longer log if start > 1), checkpoints."""
    prev = GENESIS_HASH if start == 1 else "ee" * 32
    entries: list[dict[str, Any]] = []
    for seq in range(start, start + n):
        h = entry_hash(seq, prev, record(seq))
        entries.append(
            {"type": "entry", "seq": seq, "prev_hash": prev, "record": record(seq), "entry_hash": h}
        )
        prev = h
    last = start + n - 1
    header = {
        "type": "header",
        "format": EXPORT_FORMAT,
        "from": start,
        "to": end if end is not None else last,
        "exported_at": "2026-10-23T12:00:00Z",
    }
    by_seq = {e["seq"]: e["entry_hash"] for e in entries}
    cp_lines = [{"type": "checkpoint", **sign(s, by_seq[s])} for s in cps if s in by_seq]
    return [header, *entries, *cp_lines]


def lines(objs: list[dict[str, Any]]) -> list[str]:
    return [json.dumps(o) + "\n" for o in objs]


def verify(objs: list[dict[str, Any]], **kw: Any) -> Any:
    return verify_export(lines(objs), checkpoint_public_keys=JWKS, **kw)


def test_golden_entry_hash_matches_rust() -> None:
    assert entry_hash(7, "11" * 32, GOLDEN_RECORD) == GOLDEN_HASH


def test_a_clean_export_verifies_from_a_path_lines_bytes_and_the_json_form(tmp_path: Path) -> None:
    objs = make_export()
    r = verify(objs)
    assert r.ok and r.entries == 6 and r.first_bad_seq is None
    assert (r.first_seq, r.last_seq, r.from_genesis) == (1, 6, True)
    assert (r.checkpoints, r.last_signed_seq, r.unsigned_tail) == (2, 6, 0)
    path = tmp_path / "e.jsonl"
    path.write_text("".join(lines(objs)))
    assert verify_export(path, checkpoint_public_keys=JWKS).ok
    assert verify_export(str(path), checkpoint_public_keys=JWKS).ok
    with open(path, "rb") as f:
        assert verify_export(f, checkpoint_public_keys=JWKS).ok
    form = {
        "header": objs[0],
        "entries": [o for o in objs if o["type"] == "entry"],
        "checkpoints": [o for o in objs if o["type"] == "checkpoint"],
    }
    assert verify_export(json.dumps(form, indent=2).splitlines(), checkpoint_public_keys=JWKS).ok


def test_keys_may_be_a_kid_map_of_raw_or_base64url_keys() -> None:
    raw = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    for keys in ({KID: raw}, {KID: b64(raw)}):
        assert verify_export(lines(make_export()), checkpoint_public_keys=keys).ok
    with pytest.raises(ExportError):
        verify_export(lines(make_export()), checkpoint_public_keys={KID: b"short"})


@pytest.mark.parametrize("seq", [1, 2, 4, 6])
def test_one_changed_byte_in_an_entry_is_reported_at_its_seq(seq: int) -> None:
    objs = make_export()
    objs[seq]["record"]["chain_digest"] = "ce" + "cd" * 31
    r = verify(objs)
    assert not r.ok and r.first_bad_seq == seq
    assert r.entries == seq


def test_a_changed_kind_or_chain_id_breaks_the_hash() -> None:
    for field, value in (("kind", "admin"), ("chain_id", "other")):
        objs = make_export()
        objs[3]["record"][field] = value
        assert verify(objs).first_bad_seq == 3


def test_a_broken_link_a_gap_and_a_reorder_are_found() -> None:
    objs = make_export()
    objs[3]["prev_hash"] = "00" * 32
    assert verify(objs).first_bad_seq == 3
    objs = make_export()
    del objs[3]  # entry 3 removed; entry 4 now follows 2
    r = verify(objs)
    assert not r.ok and r.first_bad_seq == 4
    objs = make_export()
    objs[2], objs[3] = objs[3], objs[2]
    assert verify(objs).first_bad_seq == 3


def test_checkpoint_signatures_and_head_hashes_are_checked() -> None:
    objs = make_export()
    cp = objs[-1]
    cp["signature"] = b64(b"x" * 64)
    r = verify(objs)
    assert not r.ok and [b.seq for b in r.bad_checkpoints] == [6]
    assert r.bad_checkpoints[0].reason == "signature does not verify"
    assert r.last_signed_seq == 3 and r.unsigned_tail == 3 and r.unsigned_tail_rejected

    objs = make_export()
    objs[-1] = {"type": "checkpoint", **sign(6, "ff" * 32)}  # validly signed, wrong head
    r = verify(objs)
    assert [b.reason for b in r.bad_checkpoints] == ["head hash differs from the log at that seq"]

    other = Ed25519PrivateKey.generate()
    objs = make_export()
    objs[-1] = {"type": "checkpoint", **sign(6, objs[6]["entry_hash"], key=other)}
    assert not verify(objs).ok
    objs = make_export()
    objs[-1] = {"type": "checkpoint", **sign(6, objs[6]["entry_hash"], kid="nope")}
    assert "unknown signing key `nope`" in verify(objs).bad_checkpoints[0].reason


def test_a_checkpoint_outside_the_entries_is_signature_checked_only() -> None:
    objs = make_export(cps=(3, 6))
    objs.append({"type": "checkpoint", **sign(50, "aa" * 32)})
    assert verify(objs).ok
    objs.append({"type": "checkpoint", **{**sign(51, "aa" * 32), "head_hash": "bb" * 32}})
    r = verify(objs)
    assert not r.ok and [b.seq for b in r.bad_checkpoints] == [51]


def test_a_checkpoint_past_the_last_entry_is_not_matched_but_the_header_catches_the_cut() -> None:
    # Like the Rust check: a checkpoint beyond the entries is only signature-checked, and the
    # missing entry shows as a truncated range.
    objs = make_export(n=6, cps=(3, 6))
    cut = [o for o in objs if o.get("seq") != 6 or o["type"] == "checkpoint"]
    r = verify(cut)
    assert not r.ok and r.truncated and not r.bad_checkpoints and r.last_seq == 5


def test_unsigned_tail_is_rejected_unless_allowed() -> None:
    objs = make_export(n=6, cps=(3,))
    r = verify(objs)
    assert not r.ok and r.unsigned_tail == 3 and r.unsigned_tail_rejected
    r = verify(objs, allow_unsigned_tail=True)
    assert r.ok and r.unsigned_tail == 3 and not r.unsigned_tail_rejected
    # No checkpoint at all: every entry is the tail.
    r = verify(make_export(n=4, cps=()), allow_unsigned_tail=True)
    assert r.ok and r.unsigned_tail == 4 and r.last_signed_seq is None
    assert not verify(make_export(n=4, cps=())).ok


def test_the_declared_range_is_enforced() -> None:
    objs = make_export()
    objs[0]["to"] = 8  # claims more than the file holds
    r = verify(objs)
    assert not r.ok and r.truncated
    objs = make_export()
    objs[0]["from"] = 2  # file starts before the declared range
    r = verify(objs)
    assert not r.ok and r.truncated and r.outside_range == 1
    objs = make_export()
    objs[0]["to"] = 4
    r = verify(objs)
    assert not r.ok and r.outside_range == 2 and not r.truncated
    # An empty file for a non-empty range is truncated; an empty range is fine.
    assert verify([{**make_export()[0], "from": 1, "to": 3}]).truncated
    assert verify([{**make_export()[0], "from": 5, "to": 4}]).ok


def test_a_window_of_the_log_verifies_without_genesis() -> None:
    objs = make_export(n=4, start=10, cps=(12,))
    r = verify(objs, allow_unsigned_tail=True)
    assert r.ok and not r.from_genesis and r.first_seq == 10
    objs[2]["record"]["reason"] = "x"
    assert verify(objs, allow_unsigned_tail=True).first_bad_seq == 11


def test_seq_u64_max_is_a_bad_entry_not_an_overflow() -> None:
    top = 2**64 - 1
    h = entry_hash(top, "aa" * 32, record(0))
    objs: list[dict[str, Any]] = [
        {"type": "header", "format": EXPORT_FORMAT, "from": top, "to": top, "exported_at": "x"},
        {"type": "entry", "seq": top, "prev_hash": "aa" * 32, "record": record(0), "entry_hash": h},
    ]
    r = verify(objs, allow_unsigned_tail=True)
    assert not r.ok and r.first_bad_seq == top


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda o: o.pop(0), "no header"),
        (lambda o: o[0].update(format="attenuo-audit-export-v1"), "v1"),
        (lambda o: o[0].update(format="nope"), "unsupported"),
        (lambda o: o[0].update(filter={"kind": "admin"}), "filtered"),
        (lambda o: o[0].update(filter={"tool": "token.exchange"}), "filtered"),
        (lambda o: o[0].update(filter={"decision": "deny"}), "filtered"),
        (lambda o: o[0].update(filter={"tool": "token.exchange", "decision": "deny"}), "filtered"),
        (lambda o: o.insert(1, dict(o[0])), "second header"),
        (lambda o: o.append({"type": "mystery"}), "unknown line type"),
        (lambda o: o[0].update(**{"from": -1}), "non-negative"),
        (lambda o: o[1].update(seq="1"), "non-negative"),
    ],
)
def test_input_that_is_not_an_export_raises(mutate: Any, match: str) -> None:
    objs = make_export()
    mutate(objs)
    with pytest.raises(ExportError, match=match):
        verify(objs)


def test_garbage_lines_duplicates_and_constants_raise() -> None:
    good = lines(make_export())
    bads = ("not json\n", "[1]\n", '{"type":"entry","type":"entry"}\n', '{"from":NaN}\n')
    for bad in bads:
        with pytest.raises(ExportError):
            verify_export([good[0], bad, *good[1:]], checkpoint_public_keys=JWKS)
    with pytest.raises(ExportError, match="cannot read"):
        verify_export("/nonexistent/export.jsonl", checkpoint_public_keys=JWKS)


def test_blank_lines_and_crlf_are_tolerated() -> None:
    crlf = [ln.replace("\n", "\r\n") for ln in lines(make_export())]
    assert verify_export([*crlf[:2], "\r\n", *crlf[2:]], checkpoint_public_keys=JWKS).ok


# ---- cross-check against shipped checkpoints (SR-21) -------------------------------------------


def checkpoints_of(objs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{k: v for k, v in o.items() if k != "type"} for o in objs if o["type"] == "checkpoint"]


def envelope(cp: dict[str, Any]) -> dict[str, Any]:
    """What the file sink writes for ``cp``."""
    return {
        "checkpoint": cp,
        "checkpoint_sha256": hashlib.sha256(rfc8785.dumps(cp)).hexdigest(),
        "format": SHIPPED_FORMAT,
        "kid": cp["kid"],
        "public_url": None,
        "signature": cp["signature"],
    }


def shipped_lines(cps: list[dict[str, Any]]) -> list[str]:
    return [rfc8785.dumps(envelope(c)).decode() + "\n" for c in cps]


def cross(
    objs: list[dict[str, Any]], shipped: list[str] | None = None, **kw: Any
) -> CrossCheckReport:
    if shipped is None:
        shipped = shipped_lines(checkpoints_of(make_export(**kw)))
    return cross_check(lines(objs), shipped, checkpoint_public_keys=JWKS)


def rewritten(start_at: int) -> list[dict[str, Any]]:
    """The attacker's export: records from ``start_at`` changed, hashes recomputed, checkpoints
    signed again with the (stolen) key."""
    objs = make_export()
    entries = [o for o in objs if o["type"] == "entry"]
    prev = GENESIS_HASH
    for e in entries:
        if e["seq"] >= start_at:
            e["record"] = {**e["record"], "reason": "rewritten"}
        e["prev_hash"] = prev
        e["entry_hash"] = prev = entry_hash(e["seq"], prev, e["record"])
    by_seq = {e["seq"]: e["entry_hash"] for e in entries}
    for o in objs:
        if o["type"] == "checkpoint" and o["head_hash"] != by_seq[o["seq"]]:
            o.update(head_hash=by_seq[o["seq"]], at="2026-10-24T00:00:00Z")
            o["signature"] = sign_at(o)
    return objs


def sign_at(cp: dict[str, Any]) -> str:
    payload = rfc8785.dumps([cp["seq"], cp["head_hash"], cp["at"], cp["kid"]])
    ctx = b"attenuo-checkpoint-v1"
    return b64(KEY.sign(struct.pack(">I", len(ctx)) + ctx + payload))


def test_a_genuine_export_matches_its_shipped_checkpoints(tmp_path: Path) -> None:
    objs = make_export()
    r = cross(objs)
    assert r.ok and r.mismatches == ()
    assert (r.shipped, r.in_range, r.matched, r.beyond_range) == (2, 2, 2, 0)
    assert r.last_shipped_seq == 6
    # A retried delivery (the same line twice) is not a conflict.
    twice = shipped_lines(checkpoints_of(objs)) * 2
    assert cross(objs, twice).ok
    # Paths and bare checkpoint lines (an export's own `checkpoint` lines) work too.
    sink = tmp_path / "shipped.jsonl"
    sink.write_text("".join(shipped_lines(checkpoints_of(objs))))
    assert (
        cross_check(lines(objs), sink, checkpoint_public_keys=JWKS).ok
        and cross_check(lines(objs), str(sink), checkpoint_public_keys=JWKS).ok
    )
    bare = [json.dumps(o) + "\n" for o in objs if o["type"] == "checkpoint"] + ["\n"]
    assert cross(objs, bare).ok


def test_a_rewritten_and_re_signed_log_is_caught_by_the_shipped_copies() -> None:
    attacker = rewritten(2)
    assert verify(attacker).ok  # alone it verifies: the attacker had the key
    r = cross(attacker)
    assert not r.ok
    assert [m.seq for m in r.mismatches] == [3, 6]
    for m in r.mismatches:
        assert "RE-SIGNED after shipping" in m.reason
        assert "head_hash" in m.reason and "history rewritten" in m.reason
    assert r.mismatches[0].line == 1 and r.mismatches[1].line == 2
    # Only what changed after the first checkpoint: the early one still matches.
    r = cross(rewritten(5))
    assert [m.seq for m in r.mismatches] == [6]
    assert r.matched == 1


def test_deleted_duplicate_and_forged_shipped_checkpoints_are_reported() -> None:
    objs = make_export(cps=(2, 4, 6))
    shipped = shipped_lines(checkpoints_of(objs))
    # A checkpoint deleted from the export.
    gone = [o for o in objs if not (o["type"] == "checkpoint" and o["seq"] == 4)]
    r = cross(gone, shipped)
    assert [(m.seq, m.line) for m in r.mismatches] == [(4, 2)]
    assert "deleted after shipping" in r.mismatches[0].reason
    # Two different shipped copies for one seq: the second is reported at its line.
    other = shipped_lines([sign(4, "ab" * 32)])
    r = cross(objs, [*shipped, *other])
    assert [(m.seq, m.line) for m in r.mismatches] == [(4, 4)]
    assert "two different checkpoints for this seq (lines 2 and 4)" in r.mismatches[0].reason
    # A shipped copy that does not verify (a forged one, signed by another key).
    forged = sign(4, objs[4]["entry_hash"], key=Ed25519PrivateKey.generate())
    r = cross(objs, [shipped[0], *shipped_lines([forged]), shipped[2]])
    assert [m.seq for m in r.mismatches] == [4]
    assert "shipped checkpoint does not verify: signature does not verify" in r.mismatches[0].reason
    unknown = sign(4, objs[4]["entry_hash"], kid="other")
    r = cross(objs, shipped_lines([unknown]))
    assert "unknown signing key `other`" in r.mismatches[0].reason


def test_an_envelope_that_disagrees_with_its_checkpoint_is_reported() -> None:
    objs = make_export()
    cps = checkpoints_of(objs)
    env = envelope(cps[0])
    env["checkpoint_sha256"] = "00" * 32
    r = cross(objs, [json.dumps(env) + "\n"])
    assert r.mismatches[0].seq == 3
    assert "checkpoint_sha256" in r.mismatches[0].reason
    env = envelope(cps[0])
    env["kid"] = "other"
    assert (
        "differs from the checkpoint's own" in cross(objs, [json.dumps(env)]).mismatches[0].reason
    )
    env = {**envelope(cps[0]), "format": "v0"}
    assert "unsupported format `v0`" in cross(objs, [json.dumps(env)]).mismatches[0].reason


ANCHOR_LINE = (
    '{"anchor":{"archive_sha256":null,"at":"2026-10-24T00:00:00Z","kid":"k",'
    '"previous_through_seq":null,"prune_entry_hash":"' + "ab" * 32 + '","prune_seq":7,'
    '"signature":"s","through_hash":"' + "cd" * 32 + '","through_seq":3},'
    '"anchor_sha256":"' + "ef" * 32 + '","format":"attenuo-shipped-anchor-v1","kid":"k",'
    '"public_url":null,"signature":"s"}\n'
)


def test_a_prune_anchor_line_in_the_shipped_file_is_skipped() -> None:
    objs = make_export()
    shipped = shipped_lines(checkpoints_of(objs))
    with_anchor = [shipped[0], ANCHOR_LINE, shipped[1]]
    parsed = parse_shipped(with_anchor)
    # The anchor is not a checkpoint; the lines after it keep their own numbers.
    assert [p.line for p in parsed] == [1, 3]
    r = cross(objs, with_anchor)
    assert r.ok and r.shipped == 2 and r.matched == 2


def test_shipped_checkpoints_past_the_export_are_counted_not_checked() -> None:
    objs = make_export()
    log = make_export(n=9, cps=(3, 6, 9))
    r = cross(objs, shipped_lines(checkpoints_of(log)))
    assert r.ok
    assert (r.in_range, r.matched, r.beyond_range, r.last_shipped_seq) == (2, 2, 1, 9)
    # Checkpoints before a windowed export's range are not checked either (seq 3 here; the
    # window's own hashes differ from the full log's, so seq 6 is reported).
    window = make_export(n=3, start=4, cps=(6,))
    r = cross(window, shipped_lines(checkpoints_of(make_export())))
    assert (r.in_range, [m.seq for m in r.mismatches]) == (1, [6])


def test_the_genesis_checkpoint_matches_and_an_empty_shipped_file_is_ok() -> None:
    objs = make_export(cps=(0, 3, 6))
    objs.append({"type": "checkpoint", **sign(0, GENESIS_HASH)})
    assert cross(objs, shipped_lines([sign(0, GENESIS_HASH)])).matched == 1
    r = cross(objs, [])
    assert r.ok and r.shipped == 0 and r.last_shipped_seq is None


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("not json\n", "shipped checkpoints, line 1"),
        ("[1]\n", "not a JSON object"),
        ('{"type":"entry","seq":1}\n', "not a checkpoint line"),
        ('{"seq":1}\n', "head_hash"),
        (
            '{"checkpoint":1,"format":"x","kid":"k","signature":"s","checkpoint_sha256":"h"}\n',
            "object",
        ),
    ],
)
def test_a_shipped_file_that_is_not_checkpoints_raises(text: str, match: str) -> None:
    with pytest.raises(ExportError, match=match):
        parse_shipped([text])
    with pytest.raises(ExportError, match=match):
        cross(make_export(), [text])


def test_cross_check_refuses_what_verify_export_refuses() -> None:
    objs = make_export()
    with pytest.raises(ExportError, match="no header"):
        cross(objs[1:], [])
    with pytest.raises(ExportError, match="32 bytes"):
        cross_check(lines(objs), [], checkpoint_public_keys={KID: "AAAA"})


# ---- a pruned log: the header anchor and several files ------------------------------------

ANCHOR_CONTEXT = b"attenuo-audit-anchor-v1"


def _opt(v: int | None) -> bytes:
    return b"null" if v is None else b"%d" % v


def sign_anchor(a: dict[str, Any], key: Ed25519PrivateKey = KEY) -> str:
    payload = b"[%d,%s,%d,%s,%s,%s,%s,%s]" % (
        a["through_seq"],
        rfc8785.dumps(a["through_hash"]),
        a["prune_seq"],
        rfc8785.dumps(a["prune_entry_hash"]),
        _opt(a["previous_through_seq"]),
        rfc8785.dumps(a["archive_sha256"]),
        rfc8785.dumps(a["at"]),
        rfc8785.dumps(a["kid"]),
    )
    ctx = ANCHOR_CONTEXT
    return b64(key.sign(struct.pack(">I", len(ctx)) + ctx + payload))


def prune_record(through_seq: int, through_hash: str, digest: str | None) -> dict[str, Any]:
    args: dict[str, Any] = {
        "through_seq": through_seq,
        "through_hash": through_hash,
        "previous_through_seq": None,
        "archive_sha256": digest,
    }
    return {
        **GOLDEN_RECORD,
        "kind": "admin",
        "server": "attenuo",
        "tool": PRUNE_TOOL,
        "decision": "allow",
        "reason": "admin_action",
        "arguments_digest": hashlib.sha256(rfc8785.dumps(args)).hexdigest(),
    }


def pruned_log(
    digest: str | None = "ab" * 32,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """A log of 13 entries pruned through 10 by the record at 11: the archive (1..=10, ending
    at a checkpoint), the retained export (11..=13, its header carrying the anchor), and the
    anchor."""
    entries: list[dict[str, Any]] = []
    prev = GENESIS_HASH
    for seq in range(1, 14):
        rec = record(seq) if seq != 11 else prune_record(10, entries[9]["entry_hash"], digest)
        h = entry_hash(seq, prev, rec)
        entries.append(
            {"type": "entry", "seq": seq, "prev_hash": prev, "record": rec, "entry_hash": h}
        )
        prev = h
    by_seq = {e["seq"]: e["entry_hash"] for e in entries}
    anchor: dict[str, Any] = {
        "through_seq": 10,
        "through_hash": by_seq[10],
        "prune_seq": 11,
        "prune_entry_hash": by_seq[11],
        "previous_through_seq": None,
        "archive_sha256": digest,
        "at": "2026-10-24T00:00:00Z",
        "kid": KID,
    }
    anchor["signature"] = sign_anchor(anchor)

    def header(lo: int, hi: int, **extra: Any) -> dict[str, Any]:
        return {
            "type": "header",
            "format": EXPORT_FORMAT,
            "from": lo,
            "to": hi,
            "exported_at": "2026-10-24T00:00:00Z",
            **extra,
        }

    def cps(*seqs: int) -> list[dict[str, Any]]:
        return [{"type": "checkpoint", **sign(s, by_seq[s])} for s in seqs]

    archive = [header(1, 10), *entries[:10], *cps(5, 10)]
    retained = [header(11, 13, anchor=anchor), *entries[10:], *cps(11, 13)]
    return archive, retained, anchor


def with_anchor(objs: list[dict[str, Any]], **changes: Any) -> list[dict[str, Any]]:
    """`objs` with the header's anchor changed (and signed again unless `signature` is given)."""
    out: list[dict[str, Any]] = json.loads(json.dumps(objs))
    a = out[0]["anchor"]
    a.update({k: v for k, v in changes.items() if k != "signature"})
    a["signature"] = changes.get("signature", sign_anchor(a))
    return out


def test_an_export_after_a_prune_starts_from_its_signed_anchor() -> None:
    archive, retained, _ = pruned_log()
    r = verify(retained)
    assert r.ok, r
    assert (r.from_anchor, r.from_genesis, r.pruned_through, r.anchors) == (True, False, 10, 1)
    assert r.bad_anchors == ()
    # Without an archive digest too.
    assert verify(pruned_log(None)[1]).ok
    # The archive is an ordinary export from genesis.
    a = verify(archive)
    assert a.ok and a.from_genesis and not a.from_anchor and a.anchors == 0


def test_without_its_anchor_the_retained_export_is_a_window() -> None:
    _, retained, _ = pruned_log()
    bare = json.loads(json.dumps(retained))
    del bare[0]["anchor"]
    r = verify(bare)
    assert r.ok and not r.from_anchor and r.pruned_through is None and r.anchors == 0


def test_a_header_anchor_that_does_not_verify_or_fit_is_reported() -> None:
    _, retained, _ = pruned_log()
    other = Ed25519PrivateKey.generate()
    forged = with_anchor(retained)
    forged[0]["anchor"]["signature"] = sign_anchor(forged[0]["anchor"], other)
    cases = [
        (forged, "signature does not verify"),
        (with_anchor(retained, kid="k9"), "unknown signing key `k9`"),
        (with_anchor(retained, through_seq=9), "the header's anchor is through seq 9"),
        (
            with_anchor(retained, prune_entry_hash="00" * 32),
            "does not hash to prune_entry_hash",
        ),
        (
            with_anchor(retained, archive_sha256="cd" * 32),
            "arguments digest does not match",
        ),
    ]
    for objs, reason in cases:
        r = verify(objs)
        assert not r.ok and not r.from_anchor, (reason, r)
        assert len(r.bad_anchors) == 1 and reason in r.bad_anchors[0].reason, (reason, r)


def test_an_anchor_for_another_hash_is_bad_and_the_file_is_a_window() -> None:
    _, retained, _ = pruned_log()
    # Signed again, so the signature verifies; the prune record in the file names the real
    # hash, so the anchor fails there and the walk falls back to a window, as in Rust.
    r = verify(with_anchor(retained, through_hash="00" * 32))
    assert not r.ok and not r.from_anchor and r.pruned_through is None
    assert r.first_bad_seq is None
    assert "arguments digest does not match" in r.bad_anchors[0].reason


def test_a_malformed_header_anchor_raises() -> None:
    _, retained, _ = pruned_log()
    bad = json.loads(json.dumps(retained))
    bad[0]["anchor"]["through_seq"] = "10"
    with pytest.raises(ExportError, match="through_seq"):
        verify(bad)
    bad[0]["anchor"] = "anchor"
    with pytest.raises(ExportError, match="anchor"):
        verify(bad)


def test_archives_and_the_retained_export_verify_as_one_log(tmp_path: Path) -> None:
    archive, retained, _ = pruned_log()
    a, b = tmp_path / "archive.jsonl", tmp_path / "retained.jsonl"
    a.write_text("".join(lines(archive)))
    b.write_text("".join(lines(retained)))
    r = verify_exports([a, b], checkpoint_public_keys=JWKS)
    assert isinstance(r, ExportsReport)
    assert r.ok and r.links == () and r.files[1].from_anchor, r

    # Out of order.
    r = verify_exports([b, a], checkpoint_public_keys=JWKS)
    assert not r.ok
    assert r.links[0] == LinkProblem(
        0,
        1,
        "the seqs are not contiguous: the earlier file ends at seq 13, "
        "the later one starts at seq 1",
    )
    # An archive that does not end at a checkpoint.
    short = [o for o in archive if not (o["type"] == "checkpoint" and o["seq"] == 10)]
    r = verify_exports([lines(short), lines(retained)], checkpoint_public_keys=JWKS)
    assert any("does not end at a checkpoint" in p.reason for p in r.links), r
    # One changed byte in either file is reported at its seq in that file.
    for which, seq in ((0, 4), (1, 12)):
        files = [json.loads(json.dumps(archive)), json.loads(json.dumps(retained))]
        e = next(o for o in files[which] if o.get("seq") == seq and o["type"] == "entry")
        e["record"]["reason"] = e["record"]["reason"] + "x"
        r = verify_exports([lines(f) for f in files], checkpoint_public_keys=JWKS)
        assert not r.ok and r.files[which].first_bad_seq == seq, r
    # The unsigned tail is accepted only in the last file.
    open_tail = [*retained[:-1]]
    r = verify_exports(
        [lines(archive), lines(open_tail)], checkpoint_public_keys=JWKS, allow_unsigned_tail=True
    )
    assert r.ok, r
    r = verify_exports(
        [lines(open_tail), lines(archive)], checkpoint_public_keys=JWKS, allow_unsigned_tail=True
    )
    assert not r.files[0].ok and r.files[0].unsigned_tail_rejected


def test_a_header_anchor_that_does_not_name_the_earlier_file_end_is_a_link_problem() -> None:
    archive, retained, _ = pruned_log()
    # A window export starting at 11 with an anchor for another boundary would fail on its
    # own; here the archive is cut at 9 so its end is not the anchor's boundary.
    cut = [o for o in archive if not (o["type"] in ("entry", "checkpoint") and o["seq"] == 10)]
    cut[0] = {**cut[0], "to": 9}
    r = verify_exports([lines(cut), lines(retained)], checkpoint_public_keys=JWKS)
    reasons = [p.reason for p in r.links]
    assert any(
        "header anchor is through seq 10, not the earlier file's end at seq 9" in x for x in reasons
    ), reasons
