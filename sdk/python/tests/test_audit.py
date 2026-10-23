"""Offline export verification (`onbehalf.audit.verify_export`)."""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from onbehalf.audit import (
    EXPORT_FORMAT,
    GENESIS_HASH,
    ExportError,
    entry_hash,
    verify_export,
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
GOLDEN_HASH = "9026ac429517fb97a10afa12781cb97297a18ab36085315d82c41ba7b9ba861e"


def record(i: int, kind: str = "decision") -> dict[str, Any]:
    return {**GOLDEN_RECORD, "kind": kind, "reason": f"r{i}", "tool": f"t{i}"}


def sign(seq: int, head_hash: str, kid: str = KID, key: Ed25519PrivateKey = KEY) -> dict[str, Any]:
    at = "2026-10-23T12:00:00Z"
    payload = rfc8785.dumps([seq, head_hash, at, kid])
    ctx = b"onbehalf-checkpoint-v1"
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
        (lambda o: o[0].update(format="onbehalf-audit-export-v1"), "v1"),
        (lambda o: o[0].update(format="nope"), "unsupported"),
        (lambda o: o[0].update(filter={"kind": "admin"}), "filtered"),
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
