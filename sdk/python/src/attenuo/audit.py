"""Offline verification of an audit export.

``verify_export`` re-checks a file written by ``attenuo audit export`` (or
``AdminClient.audit_export``) with nothing but the issuer's public keys: the SHA-256 hash chain
over RFC 8785 canonical JSON, the range the header declares, and the Ed25519 checkpoint
signatures. It follows the Rust ``verify_export_with`` (``attenuo audit verify --file``) rule
for rule, so the same file gives the same verdict, and the same ``first_bad_seq``, in both::

    from attenuo.audit import verify_export

    report = verify_export("audit.jsonl", checkpoint_public_keys=jwks)  # GET /.well-known/jwks.json
    assert report.ok, report

A file that fails verification gives a report with ``ok == False``; a file that cannot be read
as an export at all (no header, the wrong format, a filtered export, a line that is not JSON)
raises :class:`ExportError`. The Ed25519 check needs the ``cryptography`` package
(``pip install 'attenuo[verify]'``).

Differences from the Rust check, all on the strict side: the record is hashed as it appears in
the file (Rust decodes it into its record type first, which drops members it does not know),
and duplicate object keys, ``NaN`` and ``Infinity`` are refused.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import struct
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import rfc8785

from .errors import AttenuoError

__all__ = [
    "ENTRY_HASH_VERSION",
    "EXPORT_FORMAT",
    "GENESIS_HASH",
    "BadCheckpoint",
    "ExportError",
    "ExportReport",
    "entry_hash",
    "verify_export",
]

#: First element of the array the entry hash covers.
ENTRY_HASH_VERSION = "attenuo-audit-entry-v2"
#: ``prev_hash`` of the first entry of a log.
GENESIS_HASH = "0" * 64
#: Value of the header's ``format`` member.
EXPORT_FORMAT = "attenuo-audit-export-v2"
_CHECKPOINT_CONTEXT = "attenuo-checkpoint-v1"
_U64_MAX = 2**64 - 1
_B64URL = re.compile(r"[A-Za-z0-9_-]*")


class ExportError(AttenuoError):
    """The input is not an audit export this version can verify."""


@dataclass(frozen=True)
class BadCheckpoint:
    seq: int
    reason: str


@dataclass(frozen=True)
class ExportReport:
    """The verdict on an export (the fields of the Rust ``ExportReport``)."""

    #: Every check passed (and, unless ``allow_unsigned_tail``, every entry is countersigned).
    ok: bool
    #: Entries examined, including the first bad one.
    entries: int
    #: Seq of the first entry that fails the chain walk (``None`` if the chain is intact).
    first_bad_seq: int | None
    #: Checkpoints in the file.
    checkpoints: int
    #: Highest seq with a valid checkpoint.
    last_signed_seq: int | None
    #: Entries after ``last_signed_seq``, covered by the hash chain only.
    unsigned_tail: int
    bad_checkpoints: tuple[BadCheckpoint, ...] = field(default_factory=tuple)
    #: Seq of the first and last entry in the file.
    first_seq: int | None = None
    last_seq: int | None = None
    #: The file starts at seq 1 with the genesis ``prev_hash``.
    from_genesis: bool = False
    #: Entries of the header's range are missing from the start or end of the file.
    truncated: bool = False
    #: Entries whose seq is outside the header's ``from..=to``.
    outside_range: int = 0
    #: Failed only because of an unsigned tail that ``allow_unsigned_tail`` did not accept.
    unsigned_tail_rejected: bool = False


def entry_hash(seq: int, prev_hash: str, record: Mapping[str, Any]) -> str:
    """SHA-256 (hex) of the RFC 8785 canonical JSON of
    ``["attenuo-audit-entry-v2", seq, prev_hash, record]``."""
    # `seq` is written by hand: `rfc8785` refuses integers beyond 2**53, the Rust side keeps
    # their digits (a u64 seq).
    data = b"[%s,%d,%s,%s]" % (
        rfc8785.dumps(ENTRY_HASH_VERSION),
        seq,
        rfc8785.dumps(prev_hash),
        rfc8785.dumps(dict(record)),
    )
    return hashlib.sha256(data).hexdigest()


def verify_export(
    path_or_lines: str | os.PathLike[str] | Iterable[str | bytes],
    *,
    checkpoint_public_keys: Mapping[str, Any],
    allow_unsigned_tail: bool = False,
) -> ExportReport:
    """Verify an audit export offline.

    ``path_or_lines`` is a file path (``str`` or ``PathLike``) or an iterable of lines (an open
    file, a list; ``str`` or ``bytes``). The file is JSON Lines, or the single-object JSON form
    of ``attenuo audit export --format json``. A ``str`` is always a path: pass
    ``text.splitlines()`` for text in memory.

    ``checkpoint_public_keys`` is the issuer's JWKS (``{"keys": [...]}``, as served at
    ``/.well-known/jwks.json``) or a mapping of ``kid`` to the raw 32-byte Ed25519 public key
    (``bytes``) or its base64url ``x``.

    Strict like ``attenuo audit verify --file``: the header is required, entries outside its
    ``from..=to`` fail, a file short of that range fails, and so do entries after the last valid
    checkpoint unless ``allow_unsigned_tail`` is set (an export taken while the log was ahead of
    its newest checkpoint).
    """
    keys = _load_keys(checkpoint_public_keys)
    export = _parse(_read_text(path_or_lines))
    header, entries, cps = export

    first_seq = entries[0]["seq"] if entries else None
    last_seq = entries[-1]["seq"] if entries else None
    from_genesis = first_seq == 1 and entries[0]["prev_hash"] == GENESIS_HASH
    anchored = first_seq == 1
    lo, hi = first_seq or 0, last_seq or 0
    inside = [c for c in cps if lo <= c["seq"] <= hi]

    # Hash chain.
    ok_hashes: dict[int, str] = {}
    wanted = {c["seq"] for c in inside}
    count = 0
    ok_count = 0
    last_ok: int | None = None
    first_bad: int | None = None
    expected_seq, expected_prev = 1, GENESIS_HASH
    for i, e in enumerate(entries):
        count += 1
        if i == 0 and not anchored:
            expected_seq, expected_prev = e["seq"], e["prev_hash"]
        good = (
            e["seq"] < _U64_MAX
            and e["seq"] == expected_seq
            and e["prev_hash"] == expected_prev
            and _hash_matches(e)
        )
        if not good:
            first_bad = e["seq"]
            break
        last_ok = e["seq"]
        ok_count += 1
        if e["seq"] in wanted:
            ok_hashes[e["seq"]] = e["entry_hash"]
        expected_seq, expected_prev = e["seq"] + 1, e["entry_hash"]
    chain_ok = first_bad is None

    # Checkpoints inside the entry window must match an entry hash.
    bad: list[BadCheckpoint] = []
    last_signed: int | None = None
    for cp in sorted(inside, key=lambda c: c["seq"]):
        reason = _verify_checkpoint(cp, keys)
        if reason is not None:
            bad.append(BadCheckpoint(cp["seq"], reason))
            continue
        if cp["seq"] == 0:
            actual = GENESIS_HASH if anchored else None
        else:
            actual = ok_hashes.get(cp["seq"])
        if actual is not None and actual == cp["head_hash"]:
            last_signed = cp["seq"] if last_signed is None else max(last_signed, cp["seq"])
        elif actual is not None:
            bad.append(BadCheckpoint(cp["seq"], "head hash differs from the log at that seq"))
        elif chain_ok and (last_ok is None or cp["seq"] > last_ok):
            bad.append(BadCheckpoint(cp["seq"], "log ends before this checkpoint (truncated)"))
    # Outside the window the signature is still checked.
    for cp in cps:
        if not lo <= cp["seq"] <= hi:
            reason = _verify_checkpoint(cp, keys)
            if reason is not None:
                bad.append(BadCheckpoint(cp["seq"], reason))

    if last_ok is not None and last_signed is not None:
        unsigned_tail = max(last_ok - last_signed, 0)
    elif last_ok is not None:
        unsigned_tail = ok_count
    else:
        unsigned_tail = 0

    if first_seq is not None and last_seq is not None:
        truncated = first_seq != header["from"] or last_seq < header["to"]
    else:
        truncated = header["to"] >= header["from"] and header["to"] > 0
    outside = sum(1 for e in entries if e["seq"] < header["from"] or e["seq"] > header["to"])
    tail_rejected = unsigned_tail > 0 and not allow_unsigned_tail
    ok = chain_ok and not bad and not truncated and outside == 0 and not tail_rejected
    return ExportReport(
        ok=ok,
        entries=count,
        first_bad_seq=first_bad,
        checkpoints=len(cps),
        last_signed_seq=last_signed,
        unsigned_tail=unsigned_tail,
        bad_checkpoints=tuple(bad),
        first_seq=first_seq,
        last_seq=last_seq,
        from_genesis=from_genesis,
        truncated=truncated,
        outside_range=outside,
        unsigned_tail_rejected=tail_rejected,
    )


# ---- parsing ------------------------------------------------------------------------------


def _hash_matches(e: dict[str, Any]) -> bool:
    try:
        return bool(entry_hash(e["seq"], e["prev_hash"], e["record"]) == e["entry_hash"])
    except (ValueError, TypeError, OverflowError, rfc8785.CanonicalizationError):
        return False


def _read_text(src: str | os.PathLike[str] | Iterable[str | bytes]) -> str:
    if isinstance(src, (str, os.PathLike)):
        try:
            with open(src, encoding="utf-8", newline="") as f:
                return f.read()
        except (OSError, UnicodeDecodeError) as e:
            raise ExportError(f"cannot read {os.fspath(src)}: {e}") from e
    out: list[str] = []
    for line in src:
        if isinstance(line, bytes):
            try:
                line = line.decode("utf-8")
            except UnicodeDecodeError as e:
                raise ExportError(f"line is not UTF-8: {e}") from e
        out.append(line if line.endswith("\n") else line + "\n")
    return "".join(out)


def _no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate member `{k}`")
        out[k] = v
    return out


def _no_const(name: str) -> Any:
    raise ValueError(f"`{name}` is not JSON")


def _loads(text: str) -> Any:
    return json.loads(text, object_pairs_hook=_no_dupes, parse_constant=_no_const)


def _is_uint(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= _U64_MAX


def _need(obj: dict[str, Any], where: str, **types: str) -> None:
    for name, kind in types.items():
        v = obj.get(name)
        good = _is_uint(v) if kind == "uint" else isinstance(v, str)
        if not good:
            want = "a non-negative integer" if kind == "uint" else "a string"
            raise ExportError(f"{where}: `{name}` must be {want}")


def _parse(text: str) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    header: dict[str, Any] | None = None
    entries: list[dict[str, Any]] = []
    cps: list[dict[str, Any]] = []
    whole: Any = None
    if text.lstrip().startswith("{"):
        try:
            whole = _loads(text)
        except ValueError:
            whole = None
    if isinstance(whole, dict) and "type" not in whole:
        header = whole.get("header")
        raw_entries = whole.get("entries", [])
        raw_cps = whole.get("checkpoints", [])
        if not isinstance(raw_entries, list) or not isinstance(raw_cps, list):
            raise ExportError("`entries` and `checkpoints` must be arrays")
        entries = [_entry(e, f"entries[{i}]") for i, e in enumerate(raw_entries)]
        cps = [_checkpoint(c, f"checkpoints[{i}]") for i, c in enumerate(raw_cps)]
    else:
        for n, line in enumerate(text.split("\n"), start=1):
            line = line.removesuffix("\r")
            if not line.strip():
                continue
            where = f"line {n}"
            try:
                obj = _loads(line)
            except ValueError as e:
                raise ExportError(f"{where}: {e}") from e
            if not isinstance(obj, dict):
                raise ExportError(f"{where}: not a JSON object")
            kind = obj.get("type")
            if kind == "header":
                if header is not None:
                    raise ExportError(f"{where}: second header")
                header = obj
            elif kind == "entry":
                entries.append(_entry(obj, where))
            elif kind == "checkpoint":
                cps.append(_checkpoint(obj, where))
            else:
                raise ExportError(f"{where}: unknown line type {kind!r}")
    if header is None:
        raise ExportError(
            "the export has no header line; the header declares the range of entries the file holds"
        )
    return _check_header(header), entries, cps


def _check_header(h: Any) -> dict[str, Any]:
    if not isinstance(h, dict):
        raise ExportError("the header must be an object")
    _need(h, "header", format="str", exported_at="str", **{"from": "uint", "to": "uint"})
    if h["format"] == "attenuo-audit-export-v1":
        raise ExportError(
            "export format `attenuo-audit-export-v1` was written by an earlier attenuo whose "
            "entry hashes were not RFC 8785 canonical; this version verifies only "
            f"`{EXPORT_FORMAT}` (export the log again with this version)"
        )
    if h["format"] != EXPORT_FORMAT:
        raise ExportError(f"unsupported export format `{h['format']}` (expected `{EXPORT_FORMAT}`)")
    if h.get("filter") is not None:
        raise ExportError(
            "the export is filtered (its header has a `filter`), so its hash chain has gaps and "
            "nothing proves it is complete; verify an export taken without kind and chain_id "
            "filters, then filter that"
        )
    return h


def _entry(e: Any, where: str) -> dict[str, Any]:
    if not isinstance(e, dict):
        raise ExportError(f"{where}: not a JSON object")
    _need(e, where, seq="uint", prev_hash="str", entry_hash="str")
    if not isinstance(e.get("record"), dict):
        raise ExportError(f"{where}: `record` must be an object")
    return e


def _checkpoint(c: Any, where: str) -> dict[str, Any]:
    if not isinstance(c, dict):
        raise ExportError(f"{where}: not a JSON object")
    _need(c, where, seq="uint", head_hash="str", at="str", kid="str", signature="str")
    return c


# ---- checkpoints --------------------------------------------------------------------------


def _b64url_decode(text: str) -> bytes | None:
    """Strict unpadded base64url: no padding, no stray characters, no non-zero trailing bits."""
    if not _B64URL.fullmatch(text) or len(text) % 4 == 1:
        return None
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return None
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != text:
        return None
    return raw


def _load_keys(src: Mapping[str, Any]) -> dict[str, bytes]:
    keys: dict[str, bytes] = {}
    if "keys" in src and isinstance(src["keys"], list):
        for k in src["keys"]:
            if not isinstance(k, dict) or k.get("kty") != "OKP" or k.get("crv") != "Ed25519":
                continue
            kid, x = k.get("kid"), k.get("x")
            if isinstance(kid, str) and isinstance(x, str):
                keys[kid] = _raw_key(kid, x)
        return keys
    for kid, v in src.items():
        keys[str(kid)] = _raw_key(str(kid), v)
    return keys


def _raw_key(kid: str, v: Any) -> bytes:
    raw = _b64url_decode(v) if isinstance(v, str) else bytes(v) if isinstance(v, bytes) else None
    if raw is None or len(raw) != 32:
        raise ExportError(f"key `{kid}`: an Ed25519 public key is 32 bytes (raw, or base64url)")
    return raw


def _verify_checkpoint(cp: dict[str, Any], keys: dict[str, bytes]) -> str | None:
    """``None`` when the signature verifies, else why not."""
    key = keys.get(cp["kid"])
    if key is None:
        return f"unknown signing key `{cp['kid']}`"
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as e:  # pragma: no cover - depends on the environment
        raise ExportError(
            "checking checkpoint signatures needs the `cryptography` package "
            "(pip install 'attenuo[verify]')"
        ) from e
    sig = _b64url_decode(cp["signature"])
    ctx = _CHECKPOINT_CONTEXT.encode()
    payload = b"[%d,%s,%s,%s]" % (
        cp["seq"],
        rfc8785.dumps(cp["head_hash"]),
        rfc8785.dumps(cp["at"]),
        rfc8785.dumps(cp["kid"]),
    )
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(
            sig or b"", struct.pack(">I", len(ctx)) + ctx + payload
        )
    except (InvalidSignature, ValueError):
        return "signature does not verify"
    return None
