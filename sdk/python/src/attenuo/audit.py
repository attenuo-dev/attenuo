"""Offline verification of an audit export.

``verify_export`` re-checks a file written by ``attenuo audit export`` (or
``AdminClient.audit_export``) with nothing but the issuer's public keys: the SHA-256 hash chain
over RFC 8785 canonical JSON, the range the header declares, and the Ed25519 checkpoint
signatures. It follows the Rust ``verify_export_with`` (``attenuo audit verify --file``) rule
for rule, so the same file gives the same verdict, and the same ``first_bad_seq``, in both::

    from attenuo.audit import verify_export

    report = verify_export("audit.jsonl", checkpoint_public_keys=jwks)  # GET /.well-known/jwks.json
    assert report.ok, report

``cross_check`` adds the SR-21 comparison with checkpoints the server shipped off the host
(``[audit.sink]``), the Rust ``cross_check`` (``attenuo audit verify --file --checkpoints``) rule
for rule: a checkpoint signed again after it was shipped, one deleted from the export, two
different shipped copies for one seq, and a shipped copy that does not verify are reported with
the same ``seq`` and reason in both::

    from attenuo.audit import cross_check

    cross = cross_check("audit.jsonl", "shipped.jsonl", checkpoint_public_keys=jwks)
    assert cross.ok, (cross.mismatches, cross.anchors.mismatches)

The same file holds the signed anchors of the prunes (``attenuo-shipped-anchor-v1``), and
``cross_check`` checks them as ``cross_check_anchors`` does in Rust: each must verify, the anchor
of the boundary right before the export's start must be the one in its header, and an anchor that
says entries the export still holds were pruned means the log was rewound. The result is in
``cross.anchors``; ``cross.ok`` covers both checks.

An export taken after a prune starts at the first retained entry, and its header carries the
prune's signed ``anchor``. ``verify_export`` checks the anchor's signature, that the file starts
right after it, and the prune record when it is in the file, then reports ``from_anchor`` and
``pruned_through``, as the Rust check does. ``verify_exports`` verifies several files, oldest
first (the archives of the prunes, then the retained export), and checks that they link into
one log, as ``attenuo audit verify --file a --file b`` does::

    from attenuo.audit import verify_exports

    report = verify_exports(["archive-1.jsonl", "retained.jsonl"], checkpoint_public_keys=jwks)
    assert report.ok, (report.files, report.links)

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
    "PRUNE_TOOL",
    "SHIPPED_ANCHOR_FORMAT",
    "SHIPPED_FORMAT",
    "AnchorCheckReport",
    "BadAnchor",
    "BadCheckpoint",
    "CrossCheckReport",
    "ExportError",
    "ExportReport",
    "ExportsReport",
    "LinkProblem",
    "ShippedAnchor",
    "ShippedLine",
    "ShippedMismatch",
    "cross_check",
    "entry_hash",
    "parse_shipped",
    "parse_shipped_anchors",
    "verify_export",
    "verify_exports",
]

#: First element of the array the entry hash covers.
ENTRY_HASH_VERSION = "attenuo-audit-entry-v2"
#: ``prev_hash`` of the first entry of a log.
GENESIS_HASH = "0" * 64
#: Value of the header's ``format`` member.
EXPORT_FORMAT = "attenuo-audit-export-v2"
#: Value of a shipped checkpoint's ``format`` member.
SHIPPED_FORMAT = "attenuo-shipped-checkpoint-v1"
#: The tool of a prune's own audit record.
PRUNE_TOOL = "admin.audit.prune"
#: Value of a shipped anchor's ``format`` member: the envelope of a prune's signed anchor, which
#: the sink ships with the checkpoints (ADR-0015). :func:`parse_shipped` skips these lines and
#: :func:`parse_shipped_anchors` reads them.
SHIPPED_ANCHOR_FORMAT = "attenuo-shipped-anchor-v1"
_CHECKPOINT_CONTEXT = "attenuo-checkpoint-v1"
_ANCHOR_CONTEXT = "attenuo-audit-anchor-v1"
_CP_FIELDS = ("seq", "head_hash", "at", "kid", "signature")
_ANCHOR_FIELDS = (
    "through_seq",
    "through_hash",
    "prune_seq",
    "prune_entry_hash",
    "previous_through_seq",
    "archive_sha256",
    "at",
    "kid",
    "signature",
)
_U64_MAX = 2**64 - 1
_B64URL = re.compile(r"[A-Za-z0-9_-]*")


class ExportError(AttenuoError):
    """The input is not an audit export this version can verify."""


@dataclass(frozen=True)
class BadCheckpoint:
    seq: int
    reason: str


@dataclass(frozen=True)
class BadAnchor:
    """A prune anchor that failed verification."""

    #: The ``through_seq`` the anchor claims.
    through_seq: int
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
    #: The header carries a prune anchor whose signature verifies, and the file starts right
    #: after it (its first entry is ``through_seq + 1`` with ``prev_hash`` equal to
    #: ``through_hash``): the entries before were pruned through the server.
    from_anchor: bool = False
    #: The anchor's ``through_seq`` when the walk started from a valid header anchor.
    pruned_through: int | None = None
    #: Anchors in the header (0 or 1).
    anchors: int = 0
    #: The header's anchor, when it does not verify or does not fit the file.
    bad_anchors: tuple[BadAnchor, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class LinkProblem:
    """Why two files given in a row to :func:`verify_exports` do not form one log."""

    #: Index of the earlier file, from 0, in the order given.
    earlier: int
    #: Index of the later file (``earlier + 1``).
    later: int
    reason: str


@dataclass(frozen=True)
class ExportsReport:
    """The verdict of :func:`verify_exports`."""

    #: Every file verifies and every pair of neighbours links.
    ok: bool
    #: Each file's own report, in the order given.
    files: tuple[ExportReport, ...]
    #: Each pair of neighbouring files that does not link.
    links: tuple[LinkProblem, ...]
    #: The first file starts at seq 1 with the genesis ``prev_hash``.
    from_genesis: bool = False
    #: The first file starts right after the valid prune anchor in its header: the archives of
    #: the earlier prunes are not among the files.
    from_anchor: bool = False
    #: The first file's anchor ``through_seq`` when ``from_anchor`` is set.
    pruned_through: int | None = None


@dataclass(frozen=True)
class ShippedLine:
    """One parsed line of a shipped-checkpoint file."""

    #: 1-based line number in the file.
    line: int
    #: The five checkpoint members: ``seq``, ``head_hash``, ``at``, ``kid``, ``signature``.
    checkpoint: Mapping[str, Any]
    #: Set when the line was an envelope that does not match its own checkpoint.
    inconsistency: str | None = None


@dataclass(frozen=True)
class ShippedMismatch:
    """A shipped checkpoint the export disagrees with, or one that is unusable."""

    seq: int
    #: Line of the shipped file.
    line: int
    reason: str


@dataclass(frozen=True)
class ShippedAnchor:
    """One shipped prune anchor (``attenuo-shipped-anchor-v1``) of a shipped file."""

    #: 1-based line number in the file.
    line: int
    #: The nine members of the signed anchor: ``through_seq``, ``through_hash``, ``prune_seq``,
    #: ``prune_entry_hash``, ``previous_through_seq``, ``archive_sha256``, ``at``, ``kid``,
    #: ``signature`` (a missing optional member is ``None``).
    anchor: Mapping[str, Any]
    #: The envelope's ``format``, ``kid``, ``signature`` and ``anchor_sha256``, as shipped.
    format: str
    kid: str
    signature: str
    anchor_sha256: str
    #: ``[server] public_url`` of the server that signed it, when set.
    public_url: str | None = None


@dataclass(frozen=True)
class AnchorCheckReport:
    """The shipped-anchor part of :func:`cross_check` (the fields of the Rust
    ``AnchorCheckReport``)."""

    #: Anchor lines in the shipped file.
    shipped: int = 0
    #: Shipped anchors whose prune record lies at or before the export's end: the export was
    #: taken after that prune, so it must account for it (checked).
    checked: int = 0
    #: Of those, the ones the export accounts for.
    matched: int = 0
    #: Shipped anchors whose prune record is past the export's end (an archive, or an export
    #: taken before that prune): not checked.
    beyond_range: int = 0
    #: Each shipped anchor the export does not account for, or that is unusable; ``seq`` is the
    #: anchor's ``through_seq``. Also the header's own anchor (``line`` 0) when the shipped file
    #: does not hold it.
    mismatches: tuple[ShippedMismatch, ...] = ()
    #: No mismatches.
    ok: bool = True


@dataclass(frozen=True)
class CrossCheckReport:
    """The verdict of :func:`cross_check` (the fields of the Rust ``CrossCheckReport``, and the
    shipped anchors in ``anchors``)."""

    #: Lines in the shipped file.
    shipped: int
    #: Shipped checkpoints whose seq lies in the export header's ``from..=to`` (checked).
    in_range: int
    #: Of those, the ones the export agrees with.
    matched: int
    #: Shipped checkpoints past the export's range: not checked. If the export was taken up to
    #: the head of the log, these say the log is shorter than what was shipped.
    beyond_range: int
    #: Highest seq in the shipped file.
    last_shipped_seq: int | None
    #: In the order of the shipped file; the first is the first offending seq.
    mismatches: tuple[ShippedMismatch, ...]
    #: No mismatches here and none in ``anchors``.
    ok: bool
    #: Shipped checkpoints before the export's range: not checked against its entries. The one
    #: at the header anchor's ``through_seq`` is checked against the anchor.
    below_range: int = 0
    #: The shipped prune anchors of the same file, checked against the export.
    anchors: AnchorCheckReport = field(default_factory=AnchorCheckReport)


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
    return _verify_parsed(
        _parse(_read_text(path_or_lines)), keys, allow_unsigned_tail=allow_unsigned_tail
    )


def verify_exports(
    paths_or_lines: Iterable[str | os.PathLike[str] | Iterable[str | bytes]],
    *,
    checkpoint_public_keys: Mapping[str, Any],
    allow_unsigned_tail: bool = False,
) -> ExportsReport:
    """Verify several exports, oldest first, as one log: ``attenuo audit verify --file a
    --file b``.

    Each item is what :func:`verify_export` takes. Each file is verified strictly on its own
    (``allow_unsigned_tail`` applies to the last file only), then each file and the next must
    link: both hold entries, the seqs are contiguous, the later file's first ``prev_hash`` is
    the earlier file's last entry hash, the earlier file has a checkpoint at its last seq naming
    that hash, and an anchor in the later file's header, if present, names the earlier file's
    end. ``from_genesis`` and ``from_anchor`` say where the set starts: neither is set when the
    first file starts at a later seq without an anchor, so entries before it are not covered.

    Raises :class:`ExportError` for an empty list or a bare string or bytes (pass a list of
    paths).
    """
    if isinstance(paths_or_lines, (str, bytes, os.PathLike)):
        raise ExportError("verify_exports takes a list of files, not one path or string")
    sources = list(paths_or_lines)
    if not sources:
        raise ExportError("verify_exports needs at least one file")
    keys = _load_keys(checkpoint_public_keys)
    parsed = [_parse(_read_text(src)) for src in sources]
    files = tuple(
        _verify_parsed(p, keys, allow_unsigned_tail=allow_unsigned_tail and i == len(parsed) - 1)
        for i, p in enumerate(parsed)
    )
    links = tuple(_link(parsed))
    first = files[0]
    return ExportsReport(
        ok=all(f.ok for f in files) and not links,
        files=files,
        links=links,
        from_genesis=first.from_genesis,
        from_anchor=first.from_anchor,
        pruned_through=first.pruned_through,
    )


def _link(
    parsed: list[tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]],
) -> list[LinkProblem]:
    out: list[LinkProblem] = []
    for i in range(len(parsed) - 1):
        (_, a_entries, a_cps), (b_header, b_entries, _) = parsed[i], parsed[i + 1]

        def fail(reason: str, i: int = i) -> None:
            out.append(LinkProblem(i, i + 1, reason))

        if not a_entries or not b_entries:
            fail(
                "the earlier file holds no entries"
                if not a_entries
                else "the later file holds no entries"
            )
            continue
        last, first = a_entries[-1], b_entries[0]
        if last["seq"] + 1 != first["seq"]:
            fail(
                f"the seqs are not contiguous: the earlier file ends at seq {last['seq']}, the "
                f"later one starts at seq {first['seq']}"
            )
        elif first["prev_hash"] != last["entry_hash"]:
            fail(
                f"the later file's first entry (seq {first['seq']}) does not link to the earlier "
                f"file's last (its prev_hash is not the entry hash at seq {last['seq']})"
            )
        cp = next((c for c in a_cps if c["seq"] == last["seq"]), None)
        if cp is None:
            fail(
                f"the earlier file does not end at a checkpoint: none at its last seq {last['seq']}"
            )
        elif cp["head_hash"] != last["entry_hash"]:
            fail(
                f"the earlier file's checkpoint at its last seq {last['seq']} names another hash "
                "than its entry"
            )
        an = b_header.get("anchor")
        if an is not None and (
            an["through_seq"] != last["seq"] or an["through_hash"] != last["entry_hash"]
        ):
            fail(
                f"the later file's header anchor is through seq {an['through_seq']}, not the "
                f"earlier file's end at seq {last['seq']} and its hash"
            )
    return out


def _verify_parsed(
    export: tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]],
    keys: dict[str, bytes],
    *,
    allow_unsigned_tail: bool,
) -> ExportReport:
    header, entries, cps = export

    first_seq = entries[0]["seq"] if entries else None
    last_seq = entries[-1]["seq"] if entries else None
    from_genesis = first_seq == 1 and entries[0]["prev_hash"] == GENESIS_HASH
    # An anchor in the header: checked here, and the walk starts where it says.
    anchor = header.get("anchor")
    bad_anchors: list[BadAnchor] = []
    if anchor is not None:
        reason = _verify_anchor(anchor, keys)
        if reason is None and anchor["through_seq"] + 1 != header["from"]:
            reason = (
                f"the header's anchor is through seq {anchor['through_seq']}, but the export "
                f"starts at {header['from']}"
            )
        if reason is None:
            record = next((e for e in entries if e["seq"] == anchor["prune_seq"]), None)
            if record is not None:
                reason = _check_prune_record(anchor, record)
        if reason is not None:
            bad_anchors.append(BadAnchor(anchor["through_seq"], reason))
    start_anchor = anchor if anchor is not None and not bad_anchors else None
    genesis = start_anchor is None and first_seq == 1
    from_anchor = (
        start_anchor is not None
        and bool(entries)
        and entries[0]["seq"] == start_anchor["through_seq"] + 1
        and entries[0]["prev_hash"] == start_anchor["through_hash"]
    )
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
    if start_anchor is not None:
        expected_seq = start_anchor["through_seq"] + 1
        expected_prev = start_anchor["through_hash"]
    for i, e in enumerate(entries):
        count += 1
        if i == 0 and not genesis and start_anchor is None:
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
            actual: str | None = GENESIS_HASH if genesis else None
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
    ok = (
        chain_ok
        and not bad
        and not bad_anchors
        and not truncated
        and outside == 0
        and not tail_rejected
    )
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
        from_anchor=from_anchor,
        pruned_through=start_anchor["through_seq"] if start_anchor is not None else None,
        anchors=0 if anchor is None else 1,
        bad_anchors=tuple(bad_anchors),
    )


def parse_shipped(
    path_or_lines: str | os.PathLike[str] | Iterable[str | bytes],
) -> list[ShippedLine]:
    """Parse a JSONL file of shipped checkpoints (``[audit.sink]`` file output).

    A line is the sink's envelope (``format``, ``checkpoint``, ``kid``, ``signature``,
    ``checkpoint_sha256``) or a bare checkpoint (an export's ``checkpoint`` line, or
    ``GET /admin/audit/checkpoint`` saved by an operator's own job). Blank lines are skipped,
    and so are lines whose ``format`` is ``attenuo-shipped-anchor-v1`` (the signed anchor of a
    prune, which the sink ships with the checkpoints); anything else raises
    :class:`ExportError`. An envelope that disagrees with its own
    checkpoint is not an error here: the line carries ``inconsistency`` and
    :func:`cross_check` reports it.
    """
    return _shipped_lines(_read_text(path_or_lines))


def _shipped_lines(text: str) -> list[ShippedLine]:
    out: list[ShippedLine] = []
    for n, raw in enumerate(text.split("\n"), start=1):
        line = raw.removesuffix("\r")
        if not line.strip():
            continue
        where = f"shipped checkpoints, line {n}"
        try:
            values = _line_values(line)
        except ValueError as e:
            raise ExportError(f"{where}: {e}") from e
        for obj in values:
            if not isinstance(obj, dict):
                raise ExportError(f"{where}: not a JSON object")
            if obj.get("format") == SHIPPED_ANCHOR_FORMAT:
                continue
            if "checkpoint" in obj:
                _need(obj, where, format="str", kid="str", signature="str", checkpoint_sha256="str")
                _public_url(obj, where)
                if not isinstance(obj["checkpoint"], dict):
                    raise ExportError(f"{where}: `checkpoint` must be an object")
                cp = _cp5(_checkpoint(obj["checkpoint"], where))
                out.append(ShippedLine(n, cp, _inconsistency(obj, cp)))
            else:
                kind = obj.pop("type", "checkpoint")
                if kind != "checkpoint":
                    raise ExportError(f"{where}: not a checkpoint line (type {json.dumps(kind)})")
                out.append(ShippedLine(n, _cp5(_checkpoint(obj, where))))
    return out


def parse_shipped_anchors(
    path_or_lines: str | os.PathLike[str] | Iterable[str | bytes],
) -> list[ShippedAnchor]:
    """Every shipped prune anchor of a shipped file: the values of a line that have an
    ``anchor`` member, with their 1-based line number. Other lines are skipped, and so is a line
    that is not JSON (:func:`parse_shipped` reports it). Objects written back to back on one
    line (S3 objects joined with ``cat``, which adds no newline) are each read.

    Raises :class:`ExportError` naming the line when a value with an ``anchor`` member is not a
    shipped anchor (a member missing or of the wrong type). An envelope that disagrees with its
    anchor is not an error here: :func:`cross_check` reports it.
    """
    return _shipped_anchors(_read_text(path_or_lines))


def _shipped_anchors(text: str) -> list[ShippedAnchor]:
    out: list[ShippedAnchor] = []
    for n, raw in enumerate(text.split("\n"), start=1):
        line = raw.removesuffix("\r")
        if not line.strip():
            continue
        try:
            values = _line_values(line)
        except ValueError:
            continue
        where = f"shipped anchors, line {n}"
        for obj in values:
            if not isinstance(obj, dict) or "anchor" not in obj:
                continue
            _need(obj, where, format="str", kid="str", signature="str", anchor_sha256="str")
            _public_url(obj, where)
            a = _anchor(obj["anchor"], f"{where}: anchor")
            out.append(
                ShippedAnchor(
                    line=n,
                    anchor=_a9(a),
                    format=obj["format"],
                    kid=obj["kid"],
                    signature=obj["signature"],
                    anchor_sha256=obj["anchor_sha256"],
                    public_url=obj.get("public_url"),
                )
            )
    return out


def _public_url(obj: Mapping[str, Any], where: str) -> None:
    if obj.get("public_url") is not None and not isinstance(obj["public_url"], str):
        raise ExportError(f"{where}: `public_url` must be a string")


def _a9(a: Mapping[str, Any]) -> dict[str, Any]:
    return {k: a.get(k) for k in _ANCHOR_FIELDS}


def _anchor_sha256(a: Mapping[str, Any]) -> str:
    """Hex SHA-256 of the RFC 8785 canonical JSON of the nine anchor members."""
    # Members in code-unit order; the integers by hand, as in `_checkpoint_sha256`.
    data = (
        b'{"archive_sha256":%s,"at":%s,"kid":%s,"previous_through_seq":%s,'
        b'"prune_entry_hash":%s,"prune_seq":%d,"signature":%s,"through_hash":%s,'
        b'"through_seq":%d}'
        % (
            rfc8785.dumps(a.get("archive_sha256")),
            rfc8785.dumps(a["at"]),
            rfc8785.dumps(a["kid"]),
            _opt_uint(a.get("previous_through_seq")),
            rfc8785.dumps(a["prune_entry_hash"]),
            a["prune_seq"],
            rfc8785.dumps(a["signature"]),
            rfc8785.dumps(a["through_hash"]),
            a["through_seq"],
        )
    )
    return hashlib.sha256(data).hexdigest()


def _cp5(c: Mapping[str, Any]) -> dict[str, Any]:
    return {k: c[k] for k in _CP_FIELDS}


def _checkpoint_sha256(cp: Mapping[str, Any]) -> str:
    """Hex SHA-256 of the RFC 8785 canonical JSON of the five checkpoint members."""
    # Members in code-unit order; `seq` by hand since `rfc8785` refuses integers beyond 2**53.
    data = b'{"at":%s,"head_hash":%s,"kid":%s,"seq":%d,"signature":%s}' % (
        rfc8785.dumps(cp["at"]),
        rfc8785.dumps(cp["head_hash"]),
        rfc8785.dumps(cp["kid"]),
        cp["seq"],
        rfc8785.dumps(cp["signature"]),
    )
    return hashlib.sha256(data).hexdigest()


def _inconsistency(env: Mapping[str, Any], cp: Mapping[str, Any]) -> str | None:
    if env["format"] != SHIPPED_FORMAT:
        return f"unsupported format `{env['format']}`"
    if env["kid"] != cp["kid"] or env["signature"] != cp["signature"]:
        return "`kid` or `signature` differs from the checkpoint's own"
    if env["checkpoint_sha256"] != _checkpoint_sha256(cp):
        return "`checkpoint_sha256` does not match the checkpoint"
    return None


def cross_check(
    export: str | os.PathLike[str] | Iterable[str | bytes],
    shipped: str | os.PathLike[str] | Iterable[str | bytes],
    *,
    checkpoint_public_keys: Mapping[str, Any],
) -> CrossCheckReport:
    """Compare an audit export with checkpoints shipped off the host (SR-21).

    A signed checkpoint proves the log prefix ``1..=seq`` hashed to ``head_hash``, but it is
    signed with the server's own key: someone who holds the host and that key can rewrite the
    log and sign fresh checkpoints, and the export then verifies. A copy of the original
    checkpoint that already left the host (the checkpoint sink) is what they cannot change.

    ``export`` and ``shipped`` are file paths or iterables of lines, as for
    :func:`verify_export`; ``checkpoint_public_keys`` is the same JWKS or ``kid`` map. For each
    shipped checkpoint inside the export's declared range:

    - it must verify against the keys (a forged shipped copy would otherwise be trusted);
    - the export must hold a checkpoint at that seq, identical in every member: a different
      one was **signed again after shipping**, none at all means it was **deleted**;
    - the export's entry at that seq must hash to the shipped ``head_hash``.

    Two different shipped checkpoints for one seq are reported too, and so is an envelope whose
    ``kid``, ``signature`` or ``checkpoint_sha256`` disagrees with its checkpoint. A shipped
    checkpoint before the export's range is counted in ``below_range``; the one at the header
    anchor's ``through_seq`` must name the anchor's ``through_hash``.

    The shipped prune anchors of the same file are checked too, into ``anchors``
    (:class:`AnchorCheckReport`), as the Rust ``cross_check_anchors`` does. Each must verify
    and agree with its envelope. Then, for an anchor whose prune record (``prune_seq``) is at or
    before the export's last seq:

    - an anchor below the export's start is an older prune, accounted for;
    - the anchor of the boundary right before the export's start must be the header's anchor;
    - an anchor whose boundary is at or past the export's start says entries the export holds
      were pruned: the log was **rewound** (a restored backup, or the anchor row removed).

    An anchor whose prune record is past the export's end is not checked, except when its
    boundary lies inside the export and is not its last entry: the export then holds entries a
    later prune removed. A header anchor that the file does not hold is a mismatch too.

    ``ok`` is true only when both checks pass. This does not replace :func:`verify_export`: run
    both.
    """
    keys = _load_keys(checkpoint_public_keys)
    header, entries, cps = _parse(_read_text(export))
    shipped_text = _read_text(shipped)
    lines = _shipped_lines(shipped_text)
    anchors = _check_anchors(header, entries, _shipped_anchors(shipped_text), keys)
    lo, hi = header["from"], header["to"]
    header_anchor = header.get("anchor")
    exported = {c["seq"]: _cp5(c) for c in cps}
    entry_hashes = {e["seq"]: e["entry_hash"] for e in entries}
    first_by_seq: dict[int, ShippedLine] = {}
    mismatches: list[ShippedMismatch] = []
    in_range = matched = beyond = below = 0
    for s in lines:
        cp = s.checkpoint
        seq = cp["seq"]

        def fail(reason: str, s: ShippedLine = s, seq: int = seq) -> None:
            mismatches.append(ShippedMismatch(seq, s.line, reason))

        if s.inconsistency is not None:
            fail(f"shipped envelope is inconsistent: {s.inconsistency}")
            continue
        prev = first_by_seq.get(seq)
        if prev is None:
            first_by_seq[seq] = s
        elif prev.checkpoint != cp:
            fail(
                "the sink holds two different checkpoints for this seq "
                f"(lines {prev.line} and {s.line}): "
                "the seq was signed again after the first was shipped"
            )
            continue
        # else: a retried delivery, same content
        if seq > hi:
            beyond += 1
            continue
        if seq < lo and not (seq == 0 and lo <= 1):
            below += 1
            if header_anchor is not None and header_anchor["through_seq"] == seq:
                why = _verify_checkpoint(cp, keys)
                if why is not None:
                    fail(f"shipped checkpoint does not verify: {why}")
                elif cp["head_hash"] != header_anchor["through_hash"]:
                    fail(
                        "the shipped checkpoint at the anchor's through_seq names another hash "
                        "than the anchor (history rewritten before the prune)"
                    )
            continue
        in_range += 1
        why = _verify_checkpoint(cp, keys)
        if why is not None:
            fail(f"shipped checkpoint does not verify: {why}")
            continue
        problems: list[str] = []
        e = exported.get(seq)
        if e is None:
            problems.append("the export has no checkpoint at this seq (deleted after shipping)")
        elif e != cp:
            diff = [k for k in ("head_hash", "signature", "at", "kid") if e[k] != cp[k]]
            problems.append(
                "RE-SIGNED after shipping: the export's checkpoint at this seq differs in "
                + ", ".join(diff)
            )
        if seq > 0:
            h = entry_hashes.get(seq)
            if h is None:
                problems.append("the export has no entry at this seq")
            elif h != cp["head_hash"]:
                problems.append(
                    "the export's entry at this seq does not hash to the shipped head_hash "
                    "(history rewritten after shipping)"
                )
        if problems:
            fail("; ".join(problems))
        else:
            matched += 1
    return CrossCheckReport(
        shipped=len(lines),
        in_range=in_range,
        matched=matched,
        beyond_range=beyond,
        last_shipped_seq=max((s.checkpoint["seq"] for s in lines), default=None),
        mismatches=tuple(mismatches),
        ok=not mismatches and anchors.ok,
        below_range=below,
        anchors=anchors,
    )


def _check_anchors(
    header: Mapping[str, Any],
    entries: list[dict[str, Any]],
    shipped: list[ShippedAnchor],
    keys: dict[str, bytes],
) -> AnchorCheckReport:
    """The Rust ``cross_check_anchors``, rule for rule."""
    lo, hi = header["from"], header["to"]
    last = max(entries[-1]["seq"], hi) if entries else hi
    end = entries[-1]["seq"] if entries else None
    raw_header_anchor = header.get("anchor")
    header_anchor = None if raw_header_anchor is None else _a9(raw_header_anchor)
    mismatches: list[ShippedMismatch] = []
    checked = matched = beyond = 0
    first_by_through: dict[int, ShippedAnchor] = {}
    header_seen = False
    for s in shipped:
        a = s.anchor
        through = a["through_seq"]

        def fail(reason: str, s: ShippedAnchor = s, through: int = through) -> None:
            mismatches.append(ShippedMismatch(through, s.line, reason))

        if s.format != SHIPPED_ANCHOR_FORMAT:
            fail(f"shipped envelope is inconsistent: unsupported format `{s.format}`")
            continue
        if s.kid != a["kid"] or s.signature != a["signature"]:
            fail(
                "shipped envelope is inconsistent: `kid` or `signature` differs from the "
                "anchor's own"
            )
            continue
        if s.anchor_sha256 != _anchor_sha256(a):
            fail("shipped envelope is inconsistent: `anchor_sha256` does not match the anchor")
            continue
        why = _verify_anchor(a, keys)
        if why is not None:
            fail(f"shipped anchor does not verify: {why}")
            continue
        prev = first_by_through.get(through)
        if prev is not None:
            if prev.anchor != a:
                fail(
                    "the sink holds two different anchors for this boundary "
                    f"(lines {prev.line} and {s.line}): the log was pruned through this seq twice"
                )
            continue  # else: a retried delivery, same content, counted once
        first_by_through[through] = s
        # The boundary right before the export's start: its header's anchor, wherever the
        # export ends.
        at_start = through + 1 == lo
        if a["prune_seq"] > last and not at_start:
            # An archive ends at its prune's boundary; a boundary strictly inside the export
            # says the export holds entries that a later prune removed.
            if lo <= through <= last and through != end:
                checked += 1
                fail(
                    f"the shipped prune through seq {through} (its record at seq "
                    f"{a['prune_seq']} is past this export's end at seq {last}) has its "
                    "boundary inside this export: the export was taken before that prune, or "
                    "the log was rewound to before it; check an export taken now"
                )
                continue
            beyond += 1
            continue
        checked += 1
        if through + 1 < lo:
            matched += 1
        elif at_start:
            header_seen = True
            if header_anchor is None:
                fail(
                    "the export starts right after this shipped anchor's boundary, but its "
                    "header carries no anchor"
                )
            elif header_anchor == a:
                matched += 1
            else:
                fail(
                    "the export's header carries another anchor for this boundary than the "
                    "one shipped"
                )
        else:
            fail(
                f"REWOUND: the shipped anchor says the log was pruned through seq {through}, "
                f"but the export holds entries from seq {lo} (a restored backup, or the anchor "
                "row removed)"
            )
    if header_anchor is not None and not header_seen:
        mismatches.append(
            ShippedMismatch(
                header_anchor["through_seq"],
                0,
                "the export's header anchor is not in the shipped file (it was not shipped, or "
                "the file is incomplete)",
            )
        )
    return AnchorCheckReport(
        shipped=len(shipped),
        checked=checked,
        matched=matched,
        beyond_range=beyond,
        mismatches=tuple(mismatches),
        ok=not mismatches,
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


_DECODER = json.JSONDecoder(object_pairs_hook=_no_dupes, parse_constant=_no_const)
_JSON_WS = " \t\n\r"


def _line_values(line: str) -> list[Any]:
    """The JSON values of one line: usually one, or several objects written back to back (S3
    objects joined with ``cat``, which adds no newline between them)."""
    out: list[Any] = []
    i, n = 0, len(line)
    while True:
        while i < n and line[i] in _JSON_WS:
            i += 1
        if i >= n:
            return out
        value, i = _DECODER.raw_decode(line, i)
        out.append(value)


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
            "nothing proves it is complete; verify an export taken without kind, chain_id, tool or "
            "decision filters, then filter that"
        )
    if h.get("anchor") is not None:
        _anchor(h["anchor"])
    return h


def _anchor(a: Any, where: str = "header anchor") -> dict[str, Any]:
    if not isinstance(a, dict):
        raise ExportError(
            "header: `anchor` must be an object"
            if where == "header anchor"
            else f"{where}: must be an object"
        )
    _need(
        a,
        where,
        through_seq="uint",
        through_hash="str",
        prune_seq="uint",
        prune_entry_hash="str",
        at="str",
        kid="str",
        signature="str",
    )
    if a.get("previous_through_seq") is not None and not _is_uint(a["previous_through_seq"]):
        raise ExportError(f"{where}: `previous_through_seq` must be a non-negative integer or null")
    if a.get("archive_sha256") is not None and not isinstance(a["archive_sha256"], str):
        raise ExportError(f"{where}: `archive_sha256` must be a string or null")
    return a


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


def _verify_checkpoint(cp: Mapping[str, Any], keys: dict[str, bytes]) -> str | None:
    """``None`` when the signature verifies, else why not."""
    payload = b"[%d,%s,%s,%s]" % (
        cp["seq"],
        rfc8785.dumps(cp["head_hash"]),
        rfc8785.dumps(cp["at"]),
        rfc8785.dumps(cp["kid"]),
    )
    return _verify_signed(cp["kid"], _CHECKPOINT_CONTEXT, payload, cp["signature"], keys)


def _opt_uint(v: Any) -> bytes:
    return b"null" if v is None else b"%d" % v


def _verify_anchor(a: Mapping[str, Any], keys: dict[str, bytes]) -> str | None:
    """``None`` when the anchor's signature verifies, else why not. The payload is the RFC 8785
    JSON of ``[through_seq, through_hash, prune_seq, prune_entry_hash, previous_through_seq,
    archive_sha256, at, kid]``, framed with the anchor context."""
    payload = b"[%d,%s,%d,%s,%s,%s,%s,%s]" % (
        a["through_seq"],
        rfc8785.dumps(a["through_hash"]),
        a["prune_seq"],
        rfc8785.dumps(a["prune_entry_hash"]),
        _opt_uint(a.get("previous_through_seq")),
        rfc8785.dumps(a.get("archive_sha256")),
        rfc8785.dumps(a["at"]),
        rfc8785.dumps(a["kid"]),
    )
    return _verify_signed(a["kid"], _ANCHOR_CONTEXT, payload, a["signature"], keys)


def _check_prune_record(a: Mapping[str, Any], e: Mapping[str, Any]) -> str | None:
    """``None`` when ``e`` is the anchor's prune record: at ``prune_seq``, hashing to
    ``prune_entry_hash`` (the file's hash, which the chain walk checks), an allowed admin record
    of :data:`PRUNE_TOOL` by the server, whose ``arguments_digest`` is that of the anchor's
    values."""
    r = e["record"]
    if e["seq"] != a["prune_seq"] or e["entry_hash"] != a["prune_entry_hash"]:
        return "the entry at prune_seq does not hash to prune_entry_hash"
    if (
        r.get("kind") != "admin"
        or r.get("tool") != PRUNE_TOOL
        or r.get("server") != "attenuo"
        or r.get("decision") != "allow"
    ):
        return f"the entry at prune_seq is not an allowed `{PRUNE_TOOL}` admin record"
    # `sha256_json` of {through_seq, through_hash, previous_through_seq, archive_sha256}, keys
    # in RFC 8785 order; the integers written by hand as in `entry_hash`.
    args = b'{"archive_sha256":%s,"previous_through_seq":%s,"through_hash":%s,"through_seq":%d}' % (
        rfc8785.dumps(a.get("archive_sha256")),
        _opt_uint(a.get("previous_through_seq")),
        rfc8785.dumps(a["through_hash"]),
        a["through_seq"],
    )
    if r.get("arguments_digest") != hashlib.sha256(args).hexdigest():
        return "the prune record's arguments digest does not match the anchor"
    return None


def _verify_signed(
    kid: str, context: str, payload: bytes, signature: str, keys: dict[str, bytes]
) -> str | None:
    key = keys.get(kid)
    if key is None:
        return f"unknown signing key `{kid}`"
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as e:  # pragma: no cover - depends on the environment
        raise ExportError(
            "checking checkpoint signatures needs the `cryptography` package "
            "(pip install 'attenuo[verify]')"
        ) from e
    sig = _b64url_decode(signature)
    ctx = context.encode()
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(
            sig or b"", struct.pack(">I", len(ctx)) + ctx + payload
        )
    except (InvalidSignature, ValueError):
        return "signature does not verify"
    return None
