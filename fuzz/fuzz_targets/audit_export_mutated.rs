//! `verify_export` on mutated copies of a valid signed export (5 entries, checkpoints at 3 and
//! 5, header `1..=5`).
//!
//! Mutations: edit any field of an entry (optionally re-hashing the chain from there on, as an
//! attacker without the checkpoint key would), delete, swap or duplicate entries, renumber
//! them, edit or drop checkpoints and the header, or flip bytes of the JSONL text.
//!
//! The invariant: an export that verifies `ok` (strictly, the default) never carries an entry,
//! at or below the highest countersigned seq, that differs from the original; it has no
//! unsigned tail, and with the header kept, it holds no entry outside the header's range. In
//! other words, every mutation of signed content is rejected, and the only thing an attacker
//! can do undetected is drop the evidence (checkpoints and the entries they cover, together
//! with the header's range), which leaves a smaller export that is still all signed.
#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use onbehalf_audit::{compute_entry_hash, AuditEntry, Export};
use onbehalf_fuzz::{edge_number, edge_string, json_value};
use serde_json::Value;

const ENTRY_PATHS: &[&str] = &[
    "/seq",
    "/prev_hash",
    "/entry_hash",
    "/record/id",
    "/record/at",
    "/record/decision",
    "/record/reason",
    "/record/originating_subject",
    "/record/agents",
    "/record/chain_depth",
    "/record/chain_digest",
    "/record/leases",
    "/record/server",
    "/record/tool",
    "/record/arguments_digest",
    "/record/session_id",
    "/record/policy_ids",
    "/record/dpop_bound",
];
const CP_PATHS: &[&str] = &["/seq", "/head_hash", "/at", "/kid", "/signature"];

#[derive(Debug)]
enum Op {
    EditEntry {
        i: usize,
        path: &'static str,
        v: Value,
        rehash: bool,
    },
    DeleteEntry(usize),
    SwapEntries(usize, usize),
    DuplicateEntry(usize),
    AppendEntry {
        rehash: bool,
    },
    EditCheckpoint {
        i: usize,
        path: &'static str,
        v: Value,
    },
    DeleteCheckpoint(usize),
    DuplicateCheckpoint(usize),
    EditHeader {
        from: u64,
        to: u64,
    },
    DropHeader,
    FlipText(Vec<(u16, u8)>),
}

fn value(u: &mut Unstructured<'_>) -> Result<Value> {
    Ok(match u.int_in_range(0u8..=3)? {
        0 => edge_number(u)?,
        1 => Value::String(edge_string(u)?),
        2 => Value::from(u.int_in_range(0u64..=7)?),
        _ => json_value(u, 2)?,
    })
}

impl<'a> Arbitrary<'a> for Op {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let i = u.int_in_range(0usize..=6)?;
        Ok(match u.int_in_range(0u8..=10)? {
            0 | 1 => Op::EditEntry {
                i,
                path: u.choose(ENTRY_PATHS)?,
                v: value(u)?,
                rehash: u.arbitrary()?,
            },
            2 => Op::DeleteEntry(i),
            3 => Op::SwapEntries(i, u.int_in_range(0usize..=6)?),
            4 => Op::DuplicateEntry(i),
            5 => Op::AppendEntry {
                rehash: u.arbitrary()?,
            },
            6 => Op::EditCheckpoint {
                i,
                path: u.choose(CP_PATHS)?,
                v: value(u)?,
            },
            7 => Op::DeleteCheckpoint(i),
            8 => Op::DuplicateCheckpoint(i),
            9 => {
                if u.arbitrary()? {
                    Op::DropHeader
                } else {
                    Op::EditHeader {
                        from: u.int_in_range(0u64..=7)?,
                        to: u.int_in_range(0u64..=7)?,
                    }
                }
            }
            _ => Op::FlipText(u.arbitrary()?),
        })
    }
}

/// Recompute `entry_hash` from `i` on, and re-link the following entries.
fn rehash(entries: &mut [AuditEntry], i: usize) {
    for j in i..entries.len() {
        if j > 0 {
            entries[j].prev_hash = entries[j - 1].entry_hash.clone();
        }
        let e = &entries[j];
        entries[j].entry_hash = compute_entry_hash(e.seq, &e.prev_hash, &e.record);
    }
}

fn edit<T: serde::Serialize + serde::de::DeserializeOwned>(item: &mut T, path: &str, v: &Value) {
    let mut j = serde_json::to_value(&*item).unwrap();
    match j.pointer_mut(path) {
        Some(slot) => *slot = v.clone(),
        None => {
            if let Some((parent, key)) = path.rsplit_once('/') {
                if let Some(Value::Object(m)) = j.pointer_mut(parent) {
                    m.insert(key.into(), v.clone());
                }
            }
        }
    }
    if let Ok(t) = serde_json::from_value(j) {
        *item = t;
    }
}

fn apply(ex: &mut Export, text: &mut Option<String>, op: Op) {
    let n = ex.entries.len();
    match op {
        Op::EditEntry {
            i,
            path,
            v,
            rehash: r,
        } if n > 0 => {
            let i = i % n;
            edit(&mut ex.entries[i], path, &v);
            if r {
                rehash(&mut ex.entries, i);
            }
        }
        Op::DeleteEntry(i) if n > 0 => {
            ex.entries.remove(i % n);
        }
        Op::SwapEntries(i, j) if n > 0 => ex.entries.swap(i % n, j % n),
        Op::DuplicateEntry(i) if n > 0 => {
            let e = ex.entries[i % n].clone();
            ex.entries.insert(i % n, e);
        }
        Op::AppendEntry { rehash: r } if n > 0 => {
            let mut e = ex.entries[n - 1].clone();
            e.seq = e.seq.wrapping_add(1);
            e.record.reason = "forged".into();
            ex.entries.push(e);
            if r {
                rehash(&mut ex.entries, n);
            }
        }
        Op::EditCheckpoint { i, path, v } if !ex.checkpoints.is_empty() => {
            let i = i % ex.checkpoints.len();
            edit(&mut ex.checkpoints[i], path, &v);
        }
        Op::DeleteCheckpoint(i) if !ex.checkpoints.is_empty() => {
            let i = i % ex.checkpoints.len();
            ex.checkpoints.remove(i);
        }
        Op::DuplicateCheckpoint(i) if !ex.checkpoints.is_empty() => {
            let c = ex.checkpoints[i % ex.checkpoints.len()].clone();
            ex.checkpoints.push(c);
        }
        Op::EditHeader { from, to } => {
            if let Some(h) = &mut ex.header {
                h.from = from;
                h.to = to;
            }
        }
        Op::DropHeader => ex.header = None,
        Op::FlipText(flips) => {
            let mut bytes = onbehalf_fuzz::audit_fixture().text.clone().into_bytes();
            for (pos, b) in flips {
                let i = pos as usize % bytes.len();
                bytes[i] ^= b.max(1);
            }
            *text = String::from_utf8(bytes).ok();
        }
        _ => {}
    }
}

fuzz_target!(|ops: Vec<Op>| {
    let a = onbehalf_fuzz::audit_fixture();
    let mut ex = a.export.clone();
    let mut text = None;
    let header_kept_from = ops
        .iter()
        .all(|o| !matches!(o, Op::EditHeader { .. } | Op::DropHeader | Op::FlipText(_)));
    for op in ops {
        apply(&mut ex, &mut text, op);
    }
    if let Some(t) = text {
        match onbehalf_audit::parse_export(&t) {
            Ok(parsed) => ex = parsed,
            Err(_) => return,
        }
    }
    let Ok(report) = onbehalf_audit::verify_export(&ex, &a.keys) else {
        return;
    };
    // Only an export that verifies counts: entries after a break are reported, not vouched for.
    if let (true, Some(s)) = (report.report.ok, report.report.last_signed_seq) {
        for e in ex.entries.iter().filter(|e| e.seq <= s) {
            let orig = a.export.entries.iter().find(|o| o.seq == e.seq);
            assert_eq!(
                orig,
                Some(e),
                "a countersigned entry was altered and still verified"
            );
        }
    }
    // F5 (fixed): entries after the last checkpoint, or outside the header's range, fail a
    // strict verification; reproducer `[AppendEntry { rehash: true }]`.
    if report.report.ok {
        assert_eq!(report.report.unsigned_tail, 0, "verified with an unsigned tail");
    }
    if report.report.ok && header_kept_from {
        if let Some(h) = &ex.header {
            for e in &ex.entries {
                assert!(
                    e.seq >= h.from && e.seq <= h.to,
                    "export verified with entry {} outside its header range {}..={}",
                    e.seq,
                    h.from,
                    h.to
                );
            }
        }
    }
});
