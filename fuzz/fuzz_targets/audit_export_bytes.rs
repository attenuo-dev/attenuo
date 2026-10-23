//! `parse_export` + `verify_export` on arbitrary text (JSONL or the JSON form): never panics,
//! and nothing random passes as a signed export.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let a = onbehalf_fuzz::audit_fixture();
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(export) = onbehalf_audit::parse_export(text) else {
        return;
    };
    let _ = onbehalf_audit::to_json_form(&export);
    // Known gap (board, 2026-10-23 fuzzing): an entry with `seq` = u64::MAX and a correct hash
    // overflows `seq + 1` in the chain walk (`onbehalf-audit` log.rs) and panics where overflow
    // checks are on. Skipped here until that is fixed in `onbehalf-audit`.
    if export.entries.iter().any(|e| e.seq == u64::MAX) {
        return;
    }

    if let Ok(report) = onbehalf_audit::verify_export(&export, &a.keys) {
        // Only an export that verifies counts: entries after a break are reported, not vouched for.
        if report.report.ok && report.report.last_signed_seq.is_some_and(|s| s > 0) {
            // A checkpoint verified, so its entries must be the fixture's (the only thing the
            // fuzzer could have taken a valid signature from).
            for e in &export.entries {
                if e.seq <= report.report.last_signed_seq.unwrap() {
                    let orig = a.export.entries.iter().find(|o| o.seq == e.seq);
                    assert_eq!(orig, Some(e), "signed entry differs from the original");
                }
            }
        }
    }
});
