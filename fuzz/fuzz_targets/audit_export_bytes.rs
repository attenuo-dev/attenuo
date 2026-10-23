//! `parse_export` + `verify_export` on arbitrary text (JSONL or the JSON form): never panics,
//! and nothing random passes as a signed export.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let a = attenuo_fuzz::audit_fixture();
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(export) = attenuo_audit::parse_export(text) else {
        return;
    };
    let _ = attenuo_audit::to_json_form(&export);

    if let Ok(report) = attenuo_audit::verify_export(&export, &a.keys) {
        // Only an export that verifies counts: entries after a break are reported, not vouched for.
        // Strict verification (F5): an export that verifies is countersigned throughout.
        if report.report.ok {
            assert_eq!(report.report.unsigned_tail, 0, "ok with an unsigned tail");
            assert_eq!(report.outside_range, 0, "ok with entries outside the header range");
        }
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
