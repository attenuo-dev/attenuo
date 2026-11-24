//! The DER reads of the TLS client certificate check (`client_pki.rs`, RFC 8705
//! `tls_client_auth`), through the `fuzzing` feature of attenuo-server, which wraps the
//! server's own functions: `is_ca` (a CA file entry's `basicConstraints`), `uri_name_count`
//! (the URI names of a `subjectAltName`, for the one-name rule of SPIFFE IDs), the issuer,
//! subject and `notAfter` reads, and `useful_intermediates` (which certificates a client sent
//! are given to path building). Each runs on the raw input, and on the input placed in a
//! certificate skeleton so that the extension and name parsing is reached.
//!
//! Properties beyond "no panic":
//!
//! 1. `is_ca` is true only for a `basicConstraints` value that starts `SEQUENCE`, `BOOLEAN`
//!    `0xff`: a malformed value is never a CA.
//! 2. `uri_name_count` never counts more names than the value has room for (two bytes each).
//! 3. A `notAfter` that reads gives back the same date and time digits.
//! 4. `useful_intermediates` keeps a subsequence of what was sent: no copy of the leaf, no
//!    self-issued certificate, one per subject, and the first readable one of each subject
//!    that is neither.
#![no_main]

use arbitrary::Arbitrary;
use attenuo_server::fuzzing::{
    pki_is_ca, pki_issuer_subject, pki_not_after, pki_uri_name_count, pki_useful_intermediates,
};
use libfuzzer_sys::fuzz_target;

const BASIC_CONSTRAINTS: [u8; 3] = [0x55, 0x1d, 0x13];
const SUBJECT_ALT_NAME: [u8; 3] = [0x55, 0x1d, 0x11];

#[derive(Arbitrary, Debug)]
struct Input {
    raw: Vec<u8>,
    critical: bool,
    time: Time,
    /// (issuer, subject, serial) of certificates sent after the leaf, from a small alphabet.
    sent: Vec<(u8, u8, u8)>,
    leaf: (u8, u8, u8),
    /// Put the leaf itself among the certificates sent, at this index.
    leaf_at: Option<u8>,
}

#[derive(Arbitrary, Debug)]
struct Time {
    generalized: bool,
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = contents.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(contents);
    out
}

fn name(n: u8) -> Vec<u8> {
    tlv(0x30, &tlv(0x31, &tlv(0x30, &[0x06, 0x01, n % 4])))
}

/// A certificate skeleton: the fields the reads look at, with `extension` as its only
/// extension when given.
fn cert(
    issuer: &[u8],
    subject: &[u8],
    serial: u8,
    validity: &[u8],
    extension: Option<(&[u8], bool, &[u8])>,
) -> Vec<u8> {
    let mut tbs = tlv(0xa0, &tlv(0x02, &[2]));
    tbs.extend(tlv(0x02, &[serial]));
    tbs.extend(tlv(0x30, &[]));
    tbs.extend_from_slice(issuer);
    tbs.extend(tlv(0x30, validity));
    tbs.extend_from_slice(subject);
    tbs.extend(tlv(0x30, &[]));
    if let Some((oid, critical, value)) = extension {
        let mut ext = tlv(0x06, oid);
        if critical {
            ext.extend(tlv(0x01, &[0xff]));
        }
        ext.extend(tlv(0x04, value));
        tbs.extend(tlv(0xa3, &tlv(0x30, &tlv(0x30, &ext))));
    }
    let mut body = tlv(0x30, &tbs);
    body.extend(tlv(0x30, &[]));
    body.extend(tlv(0x03, &[0]));
    tlv(0x30, &body)
}

fn digits(v: u32, n: usize) -> String {
    format!("{v:0n$}")
}

fn simple(issuer: u8, subject: u8, serial: u8) -> Vec<u8> {
    let time = tlv(0x17, b"300101000000Z");
    let validity = [time.clone(), time].concat();
    cert(&name(issuer), &name(subject), serial, &validity, None)
}

fuzz_target!(|input: Input| {
    let raw = &input.raw;
    let _ = pki_is_ca(raw);
    let _ = pki_uri_name_count(raw);
    let _ = pki_issuer_subject(raw);
    let _ = pki_not_after(raw);

    // 1. basicConstraints.
    let validity = [tlv(0x17, b"300101000000Z"), tlv(0x17, b"300101000000Z")].concat();
    let bc = cert(
        &name(0),
        &name(1),
        1,
        &validity,
        Some((&BASIC_CONSTRAINTS, input.critical, raw)),
    );
    if pki_is_ca(&bc) {
        assert!(raw.len() >= 5 && raw[0] == 0x30, "{raw:02x?}");
        let inner = &raw[2..];
        assert!(
            inner.starts_with(&[0x01, 0x01, 0xff]) || raw[1] & 0x80 != 0,
            "{raw:02x?}"
        );
    }
    let no_ext = cert(&name(0), &name(1), 1, &validity, None);
    assert!(!pki_is_ca(&no_ext));
    assert_eq!(pki_uri_name_count(&no_ext), Some(0));

    // 2. subjectAltName.
    let san = cert(
        &name(0),
        &name(1),
        1,
        &validity,
        Some((&SUBJECT_ALT_NAME, input.critical, raw)),
    );
    if let Some(n) = pki_uri_name_count(&san) {
        assert!(n * 2 <= raw.len(), "{n} names in {} bytes", raw.len());
    }

    // 3. notAfter.
    let t = &input.time;
    let (tag, text) = if t.generalized {
        (0x18, digits(u32::from(t.year % 10_000), 4))
    } else {
        (0x17, digits(u32::from(t.year % 100), 2))
    };
    let text = format!(
        "{text}{}{}{}{}{}Z",
        digits(u32::from(t.month % 100), 2),
        digits(u32::from(t.day % 100), 2),
        digits(u32::from(t.hour % 100), 2),
        digits(u32::from(t.minute % 100), 2),
        digits(u32::from(t.second % 100), 2),
    );
    let validity = [tlv(0x17, b"000101000000Z"), tlv(tag, text.as_bytes())].concat();
    let dated = cert(&name(0), &name(1), 1, &validity, None);
    if let Some(secs) = pki_not_after(&dated) {
        let at = time::OffsetDateTime::from_unix_timestamp(secs).unwrap();
        let year = if t.generalized {
            u32::from(t.year % 10_000)
        } else {
            let yy = u32::from(t.year % 100);
            if yy < 50 {
                2000 + yy
            } else {
                1900 + yy
            }
        };
        assert_eq!(
            (
                at.year() as u32,
                u8::from(at.month()),
                at.day(),
                at.hour(),
                at.minute(),
                at.second()
            ),
            (
                year,
                t.month % 100,
                t.day % 100,
                t.hour % 100,
                t.minute % 100,
                t.second % 100
            ),
            "{text}"
        );
    }

    // 4. The intermediates kept. The expected list is built with the server's own issuer and
    // subject read (`pki_issuer_subject`): this checks the filter's logic, not that read.
    let leaf = simple(input.leaf.0, input.leaf.1, input.leaf.2);
    let mut sent: Vec<Vec<u8>> = input
        .sent
        .iter()
        .take(8)
        .map(|&(i, s, n)| simple(i, s, n))
        .collect();
    if let Some(at) = input.leaf_at {
        let at = usize::from(at) % (sent.len() + 1);
        sent.insert(at, leaf.clone());
    }
    if input.critical {
        sent.push(raw.clone());
    }
    let kept = pki_useful_intermediates(&leaf, &sent);
    let mut want: Vec<Vec<u8>> = Vec::new();
    let mut subjects: Vec<Vec<u8>> = Vec::new();
    for c in &sent {
        let Some((issuer, subject)) = pki_issuer_subject(c) else {
            continue;
        };
        if *c == leaf || issuer == subject || subjects.iter().any(|s| s == subject) {
            continue;
        }
        subjects.push(subject.to_vec());
        want.push(c.clone());
    }
    assert_eq!(kept, want);
    assert!(kept.len() <= sent.len());
    assert!(kept.iter().all(|c| *c != leaf));
});
