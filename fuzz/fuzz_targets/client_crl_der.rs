//! The CRL file reads of the TLS client certificate check (`client_crl.rs`, ADR-0023), through
//! the `fuzzing` feature of attenuo-server, which wraps the server's own functions:
//! `crl_parse` (a CRL file's bytes, PEM or DER, up to its signature: rustls-webpki's parser,
//! the entry count and the server's own reads), `crl_facts` (the issuer, dates, `cRLNumber`
//! and `issuingDistributionPoint` reads), `crl_signed_data` (the split of a signed object) and
//! `crl_may_sign` (the `cRLSign` bit of a CA certificate's `keyUsage`). Each runs on the raw
//! input, and on a CRL or certificate skeleton built from it so that the field reads are
//! reached.
//!
//! Properties beyond "no panic":
//!
//! 1. A file that parses has no `issuingDistributionPoint`, at most 100,000 entries, a
//!    `cRLNumber` without leading zero bytes, and the issuer and dates `crl_facts` reads.
//! 2. The same DER parses the same way as a PEM `X509 CRL` block, and never with a private
//!    key block next to it.
//! 3. `crl_signed_data` returns parts of its input, the to-be-signed part a `SEQUENCE`.
//! 4. A CRL skeleton with valid dates and a valid `cRLNumber` reads back its issuer, dates,
//!    number and `issuingDistributionPoint` flag; a negative or empty `cRLNumber` reads as
//!    nothing.
//! 5. `crl_may_sign` is true for a certificate without `keyUsage`, and with one only for a
//!    `BIT STRING` with the `cRLSign` bit.
#![no_main]

use arbitrary::Arbitrary;
use attenuo_server::fuzzing::{crl_facts, crl_may_sign, crl_parse, crl_signed_data};
use base64::Engine as _;
use libfuzzer_sys::fuzz_target;

const KEY_USAGE: [u8; 3] = [0x55, 0x1d, 0x0f];
const CRL_NUMBER: [u8; 3] = [0x55, 0x1d, 0x14];
const ISSUING_DISTRIBUTION_POINT: [u8; 3] = [0x55, 0x1d, 0x1c];

#[derive(Arbitrary, Debug)]
struct Input {
    raw: Vec<u8>,
    issuer: u8,
    this_update: Time,
    next_update: Time,
    /// Serial numbers of the listed certificates.
    revoked: Vec<u8>,
    /// The `cRLNumber` INTEGER contents, when the CRL has one.
    number: Option<Vec<u8>>,
    /// An `issuingDistributionPoint` with this value.
    distribution_point: Option<Vec<u8>>,
    critical: bool,
    /// The `keyUsage` value of a certificate skeleton.
    key_usage: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct Time {
    year: u8,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

impl Time {
    /// A valid UTCTime, and its Unix time.
    fn utc(&self) -> (Vec<u8>, i64) {
        let yy = i32::from(self.year % 100);
        let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
        let (month, day) = (self.month % 12 + 1, self.day % 28 + 1);
        let (hour, minute, second) = (self.hour % 24, self.minute % 60, self.second % 60);
        let text = format!("{yy:02}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z");
        let at = time::Date::from_calendar_date(year, time::Month::try_from(month).unwrap(), day)
            .unwrap()
            .with_hms(hour, minute, second)
            .unwrap()
            .assume_utc();
        (tlv(0x17, text.as_bytes()), at.unix_timestamp())
    }
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

/// The contents of a name `SEQUENCE`, from a small alphabet.
fn name_contents(n: u8) -> Vec<u8> {
    tlv(0x31, &tlv(0x30, &[0x06, 0x01, n % 4]))
}

fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut ext = tlv(0x06, oid);
    if critical {
        ext.extend(tlv(0x01, &[0xff]));
    }
    ext.extend(tlv(0x04, value));
    tlv(0x30, &ext)
}

/// A signed-object skeleton: `tbs`, an empty algorithm and an empty signature.
fn signed(tbs: &[u8]) -> Vec<u8> {
    let mut body = tlv(0x30, tbs);
    body.extend(tlv(0x30, &[]));
    body.extend(tlv(0x03, &[0]));
    tlv(0x30, &body)
}

/// A certificate skeleton with `extension` as its only extension when given.
fn cert(extension: Option<Vec<u8>>) -> Vec<u8> {
    let time = tlv(0x17, b"300101000000Z");
    let mut tbs = tlv(0xa0, &tlv(0x02, &[2]));
    tbs.extend(tlv(0x02, &[1]));
    tbs.extend(tlv(0x30, &[]));
    tbs.extend(tlv(0x30, &name_contents(0)));
    tbs.extend(tlv(0x30, &[time.clone(), time].concat()));
    tbs.extend(tlv(0x30, &name_contents(1)));
    tbs.extend(tlv(0x30, &[]));
    if let Some(ext) = extension {
        tbs.extend(tlv(0xa3, &tlv(0x30, &ext)));
    }
    signed(&tbs)
}

fn pem(label: &str, der: &[u8]) -> Vec<u8> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN {label}-----\n{b64}\n-----END {label}-----\n").into_bytes()
}

/// Property 1, for bytes that parsed, whose DER is `der`.
fn check_parsed(der: &[u8], parsed: &(Vec<u8>, i64, i64, Option<Vec<u8>>, usize)) -> Option<()> {
    let (issuer, this_update, next_update, number, entries) = parsed;
    let (f_issuer, f_this, f_next, f_number, idp) = crl_facts(der)?;
    assert!(!idp);
    assert!(*entries <= 100_000);
    assert_eq!(issuer.as_slice(), f_issuer);
    assert_eq!((*this_update, *next_update), (f_this, f_next));
    if let Some(n) = number {
        assert!(n.first() != Some(&0), "{n:02x?}");
        let full = f_number.expect("a number without a cRLNumber");
        assert!(full.ends_with(n) && full[..full.len() - n.len()].iter().all(|b| *b == 0));
    } else {
        assert!(f_number.is_none());
    }
    Some(())
}

fuzz_target!(|input: Input| {
    let raw = &input.raw;

    // 1 and 2, on the raw bytes.
    let parsed = crl_parse(raw);
    let _ = crl_facts(raw);
    if raw.first() == Some(&0x30) {
        if let Ok(p) = &parsed {
            check_parsed(raw, p).expect("a parsed CRL whose fields do not read");
        }
        assert_eq!(crl_parse(&pem("X509 CRL", raw)), parsed);
    }
    let with_key = [pem("X509 CRL", raw), pem("PRIVATE KEY", &[1, 2, 3])].concat();
    assert!(crl_parse(&with_key).is_err());

    // 3.
    if let Some((tbs, alg, signature)) = crl_signed_data(raw) {
        assert_eq!(tbs.first(), Some(&0x30));
        assert!(tbs.len() + alg.len() + signature.len() < raw.len());
        let at = raw.windows(tbs.len()).position(|w| w == tbs);
        assert!(at.is_some());
    }

    // 4. A CRL skeleton.
    let (this_tlv, this_secs) = input.this_update.utc();
    let (next_tlv, next_secs) = input.next_update.utc();
    let issuer = name_contents(input.issuer);
    let mut tbs = tlv(0x02, &[1]);
    tbs.extend(tlv(0x30, &[]));
    tbs.extend(tlv(0x30, &issuer));
    tbs.extend(&this_tlv);
    tbs.extend(&next_tlv);
    let revoked: Vec<u8> = input
        .revoked
        .iter()
        .take(16)
        .flat_map(|s| {
            let mut entry = tlv(0x02, &[s % 127 + 1]);
            entry.extend(&this_tlv);
            tlv(0x30, &entry)
        })
        .collect();
    if !revoked.is_empty() {
        tbs.extend(tlv(0x30, &revoked));
    }
    let mut exts = Vec::new();
    if let Some(n) = &input.number {
        exts.extend(extension(&CRL_NUMBER, false, &tlv(0x02, n)));
    }
    if let Some(v) = &input.distribution_point {
        exts.extend(extension(&ISSUING_DISTRIBUTION_POINT, input.critical, v));
    }
    if !exts.is_empty() {
        tbs.extend(tlv(0xa0, &tlv(0x30, &exts)));
    }
    let crl = signed(&tbs);
    let number_ok = input
        .number
        .as_ref()
        .is_none_or(|n| n.first().is_some_and(|b| b & 0x80 == 0));
    match crl_facts(&crl) {
        Some((f_issuer, f_this, f_next, f_number, idp)) => {
            assert!(number_ok);
            assert_eq!(f_issuer, issuer.as_slice());
            assert_eq!((f_this, f_next), (this_secs, next_secs));
            assert_eq!(f_number, input.number.as_deref());
            assert_eq!(idp, input.distribution_point.is_some());
        }
        None => assert!(!number_ok, "a valid CRL skeleton did not read"),
    }
    let parsed = crl_parse(&crl);
    if let Ok(p) = &parsed {
        check_parsed(&crl, p).expect("a parsed CRL whose fields do not read");
        assert_eq!(p.4, input.revoked.len().min(16));
        assert!(input.distribution_point.is_none());
    }
    assert_eq!(crl_parse(&pem("X509 CRL", &crl)), parsed);

    // 5. keyUsage.
    assert!(crl_may_sign(&cert(None)));
    assert!(crl_may_sign(&cert(Some(extension(
        &KEY_USAGE,
        true,
        &[0x03, 0x02, 0x01, 0x06]
    )))));
    assert!(!crl_may_sign(&cert(Some(extension(
        &KEY_USAGE,
        true,
        &[0x03, 0x02, 0x02, 0x04]
    )))));
    let ku = &input.key_usage;
    if crl_may_sign(&cert(Some(extension(&KEY_USAGE, input.critical, ku)))) {
        assert!(ku.len() >= 4 && ku[0] == 0x03, "{ku:02x?}");
        assert!(ku[3] & 0x02 != 0 || ku[1] & 0x80 != 0, "{ku:02x?}");
    }
});
