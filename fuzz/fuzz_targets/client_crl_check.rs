//! The CRL check of the TLS client certificate check at authentication (`client_crl.rs` and
//! `client_pki.rs`, ADR-0023), through the `fuzzing` feature of attenuo-server, which wraps the
//! server's own functions: `crl_check` (`client_crl::load` with its `signers`, signature,
//! date and issuer-file checks and the trust anchors' issuers, then `CrlSet::status`,
//! `CrlSet::anchor_status`, and `client_pki::verify`, which runs `path_status` on each path
//! rustls-webpki builds) and `crl_verify_signature`.
//!
//! The certificates and CRLs are real: a root, an intermediate and a client certificate, and a
//! CRL of the root and of the intermediate, each signed here with a fixed Ed25519 key (ring),
//! so that the signatures verify and the paths build. The input chooses the serial numbers,
//! what each CRL lists (with leading zero bytes or not), where the intermediate is (the CA
//! file, the issuer file, both, or only sent by the client), and the two rules. Raw bytes go
//! to `crl_verify_signature` and to `CrlSet::status` as well.
//!
//! Properties beyond "no panic":
//!
//! 1. The files load unless there is no CRL, or the intermediate's CRL has no signer (the
//!    intermediate is in neither file); then they are refused. When the root's CRL revokes the
//!    intermediate, its CRL is ignored: what it issued is `crl_ignored`.
//! 2. `CrlSet::status` answers as a model does: a serial number is listed when it equals a
//!    listed one once leading zero bytes are stripped from both; a CA without a CRL is
//!    `crl_missing` under "refuse", else not refused.
//! 3. `anchor_status`: the root (self-signed) is never refused; the intermediate, when it is a
//!    trust anchor, is refused as the root's CRL says of it.
//! 4. The whole check refuses for revocation exactly as the model of the path says (the
//!    client certificate in the intermediate's CRL, the intermediate in the root's), whether
//!    the path ends at the root or at the intermediate as a trust anchor; with no path, it is
//!    refused for another reason.
//! 5. `crl_verify_signature` is true for the intermediate's certificate under the root's key,
//!    false under another key and once a byte of the signature changes.
#![no_main]

use arbitrary::Arbitrary;
use attenuo_server::fuzzing::{crl_check, crl_verify_signature, CrlEntry};
use base64::Engine as _;
use libfuzzer_sys::fuzz_target;
use ring::signature::{Ed25519KeyPair, KeyPair as _};

const NAME: &str = "spiffe://example.org/a";
/// 2030-01-01T00:00:00Z.
const NOW: i64 = 1_893_456_000;
const ED25519: [u8; 3] = [0x2b, 0x65, 0x70];

#[derive(Arbitrary, Debug)]
struct Input {
    leaf_serial: Vec<u8>,
    mid_serial: Vec<u8>,
    /// The intermediate's CRL lists the client certificate, with this many leading zeros.
    leaf_listed: Option<u8>,
    /// The root's CRL lists the intermediate, with this many leading zeros.
    mid_listed: Option<u8>,
    /// More serial numbers each CRL lists, as encoded.
    root_extra: Vec<Vec<u8>>,
    mid_extra: Vec<Vec<u8>>,
    root_crl: bool,
    mid_crl: bool,
    /// Bit 0: the intermediate in the CA file; bit 1: in the issuer file.
    mid_place: u8,
    send_mid: bool,
    missing_refuse: bool,
    query: Vec<u8>,
    raw_spki: Vec<u8>,
    raw: Vec<u8>,
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

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn alg() -> Vec<u8> {
    seq(&[tlv(0x06, &ED25519)])
}

/// A name `CN=<cn>`, as its `SEQUENCE`.
fn name(cn: &str) -> Vec<u8> {
    seq(&[tlv(
        0x31,
        &seq(&[tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x0c, cn.as_bytes())]),
    )])
}

fn utc(text: &str) -> Vec<u8> {
    tlv(0x17, text.as_bytes())
}

fn spki(key: &Ed25519KeyPair) -> Vec<u8> {
    let mut bits = vec![0];
    bits.extend_from_slice(key.public_key().as_ref());
    seq(&[alg(), tlv(0x03, &bits)])
}

/// The contents of a `SEQUENCE`.
fn contents(der: &[u8]) -> &[u8] {
    let (len_bytes, start) = match der[1] {
        n if n < 0x80 => (usize::from(n), 2),
        n => {
            let k = usize::from(n & 0x7f);
            let len = der[2..2 + k]
                .iter()
                .fold(0usize, |a, b| (a << 8) | usize::from(*b));
            (len, 2 + k)
        }
    };
    &der[start..start + len_bytes]
}

fn signed(tbs: Vec<u8>, key: &Ed25519KeyPair) -> Vec<u8> {
    let mut bits = vec![0];
    bits.extend_from_slice(key.sign(&tbs).as_ref());
    seq(&[tbs, alg(), tlv(0x03, &bits)])
}

fn extension(oid: &[u8], value: Vec<u8>) -> Vec<u8> {
    seq(&[tlv(0x06, oid), tlv(0x01, &[0xff]), tlv(0x04, &value)])
}

/// A certificate: a CA (`basicConstraints` CA, `keyCertSign` and `cRLSign`) or a client
/// certificate for [`NAME`].
fn cert(
    serial: &[u8],
    issuer: &str,
    subject: &str,
    key: &Ed25519KeyPair,
    by: &Ed25519KeyPair,
    ca: bool,
) -> Vec<u8> {
    let exts = if ca {
        vec![
            extension(&[0x55, 0x1d, 0x13], seq(&[tlv(0x01, &[0xff])])),
            extension(&[0x55, 0x1d, 0x0f], tlv(0x03, &[0x01, 0x06])),
        ]
    } else {
        vec![
            extension(
                &[0x55, 0x1d, 0x25],
                seq(&[tlv(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02])]),
            ),
            extension(&[0x55, 0x1d, 0x11], seq(&[tlv(0x86, NAME.as_bytes())])),
        ]
    };
    let tbs = seq(&[
        tlv(0xa0, &tlv(0x02, &[2])),
        tlv(0x02, serial),
        alg(),
        name(issuer),
        seq(&[utc("200101000000Z"), utc("400101000000Z")]),
        name(subject),
        spki(key),
        tlv(0xa3, &seq(&exts)),
    ]);
    signed(tbs, by)
}

/// A CRL of `issuer` listing `serials`, valid around [`NOW`].
fn crl(issuer: &str, by: &Ed25519KeyPair, serials: &[Vec<u8>]) -> Vec<u8> {
    let mut parts = vec![
        tlv(0x02, &[1]),
        alg(),
        name(issuer),
        utc("291231000000Z"),
        utc("300201000000Z"),
    ];
    if !serials.is_empty() {
        let entries: Vec<Vec<u8>> = serials
            .iter()
            .map(|s| seq(&[tlv(0x02, s), utc("291231000000Z")]))
            .collect();
        parts.push(seq(&entries));
    }
    parts.push(tlv(
        0xa0,
        &seq(&[seq(&[
            tlv(0x06, &[0x55, 0x1d, 0x14]),
            tlv(0x04, &tlv(0x02, &[1])),
        ])]),
    ));
    signed(seq(&parts), by)
}

fn pem(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n")
}

/// A serial number for a certificate: 1 to 20 bytes, from the input.
fn serial_of(bytes: &[u8], default: u8) -> Vec<u8> {
    let s: Vec<u8> = bytes.iter().copied().take(20).collect();
    if s.is_empty() {
        vec![default]
    } else {
        s
    }
}

fn stripped(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|b| **b == 0).count();
    &s[n..]
}

fn padded(s: &[u8], zeros: u8) -> Vec<u8> {
    let mut out = vec![0; usize::from(zeros % 4)];
    out.extend_from_slice(s);
    out
}

/// The model's status of serial `serial` against a CA whose CRL, if it has one, lists
/// `listed`.
fn model(listed: Option<&[Vec<u8>]>, serial: &[u8], missing_refuse: bool) -> &'static str {
    match listed {
        Some(l) if l.iter().any(|s| stripped(s) == stripped(serial)) => "certificate_revoked",
        Some(_) => "not_refused",
        None if missing_refuse => "crl_missing",
        None => "not_refused",
    }
}

fn rank(reason: &str) -> u8 {
    match reason {
        "not_refused" => 0,
        "crl_missing" => 1,
        "crl_stale" => 2,
        "crl_ignored" => 3,
        "certificate_revoked" => 4,
        _ => 5,
    }
}

fuzz_target!(|input: Input| {
    let root_key = Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
    let mid_key = Ed25519KeyPair::from_seed_unchecked(&[2; 32]).unwrap();
    let leaf_key = Ed25519KeyPair::from_seed_unchecked(&[3; 32]).unwrap();
    let leaf_serial = serial_of(&input.leaf_serial, 7);
    let mid_serial = serial_of(&input.mid_serial, 2);
    let root = cert(&[1], "root", "root", &root_key, &root_key, true);
    let mid = cert(&mid_serial, "root", "mid", &mid_key, &root_key, true);
    let leaf = cert(&leaf_serial, "mid", "leaf", &leaf_key, &mid_key, false);

    // 5.
    let root_spki = spki(&root_key);
    let mid_spki = spki(&mid_key);
    assert!(crl_verify_signature(contents(&root_spki), &mid));
    assert!(!crl_verify_signature(contents(&mid_spki), &mid));
    let mut broken = mid.clone();
    let last = broken.len() - 1;
    broken[last] ^= 1;
    assert!(!crl_verify_signature(contents(&root_spki), &broken));
    let _ = crl_verify_signature(&input.raw_spki, &input.raw);
    let _ = crl_verify_signature(contents(&root_spki), &input.raw);

    let mut root_lists: Vec<Vec<u8>> = input.root_extra.iter().take(8).cloned().collect();
    if let Some(z) = input.mid_listed {
        root_lists.push(padded(&mid_serial, z));
    }
    let mut mid_lists: Vec<Vec<u8>> = input.mid_extra.iter().take(8).cloned().collect();
    if let Some(z) = input.leaf_listed {
        mid_lists.push(padded(&leaf_serial, z));
    }
    // An empty INTEGER is not one rustls-webpki reads: keep the model to what it reads.
    root_lists.retain(|s| !s.is_empty() && s.len() <= 32);
    mid_lists.retain(|s| !s.is_empty() && s.len() <= 32);
    let mut crls = Vec::new();
    if input.root_crl {
        crls.push(crl("root", &root_key, &root_lists));
    }
    if input.mid_crl {
        crls.push(crl("mid", &mid_key, &mid_lists));
    }
    let in_ca = input.mid_place & 1 != 0;
    let in_issuers = input.mid_place & 2 != 0;
    let ca_pem = if in_ca {
        format!("{}{}", pem(&root), pem(&mid))
    } else {
        pem(&root)
    };
    let issuer_pem = pem(&mid);
    let entry = CrlEntry {
        ca_pem: ca_pem.as_bytes(),
        issuer_pem: in_issuers.then_some(issuer_pem.as_bytes()),
        crls: &crls,
        stale_refuse: true,
        missing_refuse: input.missing_refuse,
        now: NOW,
    };
    let root_subject = contents(&name("root")).to_vec();
    let queries: Vec<(&[u8], &[u8], &[u8])> = vec![
        (&root_subject, contents(&root_spki), &input.query),
        (&root_subject, contents(&mid_spki), &input.query),
    ];
    let chain = if input.send_mid {
        vec![leaf.clone(), mid.clone()]
    } else {
        vec![leaf.clone()]
    };
    let root_listed = input.root_crl.then_some(root_lists.as_slice());
    let mid_listed = input.mid_crl.then_some(mid_lists.as_slice());
    let mid_revoked = model(root_listed, &mid_serial, false) == "certificate_revoked";

    // 1.
    let refused = crls.is_empty() || (input.mid_crl && !in_ca && !in_issuers);
    let mid_ignored = input.mid_crl && mid_revoked;
    let answers = match crl_check(&entry, &queries, &chain, NAME) {
        Ok(a) => {
            assert!(!refused, "loaded: {input:?}");
            a
        }
        Err(e) => {
            assert!(refused, "refused: {e}: {input:?}");
            return;
        }
    };

    // 2.
    assert_eq!(
        answers.statuses[0],
        model(root_listed, &input.query, input.missing_refuse)
    );
    // The root's name with the intermediate's key: a CA with no CRL.
    assert_eq!(
        answers.statuses[1],
        model(None, &input.query, input.missing_refuse)
    );

    // 3.
    assert_eq!(answers.anchors[0], "not_refused");
    if in_ca {
        assert_eq!(
            answers.anchors[1],
            model(root_listed, &mid_serial, input.missing_refuse)
        );
    }

    // 4.
    let leaf_status = if mid_ignored {
        "crl_ignored"
    } else {
        model(mid_listed, &leaf_serial, input.missing_refuse)
    };
    let mid_status = model(root_listed, &mid_serial, input.missing_refuse);
    let want = if rank(leaf_status) >= rank(mid_status) {
        leaf_status
    } else {
        mid_status
    };
    if input.send_mid || in_ca {
        let expected = if want == "not_refused" {
            Ok(())
        } else {
            Err(want)
        };
        assert_eq!(answers.verify, expected, "{input:?}");
    } else {
        assert!(answers.verify.is_err());
        assert!(answers.verify != Err("certificate_revoked"));
    }
});
