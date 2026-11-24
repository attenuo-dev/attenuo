//! The RFC 9440 header reads of `[server.forwarded_client_cert]` (`forwarded.rs`), through
//! the `fuzzing` feature of attenuo-server, which wraps the server's own functions:
//! `parse_values` (the `Client-Cert` and `Client-Cert-Chain` values to DER) and `parse` (a
//! header map, the repeated-line rule and the DER check). Each runs on raw bytes, and on
//! values built from generated certificates with generated spacing, so that the accepting
//! paths are reached.
//!
//! Properties beyond "no panic":
//!
//! 1. Whatever is accepted is within the caps: at most 4 chain certificates, each non-empty
//!    and at most 16 KiB, at most 64 KiB in all; a chain is never accepted without a leaf.
//! 2. Accepted values have one spelling: encoding what was read again, in the canonical form,
//!    reads back the same certificates.
//! 3. Values built from bytes within the caps, with spaces around the leaf and spaces or tabs
//!    around the commas, read back exactly those bytes; one more chain item is refused.
//! 4. Two `Client-Cert` lines, or two `Client-Cert-Chain` lines, are always refused.
//! 5. Around a whole chain only spaces are allowed (RFC 8941 §4.2.1): the same chain with
//!    spaces before and after reads back the same; with a tab before its first member or
//!    after its last it is refused.
#![no_main]

use arbitrary::Arbitrary;
use attenuo_server::fuzzing::{forwarded_parse_headers, forwarded_parse_values};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use libfuzzer_sys::fuzz_target;

const MAX_INTERMEDIATES: usize = 4;
const MAX_CERT: usize = 16 * 1024;
const MAX_TOTAL: usize = 64 * 1024;

#[derive(Arbitrary, Debug)]
struct Input {
    leaf_raw: Option<Vec<u8>>,
    chain_raw: Option<Vec<u8>>,
    leaf: Vec<u8>,
    chain: Vec<Vec<u8>>,
    /// Spaces around the leaf item, and spaces or tabs around each comma.
    pad: (u8, u8),
    seps: Vec<(u8, u8)>,
    lines: Vec<(bool, Vec<u8>)>,
}

fn item(der: &[u8]) -> String {
    format!(":{}:", STANDARD.encode(der))
}

fn pad(n: u8, tab: bool) -> String {
    let c = if tab { '\t' } else { ' ' };
    std::iter::repeat(c).take(usize::from(n % 4)).collect()
}

fuzz_target!(|input: Input| {
    // 1 and 2, on raw bytes.
    let got = forwarded_parse_values(input.leaf_raw.as_deref(), input.chain_raw.as_deref());
    if input.leaf_raw.is_none() && input.chain_raw.is_some() {
        assert!(got.is_err());
    }
    if let Ok(Some((leaf, chain))) = &got {
        assert!(input.leaf_raw.is_some());
        assert!(chain.len() <= MAX_INTERMEDIATES);
        assert!(!leaf.is_empty() && leaf.len() <= MAX_CERT);
        assert!(chain.iter().all(|c| !c.is_empty() && c.len() <= MAX_CERT));
        assert!(leaf.len() + chain.iter().map(Vec::len).sum::<usize>() <= MAX_TOTAL);
        let leaf_again = item(leaf);
        let chain_again: Vec<String> = chain.iter().map(|c| item(c)).collect();
        let chain_again = chain_again.join(", ");
        let again = forwarded_parse_values(
            Some(leaf_again.as_bytes()),
            input.chain_raw.as_ref().map(|_| chain_again.as_bytes()),
        );
        assert_eq!(again.as_ref().ok(), Some(&Some((leaf.clone(), chain.clone()))));
    }
    if matches!(got, Ok(None)) {
        assert!(input.leaf_raw.is_none() && input.chain_raw.is_none());
    }

    // 3, on built values.
    if !input.leaf.is_empty() && input.leaf.len() <= MAX_CERT {
        let chain: Vec<&Vec<u8>> = input
            .chain
            .iter()
            .filter(|c| !c.is_empty() && c.len() <= MAX_CERT)
            .take(MAX_INTERMEDIATES + 1)
            .collect();
        let leaf_value = format!("{}{}{}", pad(input.pad.0, false), item(&input.leaf), pad(input.pad.1, false));
        let mut chain_value = String::new();
        for (i, c) in chain.iter().enumerate() {
            if i > 0 {
                let (a, b) = input.seps.get(i).copied().unwrap_or((0, 0));
                chain_value += &format!("{},{}", pad(a, a & 4 != 0), pad(b, b & 4 != 0));
            }
            chain_value += &item(c);
        }
        let total = input.leaf.len() + chain.iter().map(|c| c.len()).sum::<usize>();
        let got = forwarded_parse_values(
            Some(leaf_value.as_bytes()),
            (!chain.is_empty()).then_some(chain_value.as_bytes()),
        );
        if chain.len() > MAX_INTERMEDIATES {
            // Refused by its count, or before that by the value's size.
            assert!(matches!(got, Err("too_many_intermediates" | "too_large")), "{got:?}");
        } else if total <= MAX_TOTAL {
            let want: Vec<Vec<u8>> = chain.iter().map(|c| (*c).clone()).collect();
            assert_eq!(got, Ok(Some((input.leaf.clone(), want.clone()))));
            // 5.
            if !chain.is_empty() {
                let spaced = format!("{}{chain_value}{}", pad(input.pad.0, false), pad(input.pad.1, false));
                let got = forwarded_parse_values(Some(leaf_value.as_bytes()), Some(spaced.as_bytes()));
                assert_eq!(got, Ok(Some((input.leaf.clone(), want))));
                for tabbed in [format!("\t{chain_value}"), format!("{chain_value}\t")] {
                    let got = forwarded_parse_values(Some(leaf_value.as_bytes()), Some(tabbed.as_bytes()));
                    assert!(got.is_err(), "{got:?}");
                }
            }
        } else {
            assert_eq!(got, Err("too_large"));
        }
    }

    // 4, on header maps.
    let lines: Vec<(bool, &[u8])> = input
        .lines
        .iter()
        .take(6)
        .map(|(chain, v)| (*chain, v.as_slice()))
        .collect();
    let got = forwarded_parse_headers(&lines);
    let leaf_lines = lines.iter().filter(|(c, v)| !*c && valid_header(v)).count();
    let chain_lines = lines.iter().filter(|(c, v)| *c && valid_header(v)).count();
    if leaf_lines > 1 || chain_lines > 1 {
        assert!(got.is_err());
    }
    if got == Ok(true) {
        assert_eq!(leaf_lines, 1);
    }
});

/// Whether `http` takes `v` as a header value (the wrapper skips the others).
fn valid_header(v: &[u8]) -> bool {
    axum::http::HeaderValue::from_bytes(v).is_ok()
}
