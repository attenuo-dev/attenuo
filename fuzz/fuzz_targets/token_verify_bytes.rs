//! `Verifier::verify` on arbitrary bytes: never panics, and accepts nothing it was not issued.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let f = attenuo_fuzz::fixture();
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(v) = f.verifier.verify(token, f.now) {
        // Random bytes cannot carry a valid Ed25519 signature, so whatever verifies was minted
        // by the fixture's issuer (the seed corpus holds one such token; its `jti` and leases
        // differ per run) and must look like it.
        assert_eq!(v.claims.iss, attenuo_fuzz::ISS);
        assert_eq!(v.claims.aud, attenuo_fuzz::AUD);
        assert_eq!(v.claims.chain.originating_user.subject, "user:mudit");
        attenuo_fuzz::assert_chain_sound(&v.chain, f.now);
    }
});
