//! `DelegationChain` deserialization + `validate_at` on arbitrary JSON: never panics, and a
//! chain it accepts satisfies the attenuation invariants (checked independently).
#![no_main]

use libfuzzer_sys::fuzz_target;
use onbehalf_core::DelegationChain;

fuzz_target!(|data: &[u8]| {
    let f = onbehalf_fuzz::fixture();
    let Ok(chain) = serde_json::from_slice::<DelegationChain>(data) else {
        return;
    };
    let _ = chain.digest();
    for i in 0..chain.hops.len() + 1 {
        let _ = chain.prefix_digest(i);
    }
    if chain.validate_at(f.now, onbehalf_fuzz::MAX_DEPTH).is_ok() {
        onbehalf_fuzz::assert_chain_sound(&chain, f.now);
        // Round trip: what is accepted re-serializes to the same chain.
        let again: DelegationChain =
            serde_json::from_str(&serde_json::to_string(&chain).unwrap()).unwrap();
        assert_eq!(again, chain);
        assert!(onbehalf_token::ActClaim::from_chain(&chain).is_some());
    }
});
