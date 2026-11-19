//! The hop-0 rules of SR-121 and SR-128 (`CapabilitySet::attenuate_root`,
//! `AttenuationError::LimitSplit` and `LimitConflict`), on generated grants and requests whose
//! capabilities share patterns, constraints and small limits, so that several requested
//! capabilities often fall under one limited grant capability, and one requested capability
//! often under several.
//!
//! Properties beyond "no panic":
//!
//! - `attenuate_root` refuses whenever `attenuate` refuses, with the same error, and otherwise
//!   answers a set with `attenuate`'s capabilities (the same patterns and constraints, limits
//!   possibly lower), `LimitSplit` or `LimitConflict`;
//! - on success every capability of the result is covered by the grant, and its limits are
//!   within those of every grant capability that covers its calls;
//! - the split rule of SR-128: each limited grant capability that covers a result capability's
//!   calls covers the calls of at most one result capability, and that capability's limits
//!   are within it. Computed here from the requested capabilities, the grant capabilities
//!   over each (by the pairwise coverage relation) and `attenuo_fuzz::caps::clamp_to_all_ref`:
//!   `LimitSplit` is answered only when two requested capabilities under one limited grant
//!   capability give different results, `LimitConflict` only when one capability cannot carry
//!   the limits over it, and success only when neither happens; the whole answer is also
//!   checked against `attenuo_fuzz::caps::attenuate_root_ref`, written from the documentation
//!   with the pairwise implication only;
//! - with no limited grant capability over any requested one, the answer is `attenuate`'s;
//! - the answer does not depend on the order in which the request lists its capabilities
//!   (built from the list in several orders, and read from JSON in reverse order, which keeps
//!   the other copy of capabilities that are equal but spelled differently);
//! - the same answers through the pairwise and the prepared attenuation (the grant padded with
//!   a capability that covers nothing but is too large for the pairwise path).
//!
//! Not covered, by design (SR-128's scope): a limited grant capability that only overlaps a
//! requested capability (neither covers the other's calls) bounds nothing at hop 0, and the
//! properties above do not claim it does.
#![no_main]

use std::collections::BTreeMap;

use arbitrary::{Arbitrary, Result, Unstructured};
use attenuo_core::{AttenuationError, Capability, CapabilitySet, Limits};
use attenuo_fuzz::caps::{
    attenuate_root_ref, caps, clamp_to_all_ref, covers_calls_ref, limited_over_ref, padded,
    uses_pad,
};
use libfuzzer_sys::fuzz_target;

#[derive(Debug)]
struct Input {
    grant: CapabilitySet,
    request: Vec<Capability>,
    orders: Vec<Vec<usize>>,
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let grant: Vec<Capability> = caps(u, 4, 12)?;
        let mut request = Vec::new();
        for _ in 0..u.int_in_range(0..=5)? {
            // Mostly a grant capability, narrowed or with its own limits: the shapes that
            // share a parent.
            if !grant.is_empty() && u.ratio(2u8, 3u8)? {
                let mut c = grant[u.choose_index(grant.len())?].clone();
                match u.int_in_range(0u8..=3)? {
                    0 => {}
                    1 => c.limits = attenuo_fuzz::caps::limits(u)?,
                    2 => {
                        c.constraints.insert(
                            (*u.choose(attenuo_fuzz::caps::ARGS)?).to_string(),
                            attenuo_fuzz::caps::constraint(u, 12)?,
                        );
                    }
                    _ => {
                        c.tool = attenuo_fuzz::caps::name(u)?;
                    }
                }
                request.push(c);
            } else {
                request.push(attenuo_fuzz::caps::capability(u, 12)?);
            }
        }
        let mut orders = Vec::new();
        for _ in 0..2 {
            let mut idx: Vec<usize> = (0..request.len()).collect();
            for i in (1..idx.len()).rev() {
                let j = u.int_in_range(0..=i)?;
                idx.swap(i, j);
            }
            orders.push(idx);
        }
        Ok(Input {
            grant: grant.into_iter().collect(),
            request,
            orders,
        })
    }
}

fn same_kind(a: &Result2, b: &Result2) -> bool {
    match (a, b) {
        (Ok(x), Ok(y)) => x == y,
        (Err(x), Err(y)) => std::mem::discriminant(x) == std::mem::discriminant(y),
        _ => false,
    }
}

type Result2 = std::result::Result<CapabilitySet, AttenuationError>;

fuzz_target!(|input: Input| {
    let Input {
        grant,
        request,
        orders,
    } = input;
    let requested: CapabilitySet = request.iter().cloned().collect();
    if uses_pad(&requested) {
        return;
    }
    let plain = grant.attenuate(&requested);
    let root = grant.attenuate_root(&requested);

    // Refuses whenever `attenuate` refuses, with its error; otherwise a set, a split or a
    // conflict.
    match (&plain, &root) {
        (Err(e), r) => assert_eq!(r.as_ref(), Err(e), "attenuate refused, attenuate_root not"),
        (Ok(_), Ok(_))
        | (Ok(_), Err(AttenuationError::LimitSplit { .. }))
        | (Ok(_), Err(AttenuationError::LimitConflict { .. })) => {}
        (Ok(_), Err(e)) => panic!("attenuate accepted, attenuate_root refused with {e:?}"),
    }

    // The rule, from the requested capabilities and the limited grant capabilities over each.
    let parents: Vec<&Capability> = grant.iter().collect();
    let mut under: BTreeMap<usize, Vec<Capability>> = BTreeMap::new();
    let mut conflict = false;
    let mut none_over = true;
    if plain.is_ok() {
        for c in requested.iter() {
            let over = limited_over_ref(&grant, c);
            none_over &= over.is_empty();
            let limits: Vec<&Limits> = over.iter().map(|&i| &parents[i].limits).collect();
            match clamp_to_all_ref(&c.limits, &limits) {
                None => conflict = true,
                Some(l) => {
                    for &i in &over {
                        under.entry(i).or_default().push(Capability {
                            limits: l.clone(),
                            ..c.clone()
                        });
                    }
                }
            }
        }
    }
    let split = under
        .values()
        .any(|children| children.iter().any(|c| *c != children[0]));
    let calls = |s: &CapabilitySet| -> std::collections::BTreeSet<Capability> {
        s.iter()
            .map(|c| Capability {
                limits: Limits::default(),
                ..c.clone()
            })
            .collect()
    };
    match &root {
        Ok(out) => {
            assert!(
                !split,
                "two requested capabilities under one limited grant capability"
            );
            assert!(
                !conflict,
                "limits one capability cannot carry were accepted"
            );
            assert!(grant.covers(out), "result not covered by the grant");
            assert_eq!(
                calls(out),
                calls(plain.as_ref().unwrap()),
                "not attenuate's capabilities"
            );
            for c in out.iter() {
                for p in parents.iter().filter(|p| covers_calls_ref(p, c)) {
                    assert!(
                        c.limits.narrows(&p.limits),
                        "a result capability's limits are not within a grant capability over it"
                    );
                }
            }
            for p in parents.iter().filter(|p| !p.limits.is_empty()) {
                let n = out.iter().filter(|c| covers_calls_ref(p, c)).count();
                assert!(
                    n <= 1,
                    "{n} result capabilities under one limited grant capability"
                );
            }
            if none_over {
                assert_eq!(
                    &root, &plain,
                    "no limit over the request, yet not attenuate's"
                );
            }
        }
        Err(AttenuationError::LimitSplit { .. }) => assert!(split, "split refused without one"),
        Err(AttenuationError::LimitConflict { .. }) => {
            assert!(conflict, "conflict refused without one")
        }
        Err(_) => {}
    }

    // The reference, and the prepared path.
    assert_eq!(
        root,
        attenuate_root_ref(&grant, &requested),
        "reference disagrees"
    );
    assert_eq!(
        padded(&grant).attenuate_root(&requested),
        root,
        "prepared path disagrees"
    );

    // Independent of the order the request lists its capabilities.
    for order in &orders {
        let again: CapabilitySet = order.iter().map(|&i| request[i].clone()).collect();
        assert!(
            same_kind(&grant.attenuate_root(&again), &root),
            "order changed the answer"
        );
    }
    let reversed: Vec<&Capability> = request.iter().rev().collect();
    if let Ok(text) = serde_json::to_string(&reversed) {
        if let Ok(read) = serde_json::from_str::<CapabilitySet>(&text) {
            assert_eq!(read, requested);
            assert!(
                same_kind(&grant.attenuate_root(&read), &root),
                "reading the request in another order changed the answer"
            );
        }
    }
});
