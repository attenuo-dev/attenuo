//! The hop-0 split rule of SR-121 (`CapabilitySet::attenuate_root`,
//! `AttenuationError::LimitSplit`), on generated grants and requests whose capabilities share
//! patterns, constraints and small limits, so that several requested capabilities often fall
//! under one limited grant capability.
//!
//! Properties beyond "no panic":
//!
//! - `attenuate_root` refuses whenever `attenuate` refuses, with the same error, and otherwise
//!   answers `attenuate`'s set or `LimitSplit`;
//! - on success every capability of the result is covered by the grant, by the very grant
//!   capability it took its limits from;
//! - the split rule, as the code states it: give each requested capability its parent, the
//!   grant capability `attenuate` clamps it to (the first, in canonical order, that covers it
//!   with its limits, else the first that covers its calls). On success, for each grant
//!   capability with limits, the requested capabilities whose parent it is are all clamped to
//!   one and the same capability, so at most one capability of the result carries that grant
//!   capability's limits; and `LimitSplit` is answered exactly when that fails for some
//!   limited grant capability (both checked against `attenuo_fuzz::caps`'s reference, which
//!   is written from the documentation with the pairwise implication only);
//! - the answer does not depend on the order in which the request lists its capabilities
//!   (built from the list in several orders, and read from JSON in reverse order, which keeps
//!   the other copy of capabilities that are equal but spelled differently);
//! - the same answers through the pairwise and the prepared attenuation (the grant padded with
//!   a capability that covers nothing but is too large for the pairwise path).
//!
//! Not covered: SR-128 (security review pass 17), a known open gap. When two limited grant
//! capabilities overlap, a requested capability takes its limits from one of them and is not
//! charged by the other, so "each limited grant capability that covers a result capability's
//! calls bounds at most one result capability" does not hold today. The split rule here is
//! stated per chosen parent, which is what the code promises, so that gap is not reported.
#![no_main]

use std::collections::BTreeMap;

use arbitrary::{Arbitrary, Result, Unstructured};
use attenuo_core::{AttenuationError, Capability, CapabilitySet, Limits};
use attenuo_fuzz::caps::{attenuate_root_ref, caps, covers_ref, padded, parent_of_ref, uses_pad};
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

    // Refuses whenever `attenuate` refuses, with its error; otherwise its set or a split.
    match (&plain, &root) {
        (Err(e), r) => assert_eq!(r.as_ref(), Err(e), "attenuate refused, attenuate_root not"),
        (Ok(a), Ok(b)) => assert_eq!(a, b),
        (Ok(_), Err(AttenuationError::LimitSplit { .. })) => {}
        (Ok(_), Err(e)) => panic!("attenuate accepted, attenuate_root refused with {e:?}"),
    }

    // The split rule, from the requested capabilities and their parents.
    let parents: Vec<&Capability> = grant.iter().collect();
    let mut by_parent: BTreeMap<usize, Vec<Capability>> = BTreeMap::new();
    if plain.is_ok() {
        for c in requested.iter() {
            let i = parent_of_ref(&grant, c).expect("attenuate accepted it, so it has a parent");
            let mut child = c.clone();
            child.limits = Limits::clamp_to(&c.limits, &parents[i].limits);
            by_parent.entry(i).or_default().push(child);
        }
    }
    let split = by_parent.iter().any(|(i, children)| {
        !parents[*i].limits.is_empty() && children.iter().any(|c| *c != children[0])
    });
    match &root {
        Ok(out) => {
            assert!(
                !split,
                "a limited grant capability bounds two result capabilities"
            );
            assert!(grant.covers(out), "result not covered by the grant");
            // Each result capability is one of the clamped requests, under its own parent.
            for (i, children) in &by_parent {
                for c in children {
                    assert!(out.0.contains(c));
                    assert!(covers_ref(parents[*i], c), "not covered by its parent");
                }
                if !parents[*i].limits.is_empty() {
                    let carried = out.iter().filter(|r| children.contains(r)).count();
                    assert!(
                        carried <= 1,
                        "{carried} result capabilities carry grant {i}'s limits"
                    );
                }
            }
            assert_eq!(by_parent.values().flatten().count(), requested.len());
        }
        Err(AttenuationError::LimitSplit { .. }) => assert!(split, "split refused without one"),
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
