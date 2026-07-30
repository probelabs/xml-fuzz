//! Proptest strategies: any seed → structure-aware `gen_document` bytes.
//!
//! ```text
//! cargo test --test proptest_strategies
//! ```

use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;
use xml_fuzz::stub_parser::StubXmlParser;
use xml_fuzz::{self as xfuzz, XmlParseTarget};

/// Strategy: map an arbitrary `u64` seed through `StdRng` → `gen_document`.
fn arb_document() -> impl Strategy<Value = Vec<u8>> {
    any::<u64>().prop_map(|seed| {
        let mut rng = StdRng::seed_from_u64(seed);
        xfuzz::gen_document(&mut rng)
    })
}

/// Strategy: seed → gen + one mutation.
fn arb_mutated_document() -> impl Strategy<Value = Vec<u8>> {
    any::<u64>().prop_map(|seed| {
        let mut rng = StdRng::seed_from_u64(seed);
        let doc = xfuzz::gen_document(&mut rng);
        xfuzz::apply_mutation(&mut rng, &doc)
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Generated documents must never panic the stub parser (no_panic gate).
    #[test]
    fn no_panic_on_stub(doc in arb_document()) {
        let target = StubXmlParser;
        xfuzz::gates::no_panic("proptest/stub", || {
            let _ = target.parse(&doc);
        })
        .expect("stub must not panic on generated document");
    }

    /// Mutated documents must likewise be panic-free on the stub.
    #[test]
    fn no_panic_on_stub_mutated(doc in arb_mutated_document()) {
        let target = StubXmlParser;
        xfuzz::gates::no_panic("proptest/stub_mut", || {
            let _ = target.parse(&doc);
        })
        .expect("stub must not panic on mutated document");
    }

    /// Generator always emits at least one byte for any seed.
    #[test]
    fn gen_document_nonempty(seed in any::<u64>()) {
        let mut rng = StdRng::seed_from_u64(seed);
        let doc = xfuzz::gen_document(&mut rng);
        prop_assert!(!doc.is_empty(), "empty document for seed={seed}");
    }
}
