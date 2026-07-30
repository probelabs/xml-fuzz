//! Integration tests: real consumer path imports the package API.

use rand::rngs::StdRng;
use rand::SeedableRng;
use xml_fuzz::stub_parser::StubXmlParser;
use xml_fuzz::{self as xfuzz, ParseOutcome, XmlParseTarget};

#[test]
fn consumer_generate_mutate_parse() {
    let mut rng = StdRng::seed_from_u64(99);
    let doc = xfuzz::gen_document(&mut rng);
    assert!(!doc.is_empty(), "generator must emit bytes");
    let mutated = xfuzz::apply_mutation(&mut rng, &doc);
    assert!(!mutated.is_empty() || doc.len() < 2);
    let target = StubXmlParser;
    let out = target
        .parse(&mutated)
        .expect("stub parse Result must be Ok wrapper");
    // Outcome is Accepted or Rejected — both fine; must be deterministic
    let out2 = target.parse(&mutated).unwrap();
    assert_eq!(out, out2);
}

#[test]
fn structure_aware_batch() {
    let mut target = StubXmlParser;
    for seed in [0u8, 1, 2, 3, 7, 13, 42, 99] {
        let data = [seed, seed.wrapping_mul(3), 0x3c, 0x61]; // includes '<' 'a'
        xfuzz::run_structure_aware(&data, &mut target).expect("gates must hold on stub");
    }
}

#[test]
fn corpus_drives_parser() {
    let target = StubXmlParser;
    let mut n = 0;
    for entry in xfuzz::corpus_entries() {
        let _ = target.parse(entry.data).unwrap();
        n += 1;
    }
    assert!(n >= 30);
}

#[test]
fn wellformed_and_malformed_generators() {
    let mut rng = StdRng::seed_from_u64(5);
    for _ in 0..20 {
        assert!(!xfuzz::gen_wellformed(&mut rng).is_empty());
        assert!(!xfuzz::gen_malformed(&mut rng).is_empty());
    }
}

#[test]
fn deep_nesting_gate() {
    let target = StubXmlParser;
    let deep = xfuzz::gen_deep_nesting(80, true);
    xfuzz::gates::deep_nesting_safe("deep", &deep, |b| target.parse(b)).unwrap();
}

#[test]
fn mutation_ops_registry_nonempty() {
    assert!(xfuzz::MUTATION_OPS.len() >= 15);
}

#[test]
fn coverage_families_documented() {
    let fams = xfuzz::corpus_families();
    for req in xfuzz::REQUIRED_FAMILIES {
        assert!(fams.contains(req), "missing {req}");
    }
}

#[test]
fn fuzzer_bytes_not_hardcoded_only() {
    // Two seeds must be able to produce different documents (generator path)
    let mut a = StdRng::seed_from_u64(1);
    let mut b = StdRng::seed_from_u64(2);
    let da = xfuzz::gen_document(&mut a);
    let db = xfuzz::gen_document(&mut b);
    // Extremely unlikely identical across full family switch — allow rare collision by retrying
    if da == db {
        let da2 = xfuzz::gen_document(&mut a);
        let db2 = xfuzz::gen_document(&mut b);
        assert_ne!(da2, db2, "generators stuck on single constant document");
    }
}

/// Ensures parse is invoked with fuzzer output (not a fixed fixture only).
#[test]
fn pipeline_gen_mutate_gate() {
    let mut rng = StdRng::seed_from_u64(12345);
    let doc = xfuzz::gen_document(&mut rng);
    let mut work = doc.clone();
    for _ in 0..3 {
        work = xfuzz::apply_mutation(&mut rng, &work);
    }
    let target = StubXmlParser;
    xfuzz::gates::no_panic("pipe", || {
        let r = target.parse(&work).unwrap();
        match r {
            ParseOutcome::Accepted { .. }
            | ParseOutcome::Rejected { .. }
            | ParseOutcome::Timeout { .. } => {}
        }
    })
    .unwrap();
}

#[test]
fn mutation_ops_count_matches_registry() {
    // Honesty: registry length is the source of truth for docs.
    assert_eq!(xfuzz::MUTATION_OPS.len(), 28);
}

#[test]
fn libxml2_harness_optional() {
    if let Some(mut h) = xml_fuzz::libxml2_target::LibXml2Harness::discover() {
        let out = h.parse(b"<?xml version=\"1.0\"?><r>secretbody</r>").unwrap();
        match out {
            ParseOutcome::Accepted {
                text_fingerprint, ..
            } => {
                assert!(
                    text_fingerprint.contains("secretbody"),
                    "harness must expose document text, got {text_fingerprint:?}"
                );
            }
            other => panic!("expected accept, got {other:?}"),
        }
        // push path
        h.options = h.options.clone().with_push();
        let out2 = h.parse(b"<?xml version=\"1.0\"?><r>x</r>").unwrap();
        assert!(matches!(
            out2,
            ParseOutcome::Accepted { .. } | ParseOutcome::Rejected { .. }
        ));
        // reader path (must not silently fall through to memory without mode=reader)
        h.options = xml_fuzz::libxml2_target::LibXml2Options::safe_untrusted().with_reader();
        let out3 = h.parse(b"<?xml version=\"1.0\"?><r>readertext</r>").unwrap();
        match out3 {
            ParseOutcome::Accepted { mode, text_fingerprint, .. } => {
                assert_eq!(mode, "reader");
                assert!(text_fingerprint.contains("readertext"), "{text_fingerprint}");
            }
            ParseOutcome::Rejected { mode, .. } => assert_eq!(mode, "reader"),
            ParseOutcome::Timeout { .. } => {}
        }
        // options sampling in structure-aware loop
        let rng_data = [9u8, 1, 2, 3];
        xfuzz::run_structure_aware(&rng_data, &mut h).expect("libxml2 structure aware");
    }
}

#[test]
fn xxe_policy_matrix_optional() {
    xml_fuzz::xxe_policy::run_xxe_policy_matrix(None).unwrap();
    if let Some(h) = xml_fuzz::libxml2_target::LibXml2Harness::discover() {
        xml_fuzz::xxe_policy::run_xxe_policy_matrix(Some(h.binary.clone())).unwrap();
        xml_fuzz::xxe_policy::assert_fingerprint_detects_noent_leak(Some(h.binary)).unwrap();
    }
}

#[test]
fn all_libxml2_apis_enumerated() {
    assert_eq!(xml_fuzz::LibXml2Api::ALL.len(), 23);
    for a in xml_fuzz::LibXml2Api::ALL {
        let _ = a.as_str();
        let mut rng = StdRng::seed_from_u64(42);
        let _ = xml_fuzz::gen_for_api(&mut rng, *a);
    }
}

#[test]
fn multi_harness_optional_all_apis() {
    if let Some(h) = xml_fuzz::LibXml2MultiHarness::discover() {
        // At least one iter per API — real libxml2 paths
        xml_fuzz::fuzz_all_apis(&h.binary, 2).expect("all APIs structure-aware");
    }
}

#[test]
fn no_etc_passwd_in_generators() {
    let mut rng = StdRng::seed_from_u64(0);
    for _ in 0..40 {
        let d = xfuzz::gen_document(&mut rng);
        let s = String::from_utf8_lossy(&d);
        assert!(
            !s.contains("/etc/passwd"),
            "generator must not emit /etc/passwd"
        );
    }
    for e in xfuzz::corpus_entries() {
        let s = String::from_utf8_lossy(e.data);
        assert!(!s.contains("/etc/passwd"), "corpus {} uses /etc/passwd", e.id);
    }
}

#[test]
fn budget_gate_sync() {
    xfuzz::gates::within_budget_sync("fast", std::time::Duration::from_secs(1), || 1u32).unwrap();
}
