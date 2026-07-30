//! Consumer example: structure-aware XML fuzz loop against the stub parser.
//!
//! ```sh
//! cargo run --example fuzz_loop
//! ```
//!
//! For libxml2, build `harness/libxml2_target` and point an adapter at it
//! (see `harness/README.md`).

use rand::rngs::StdRng;
use rand::SeedableRng;
use xml_fuzz::stub_parser::StubXmlParser;
use xml_fuzz::{self as xfuzz, XmlParseTarget};

fn main() {
    let mut target = StubXmlParser;
    let mut findings = 0usize;
    let mut ok = 0usize;

    // Seed from corpus explicitly (engine would call each_corpus_seed).
    xfuzz::each_corpus_seed(|seed| {
        match xfuzz::run_structure_aware(seed, &mut target) {
            Ok(()) => ok += 1,
            Err(e) => {
                findings += 1;
                eprintln!("FINDING on corpus seed: {e}");
            }
        }
    });

    // Generated work + mutations
    for seed in 0..64u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let doc = xfuzz::gen_document(&mut rng);
        let mut work = xfuzz::apply_mutation(&mut rng, &doc);
        work = xfuzz::apply_mutation(&mut rng, &work);

        // Drive the real target path with fuzzer-produced bytes
        let outcome = target.parse(&work);
        let _ = outcome;

        match xfuzz::run_structure_aware(&work, &mut target) {
            Ok(()) => ok += 1,
            Err(e) => {
                findings += 1;
                eprintln!("FINDING seed={seed}: {e}");
            }
        }
    }

    // Prefer real libxml2 harness when built
    if let Some(mut h) = xml_fuzz::libxml2_target::LibXml2Harness::discover() {
        let sample = b"<?xml version=\"1.0\"?><r>hi</r>";
        match h.parse(sample) {
            Ok(o) => eprintln!("libxml2 harness sample: {o:?}"),
            Err(e) => eprintln!("libxml2 harness error: {e}"),
        }
        for seed in 0..8u64 {
            let mut rng = StdRng::seed_from_u64(seed + 1000);
            let doc = xfuzz::gen_document(&mut rng);
            if let Err(e) = xfuzz::run_structure_aware(&doc, &mut h) {
                findings += 1;
                eprintln!("FINDING libxml2 seed={seed}: {e}");
            } else {
                ok += 1;
            }
        }
    }

    println!(
        "xml_fuzz example complete: ok_iters={ok} findings={findings} corpus={}",
        xfuzz::CORPUS.len()
    );
    if findings > 0 {
        std::process::exit(1);
    }
}
