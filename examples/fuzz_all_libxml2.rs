//! Drive structure-aware fuzzing against **every** libxml2 multi-API harness mode.
//!
//! ```sh
//! # build harness first
//! cc -O1 -g -I../include -I../.proof/native/libxml2-asan-build \
//!   harness/libxml2_all_apis.c -L../.proof/native/libxml2-asan-build -lxml2 \
//!   -Wl,-rpath,../.proof/native/libxml2-asan-build -o harness/libxml2_all_apis
//! export XML_FUZZ_LIBXML2_ALL=$PWD/harness/libxml2_all_apis
//! cargo run --example fuzz_all_libxml2
//! ```

use xml_fuzz::apis::LibXml2Api;
use xml_fuzz::{fuzz_all_apis, fuzz_one_random_api, LibXml2MultiHarness};

fn main() {
    let bin = std::env::var_os("XML_FUZZ_LIBXML2_ALL")
        .map(std::path::PathBuf::from)
        .or_else(|| LibXml2MultiHarness::discover().map(|h| h.binary));
    let Some(bin) = bin else {
        eprintln!("libxml2_all_apis harness not found; set XML_FUZZ_LIBXML2_ALL");
        std::process::exit(2);
    };
    eprintln!("using harness {}", bin.display());
    eprintln!("APIs: {}", LibXml2Api::ALL.len());

    // Full surface: N iters per API with structure-aware inputs
    let iters: usize = std::env::var("XML_FUZZ_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8);
    if let Err(e) = fuzz_all_apis(&bin, iters) {
        eprintln!("FINDING in fuzz_all_apis: {e}");
        std::process::exit(1);
    }

    // Random API rotation
    let mut h = LibXml2MultiHarness::with_binary(&bin);
    let mut findings = 0;
    for seed in 0..64u64 {
        if let Err(e) = fuzz_one_random_api(&mut h, seed) {
            findings += 1;
            eprintln!("FINDING seed={seed} api={}: {e}", h.api.as_str());
        }
    }

    println!(
        "fuzz_all_libxml2 complete: apis={} iters_per_api={} random=64 findings={findings}",
        LibXml2Api::ALL.len(),
        iters
    );
    if findings > 0 {
        std::process::exit(1);
    }
}
