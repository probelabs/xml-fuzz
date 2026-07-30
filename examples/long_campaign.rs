//! Long structure-aware campaign against the multi-API libxml2 harness.
//!
//! ```sh
//! export XML_FUZZ_LIBXML2_ALL=$PWD/harness/libxml2_all_apis
//! # optional: XML_FUZZ_SECONDS=120 (default), XML_FUZZ_ITERS=N (cap)
//! cargo run --example long_campaign --release
//! ```
//!
//! Loop until deadline: sample a random API, `gen_for_api`, apply mutations,
//! parse via the multi harness. On Timeout, GateFailure, or ASan-like exit,
//! write `crashes/crash-{api}-{seed}.bin` and log the finding.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use xml_fuzz::apis::{gen_for_api, LibXml2Api};
use xml_fuzz::gates;
use xml_fuzz::libxml2_target::LibXml2Options;
use xml_fuzz::{apply_mutations, LibXml2MultiHarness, ParseOutcome, XmlParseTarget};

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn env_opt_usize(key: &str) -> Option<usize> {
    std::env::var(key).ok().and_then(|s| s.parse().ok())
}

fn crashes_dir() -> PathBuf {
    let p = PathBuf::from(
        std::env::var_os("XML_FUZZ_CRASH_DIR").unwrap_or_else(|| "crashes".into()),
    );
    let _ = fs::create_dir_all(&p);
    p
}

fn write_crash(dir: &Path, api: &str, seed: u64, data: &[u8]) -> PathBuf {
    // Sanitize api for filenames (already uses hyphens).
    let name = format!("crash-{api}-{seed}.bin");
    let path = dir.join(&name);
    if let Err(e) = fs::write(&path, data) {
        eprintln!("WARN: failed to write {}: {e}", path.display());
    }
    path
}

/// True when the parse outcome looks like a native abort / ASan finding.
fn is_asan_like(out: &ParseOutcome) -> bool {
    match out {
        ParseOutcome::Rejected { code, text_fingerprint, .. } => {
            let c = code.to_ascii_lowercase();
            let t = text_fingerprint.to_ascii_lowercase();
            c.contains("asan")
                || c.contains("signal=")
                || c.starts_with("signal")
                || t.contains("addresssanitizer")
                || t.contains("error: addresssanitizer")
                || t.contains("undefinedbehavior")
                || t.contains("==error:")
                // Common ASan / abort exit encodings (128+signal): SIGABRT=134, SIGSEGV=139
                || code
                    .strip_prefix("exit=")
                    .and_then(|s| s.parse::<i32>().ok())
                    .map(|n| n == 134 || n == 139 || n == 136 || n >= 128)
                    .unwrap_or(false)
        }
        _ => false,
    }
}

fn main() {
    let seconds = env_u64("XML_FUZZ_SECONDS", 120);
    let max_iters = env_opt_usize("XML_FUZZ_ITERS");
    let deadline = Instant::now() + Duration::from_secs(seconds);

    let bin = std::env::var_os("XML_FUZZ_LIBXML2_ALL")
        .map(PathBuf::from)
        .or_else(|| LibXml2MultiHarness::discover().map(|h| h.binary));
    let Some(bin) = bin else {
        eprintln!("libxml2_all_apis harness not found; set XML_FUZZ_LIBXML2_ALL");
        std::process::exit(2);
    };

    let crash_dir = crashes_dir();
    let fast = std::env::var_os("XML_FUZZ_FAST").is_some()
        || bin.file_name().and_then(|s| s.to_str()).unwrap_or("").contains("_fast");
    eprintln!(
        "long_campaign: harness={} seconds={} max_iters={:?} crashes={} sanitize={}",
        bin.display(),
        seconds,
        max_iters,
        crash_dir.display(),
        if fast { "off(fast)" } else { "asan/unknown" }
    );
    eprintln!("APIs: {}", LibXml2Api::ALL.len());
    if !fast {
        eprintln!(
            "tip: for throughput, build with XML_FUZZ_SANITIZE=0 bash harness/build.sh \\\n     and run with XML_FUZZ_FAST=1 (or XML_FUZZ_LIBXML2_ALL=.../libxml2_all_apis_fast)"
        );
    }

    let mut harness = LibXml2MultiHarness {
        binary: bin,
        api: LibXml2Api::XmlMemory,
        options: LibXml2Options::safe_untrusted(),
    };
    harness.options.recover = true;

    let mut iters: u64 = 0;
    let mut timeouts: u64 = 0;
    let mut findings: u64 = 0;
    let mut ok: u64 = 0;
    let mut per_api: BTreeMap<&'static str, u64> = BTreeMap::new();
    for api in LibXml2Api::ALL {
        per_api.insert(api.as_str(), 0);
    }

    let mut seed_counter: u64 = 0;

    while Instant::now() < deadline {
        if let Some(max) = max_iters {
            if iters as usize >= max {
                break;
            }
        }

        seed_counter = seed_counter.wrapping_add(1);
        let seed = seed_counter;
        let mut rng = StdRng::seed_from_u64(seed);

        // Random API + light option sampling (keep nonet / no_xxe).
        let api = LibXml2Api::sample(&mut rng);
        harness.api = api;
        harness.options = LibXml2Options::sample(&mut rng);
        harness.options.nonet = true;
        harness.options.no_xxe = true;
        if matches!(api, LibXml2Api::XmlPush | LibXml2Api::HtmlPush) {
            harness.options.chunk_size =
                Some([1u32, 7, 17, 64][rng.gen_range(0..4)]);
        }

        let mut data = gen_for_api(&mut rng, api);
        let nmut = rng.gen_range(0..4usize);
        data = apply_mutations(&mut rng, &data, nmut);

        *per_api.entry(api.as_str()).or_insert(0) += 1;
        iters += 1;

        // Gate: no panic / clean fail around the harness call.
        let gate = gates::clean_fail(format!("campaign:{}:{}", api.as_str(), seed), || {
            harness.parse(&data)
        });

        match gate {
            Err(gf) => {
                findings += 1;
                let path = write_crash(&crash_dir, api.as_str(), seed, &data);
                log_finding("GateFailure", api.as_str(), seed, &path, &gf.to_string());
                continue;
            }
            Ok(Err(e)) => {
                findings += 1;
                let path = write_crash(&crash_dir, api.as_str(), seed, &data);
                log_finding("AdapterError", api.as_str(), seed, &path, &e);
                continue;
            }
            Ok(Ok(out)) => {
                if out.is_timeout() {
                    timeouts += 1;
                    findings += 1;
                    let path = write_crash(&crash_dir, api.as_str(), seed, &data);
                    log_finding(
                        "Timeout",
                        api.as_str(),
                        seed,
                        &path,
                        &format!("elapsed_ms={}", out.elapsed_ms()),
                    );
                    continue;
                }
                if is_asan_like(&out) {
                    findings += 1;
                    let path = write_crash(&crash_dir, api.as_str(), seed, &data);
                    log_finding(
                        "ASanLike",
                        api.as_str(),
                        seed,
                        &path,
                        &format!("{out:?}"),
                    );
                    continue;
                }
                ok += 1;
            }
        }

        // Periodic progress on long runs.
        if iters % 50 == 0 {
            let left = deadline
                .saturating_duration_since(Instant::now())
                .as_secs();
            eprintln!(
                "… progress iters={iters} ok={ok} timeouts={timeouts} findings={findings} left≈{left}s"
            );
        }
    }

    println!("=== long_campaign stats ===");
    println!("iters={iters}");
    println!("ok={ok}");
    println!("timeouts={timeouts}");
    println!("findings={findings}");
    println!("seconds_budget={seconds}");
    println!("seed_last={seed_counter}");
    println!("per_api:");
    for (api, n) in &per_api {
        println!("  {api}: {n}");
    }
    println!("crashes_dir={}", crash_dir.display());

    // Non-zero exit only when findings were recorded (timeouts count as findings).
    if findings > 0 {
        std::process::exit(1);
    }
}

fn log_finding(kind: &str, api: &str, seed: u64, path: &Path, detail: &str) {
    eprintln!(
        "FINDING kind={kind} api={api} seed={seed} file={} detail={detail}",
        path.display()
    );
}
