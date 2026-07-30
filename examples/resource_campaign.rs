//! Resource-aware campaign: **persistent worker** measures RSS/CPU/threads/FDs.
//!
//! ## Parallelism policy (measurement-first)
//!
//! - **Default `XML_FUZZ_WORKERS=1`**: one long-lived process, serial jobs.
//!   RSS growth and per-job `rss_delta_kb` are trustworthy (no sibling noise).
//! - **`XML_FUZZ_WORKERS=N` (N>1)**: N **isolated processes**, each owned by its
//!   own thread. Jobs never share a process, so each worker's RSS baseline stays
//!   independent. Host CPU contention can still inflate `elapsed_ms` / CPU
//!   deltas — use `XML_FUZZ_MEASURE=1` to compare 1 vs N before long campaigns.
//!
//! ```sh
//! bash harness/build.sh
//! export XML_FUZZ_LIBXML2_ALL=$PWD/harness/libxml2_all_apis
//! # accurate leak/growth (recommended default)
//! XML_FUZZ_SECONDS=60 cargo run --example resource_campaign --release
//! # contention probe: fixed seed budget, 1 then N workers, print stats
//! XML_FUZZ_MEASURE=1 XML_FUZZ_WORKERS=4 XML_FUZZ_ITERS=200 \
//!   cargo run --example resource_campaign --release
//! # throughput mode after measure looks clean
//! XML_FUZZ_WORKERS=4 XML_FUZZ_SECONDS=60 cargo run --example resource_campaign --release
//! ```

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use xml_fuzz::apis::{gen_for_api, LibXml2Api};
use xml_fuzz::apply_mutations;
use xml_fuzz::libxml2_target::LibXml2Options;
use xml_fuzz::resource::{
    check_resource, discover_multi_harness, ResourceBudgets, ResourceSample, ResourceWorker,
};

#[derive(Clone)]
struct Job {
    seed: u64,
    api: LibXml2Api,
    opts: LibXml2Options,
    data: Vec<u8>,
}

fn make_job(seed: u64) -> Job {
    let mut rng = StdRng::seed_from_u64(seed);
    let api = LibXml2Api::sample(&mut rng);
    let mut opts = LibXml2Options::sample(&mut rng);
    opts.nonet = true;
    opts.no_xxe = true;
    opts.recover = true;
    if matches!(api, LibXml2Api::XmlPush | LibXml2Api::HtmlPush) {
        opts.chunk_size = Some([1u32, 7, 17, 64][rng.gen_range(0..4)]);
    }
    let mut data = gen_for_api(&mut rng, api);
    let n_mut = rng.gen_range(0..3);
    data = apply_mutations(&mut rng, &data, n_mut);
    Job {
        seed,
        api,
        opts,
        data,
    }
}

#[derive(Default, Clone)]
struct Agg {
    iters: u64,
    ok: u64,
    findings: u64,
    worker_errs: u64,
    peak_rss: i64,
    sum_rss_delta: i64,
    sum_rss_delta_sq: i64,
    sum_elapsed: i64,
    sum_cpu: i64,
    max_threads: i64,
    max_fds: i64,
    base_rss: i64,
}

impl Agg {
    fn observe(&mut self, s: &ResourceSample) {
        if s.rss_kb > self.peak_rss {
            self.peak_rss = s.rss_kb;
        }
        self.sum_rss_delta += s.rss_delta_kb;
        self.sum_rss_delta_sq += s.rss_delta_kb * s.rss_delta_kb;
        self.sum_elapsed += s.elapsed_ms;
        self.sum_cpu += s.cpu_total_ms();
        if s.threads > self.max_threads {
            self.max_threads = s.threads;
        }
        if s.fds > self.max_fds {
            self.max_fds = s.fds;
        }
    }

    fn mean_rss_delta(&self) -> f64 {
        if self.ok == 0 {
            return 0.0;
        }
        self.sum_rss_delta as f64 / self.ok as f64
    }

    fn std_rss_delta(&self) -> f64 {
        if self.ok < 2 {
            return 0.0;
        }
        let n = self.ok as f64;
        let mean = self.mean_rss_delta();
        let var = (self.sum_rss_delta_sq as f64 / n) - mean * mean;
        var.max(0.0).sqrt()
    }

    fn mean_elapsed(&self) -> f64 {
        if self.ok == 0 {
            return 0.0;
        }
        self.sum_elapsed as f64 / self.ok as f64
    }

    fn mean_cpu(&self) -> f64 {
        if self.ok == 0 {
            return 0.0;
        }
        self.sum_cpu as f64 / self.ok as f64
    }
}

fn run_serial(
    bin: &Path,
    jobs: &[Job],
    budgets: &ResourceBudgets,
    crash_dir: &Path,
) -> Agg {
    let mut worker = ResourceWorker::spawn(bin).expect("spawn worker");
    let mut agg = Agg {
        base_rss: worker.base_rss_kb,
        peak_rss: worker.base_rss_kb,
        ..Default::default()
    };
    for job in jobs {
        agg.iters += 1;
        match worker.job(job.api, &job.opts, &job.data) {
            Err(e) => {
                agg.findings += 1;
                agg.worker_errs += 1;
                let path = crash_dir.join(format!(
                    "crash-worker-err-{}-{}.bin",
                    job.api.as_str(),
                    job.seed
                ));
                let _ = fs::write(&path, &job.data);
                eprintln!(
                    "FINDING worker_err api={} seed={}: {e} path={}",
                    job.api.as_str(),
                    job.seed,
                    path.display()
                );
            }
            Ok(s) => {
                agg.observe(&s);
                if let Err(gf) = check_resource(
                    format!("res:{}:{}", job.api.as_str(), job.seed),
                    budgets,
                    agg.base_rss,
                    &s,
                ) {
                    agg.findings += 1;
                    let path = crash_dir.join(format!(
                        "crash-resource-{}-{}.bin",
                        job.api.as_str(),
                        job.seed
                    ));
                    let _ = fs::write(&path, &job.data);
                    eprintln!(
                        "FINDING resource api={} seed={}: {gf} sample={s:?} path={}",
                        job.api.as_str(),
                        job.seed,
                        path.display()
                    );
                } else {
                    agg.ok += 1;
                }
            }
        }
    }
    worker.quit();
    agg
}

/// N isolated workers, each pinned to a thread. Jobs are strip-assigned so
/// load is balanced; no two threads share a process (RSS domains stay pure).
fn run_isolated_parallel(
    bin: &Path,
    jobs: &[Job],
    n_workers: usize,
    budgets: &ResourceBudgets,
    crash_dir: &Path,
) -> Agg {
    let n_workers = n_workers.max(1);
    if n_workers == 1 {
        return run_serial(bin, jobs, budgets, crash_dir);
    }

    let jobs = Arc::new(jobs.to_vec());
    let budgets = Arc::new(budgets.clone());
    let crash_dir = Arc::new(crash_dir.to_path_buf());
    let findings_log = Arc::new(Mutex::new(Vec::<String>::new()));
    let counter = Arc::new(AtomicU64::new(0));

    let handles: Vec<_> = (0..n_workers)
        .map(|wid| {
            let bin = bin.to_path_buf();
            let jobs = Arc::clone(&jobs);
            let budgets = Arc::clone(&budgets);
            let crash_dir = Arc::clone(&crash_dir);
            let findings_log = Arc::clone(&findings_log);
            let counter = Arc::clone(&counter);
            thread::spawn(move || {
                let mut worker = ResourceWorker::spawn(&bin).expect("spawn worker");
                let mut local = Agg {
                    base_rss: worker.base_rss_kb,
                    peak_rss: worker.base_rss_kb,
                    ..Default::default()
                };
                // Strip schedule: worker wid takes jobs wid, wid+N, ...
                let mut i = wid;
                while i < jobs.len() {
                    let job = &jobs[i];
                    local.iters += 1;
                    let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
                    if n % 100 == 0 {
                        eprintln!("… parallel progress jobs_done≈{n}/{}", jobs.len());
                    }
                    match worker.job(job.api, &job.opts, &job.data) {
                        Err(e) => {
                            local.findings += 1;
                            local.worker_errs += 1;
                            let path = crash_dir.join(format!(
                                "crash-worker-err-{}-{}.bin",
                                job.api.as_str(),
                                job.seed
                            ));
                            let _ = fs::write(&path, &job.data);
                            if let Ok(mut g) = findings_log.lock() {
                                g.push(format!(
                                    "worker_err api={} seed={}: {e}",
                                    job.api.as_str(),
                                    job.seed
                                ));
                            }
                        }
                        Ok(s) => {
                            local.observe(&s);
                            // Growth vs *this* worker's base, not a global base.
                            if let Err(gf) = check_resource(
                                format!("res:{}:{}", job.api.as_str(), job.seed),
                                &budgets,
                                local.base_rss,
                                &s,
                            ) {
                                local.findings += 1;
                                let path = crash_dir.join(format!(
                                    "crash-resource-{}-{}.bin",
                                    job.api.as_str(),
                                    job.seed
                                ));
                                let _ = fs::write(&path, &job.data);
                                if let Ok(mut g) = findings_log.lock() {
                                    g.push(format!(
                                        "resource api={} seed={}: {gf}",
                                        job.api.as_str(),
                                        job.seed
                                    ));
                                }
                            } else {
                                local.ok += 1;
                            }
                        }
                    }
                    i += n_workers;
                }
                worker.quit();
                local
            })
        })
        .collect();

    let mut agg = Agg::default();
    for h in handles {
        let local = h.join().expect("worker thread");
        if agg.base_rss <= 0 {
            agg.base_rss = local.base_rss;
        }
        agg.iters += local.iters;
        agg.ok += local.ok;
        agg.findings += local.findings;
        agg.worker_errs += local.worker_errs;
        if local.peak_rss > agg.peak_rss {
            agg.peak_rss = local.peak_rss;
        }
        agg.sum_rss_delta += local.sum_rss_delta;
        agg.sum_rss_delta_sq += local.sum_rss_delta_sq;
        agg.sum_elapsed += local.sum_elapsed;
        agg.sum_cpu += local.sum_cpu;
        if local.max_threads > agg.max_threads {
            agg.max_threads = local.max_threads;
        }
        if local.max_fds > agg.max_fds {
            agg.max_fds = local.max_fds;
        }
    }
    if let Ok(log) = findings_log.lock() {
        for line in log.iter().take(20) {
            eprintln!("FINDING {line}");
        }
        if log.len() > 20 {
            eprintln!("… {} more findings", log.len() - 20);
        }
    }
    agg
}

fn print_agg(label: &str, wall_s: f64, agg: &Agg, workers: usize) {
    let rps = if wall_s > 0.0 {
        agg.iters as f64 / wall_s
    } else {
        0.0
    };
    println!("=== {label} ===");
    println!("workers={workers}");
    println!("wall_s={wall_s:.3}");
    println!("iters={}", agg.iters);
    println!("ok={}", agg.ok);
    println!("findings={}", agg.findings);
    println!("worker_errs={}", agg.worker_errs);
    println!("rps={rps:.1}");
    println!("base_rss_kb={}", agg.base_rss);
    println!("peak_rss_kb={}", agg.peak_rss);
    println!(
        "rss_growth_kb={}",
        if agg.base_rss >= 0 && agg.peak_rss >= 0 {
            agg.peak_rss - agg.base_rss
        } else {
            -1
        }
    );
    println!("mean_rss_delta_kb={:.1}", agg.mean_rss_delta());
    println!("std_rss_delta_kb={:.1}", agg.std_rss_delta());
    println!("mean_elapsed_ms={:.2}", agg.mean_elapsed());
    println!("mean_cpu_ms={:.2}", agg.mean_cpu());
    println!("max_threads={}", agg.max_threads);
    println!("max_fds={}", agg.max_fds);
}

fn host_snapshot() -> String {
    let mut load = String::from("?");
    if let Ok(s) = fs::read_to_string("/proc/loadavg") {
        load = s.split_whitespace().take(3).collect::<Vec<_>>().join(" ");
    }
    let mut mem = String::from("?");
    if let Ok(s) = fs::read_to_string("/proc/meminfo") {
        let mut avail = None;
        let mut total = None;
        for line in s.lines() {
            if let Some(v) = line.strip_prefix("MemAvailable:") {
                avail = v.split_whitespace().next().map(|x| x.to_string());
            }
            if let Some(v) = line.strip_prefix("MemTotal:") {
                total = v.split_whitespace().next().map(|x| x.to_string());
            }
        }
        mem = format!(
            "avail_kb={} total_kb={}",
            avail.unwrap_or_else(|| "?".into()),
            total.unwrap_or_else(|| "?".into())
        );
    }
    format!("loadavg=[{load}] mem=[{mem}]")
}

fn main() {
    let seconds: u64 = std::env::var("XML_FUZZ_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let workers_n: usize = std::env::var("XML_FUZZ_WORKERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
        .max(1);
    let max_iters: Option<u64> = std::env::var("XML_FUZZ_ITERS")
        .ok()
        .and_then(|s| s.parse().ok());
    let measure = std::env::var_os("XML_FUZZ_MEASURE").is_some();

    let bin = std::env::var_os("XML_FUZZ_LIBXML2_ALL")
        .map(PathBuf::from)
        .or_else(discover_multi_harness);
    let Some(bin) = bin else {
        eprintln!("set XML_FUZZ_LIBXML2_ALL to multi-API harness (with --worker support)");
        std::process::exit(2);
    };

    let crash_dir = PathBuf::from(
        std::env::var_os("XML_FUZZ_CRASH_DIR").unwrap_or_else(|| "crashes".into()),
    );
    let _ = fs::create_dir_all(&crash_dir);

    let asan = !bin
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .contains("_fast");
    let budgets = if asan {
        ResourceBudgets::for_asan()
    } else {
        ResourceBudgets::default()
    };

    eprintln!(
        "resource_campaign: harness={} workers={} measure={} budgets={{max_rss_kb={:?}, max_growth={:?}, max_delta={:?}}} crashes={}",
        bin.display(),
        workers_n,
        measure,
        budgets.max_rss_kb,
        budgets.max_rss_growth_kb,
        budgets.max_rss_delta_kb,
        crash_dir.display()
    );
    eprintln!("host: {}", host_snapshot());
    eprintln!(
        "policy: each worker is an isolated process; parallel mode uses one thread per worker \
         (no shared RSS baseline). Prefer workers=1 when hunting slow leaks."
    );

    // ---- measure mode: same job list, serial vs N ----
    if measure {
        let n = max_iters.unwrap_or(200) as usize;
        let jobs: Vec<Job> = (1..=n as u64).map(make_job).collect();
        eprintln!("measure: fixed {} jobs, run serial then workers={}", n, workers_n);

        let t0 = Instant::now();
        let serial = run_serial(&bin, &jobs, &budgets, &crash_dir);
        let serial_s = t0.elapsed().as_secs_f64();
        print_agg("measure/serial workers=1", serial_s, &serial, 1);

        let t1 = Instant::now();
        let parallel = run_isolated_parallel(&bin, &jobs, workers_n, &budgets, &crash_dir);
        let parallel_s = t1.elapsed().as_secs_f64();
        print_agg(
            &format!("measure/parallel workers={workers_n}"),
            parallel_s,
            &parallel,
            workers_n,
        );

        let speedup = if parallel_s > 0.0 {
            serial_s / parallel_s
        } else {
            0.0
        };
        let delta_std_ratio = if serial.std_rss_delta() > 1.0 {
            parallel.std_rss_delta() / serial.std_rss_delta()
        } else {
            1.0
        };
        let elapsed_ratio = if serial.mean_elapsed() > 0.0 {
            parallel.mean_elapsed() / serial.mean_elapsed()
        } else {
            1.0
        };

        println!("=== measure/verdict ===");
        println!("speedup={speedup:.2}x");
        println!("rss_delta_std_ratio={delta_std_ratio:.2} (1.0 = same noise)");
        println!("mean_elapsed_ratio={elapsed_ratio:.2} (>1 means host contention inflates wall per job)");
        println!("host_after: {}", host_snapshot());
        // Soft guidance only — do not fail the process on ratios.
        if delta_std_ratio > 2.0 || elapsed_ratio > 1.5 {
            println!(
                "verdict=CAUTION: multi-worker noise/contention elevated; keep workers=1 for leak oracles"
            );
        } else if speedup < 1.2 && workers_n > 1 {
            println!("verdict=MARGINAL: little speedup; prefer workers=1 for clarity");
        } else {
            println!(
                "verdict=OK: isolated multi-worker looks usable for throughput (still serial-per-process RSS)"
            );
        }

        if serial.findings + parallel.findings > 0 {
            std::process::exit(1);
        }
        return;
    }

    // ---- timed campaign: keep workers alive the whole run (leak/growth needs that) ----
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let target_iters = max_iters.unwrap_or(u64::MAX);
    let t0 = Instant::now();
    let mut per_api: BTreeMap<&'static str, u64> = BTreeMap::new();

    let total = if workers_n == 1 {
        let mut worker = ResourceWorker::spawn(&bin).expect("spawn worker");
        let mut agg = Agg {
            base_rss: worker.base_rss_kb,
            peak_rss: worker.base_rss_kb,
            ..Default::default()
        };
        let mut seed = 0u64;
        while Instant::now() < deadline && agg.iters < target_iters {
            seed += 1;
            let job = make_job(seed);
            *per_api.entry(job.api.as_str()).or_insert(0) += 1;
            agg.iters += 1;
            match worker.job(job.api, &job.opts, &job.data) {
                Err(e) => {
                    agg.findings += 1;
                    agg.worker_errs += 1;
                    let path = crash_dir.join(format!(
                        "crash-worker-err-{}-{}.bin",
                        job.api.as_str(),
                        job.seed
                    ));
                    let _ = fs::write(&path, &job.data);
                    eprintln!(
                        "FINDING worker_err api={} seed={}: {e}",
                        job.api.as_str(),
                        job.seed
                    );
                }
                Ok(s) => {
                    agg.observe(&s);
                    if let Err(gf) = check_resource(
                        format!("res:{}:{}", job.api.as_str(), job.seed),
                        &budgets,
                        agg.base_rss,
                        &s,
                    ) {
                        agg.findings += 1;
                        let path = crash_dir.join(format!(
                            "crash-resource-{}-{}.bin",
                            job.api.as_str(),
                            job.seed
                        ));
                        let _ = fs::write(&path, &job.data);
                        eprintln!(
                            "FINDING resource api={} seed={}: {gf} sample={s:?}",
                            job.api.as_str(),
                            job.seed
                        );
                    } else {
                        agg.ok += 1;
                    }
                }
            }
            if agg.iters % 100 == 0 {
                let left = deadline.saturating_duration_since(Instant::now()).as_secs();
                eprintln!(
                    "… iters={} ok={} findings={} peak_rss_kb={} left≈{left}s",
                    agg.iters, agg.ok, agg.findings, agg.peak_rss
                );
            }
        }
        worker.quit();
        agg
    } else {
        // Long-lived isolated workers: each thread pulls from a shared job stream
        // until deadline / iter budget. RSS growth is still per-process.
        let next_seed = Arc::new(AtomicU64::new(1));
        let stop_iters = Arc::new(AtomicU64::new(0));
        let findings_log = Arc::new(Mutex::new(Vec::<String>::new()));
        let api_counts = Arc::new(Mutex::new(BTreeMap::<&'static str, u64>::new()));
        let deadline_t = deadline;
        let target = target_iters;
        let bin = bin.clone();
        let budgets = budgets.clone();
        let crash_dir = crash_dir.clone();

        let handles: Vec<_> = (0..workers_n)
            .map(|_| {
                let next_seed = Arc::clone(&next_seed);
                let stop_iters = Arc::clone(&stop_iters);
                let findings_log = Arc::clone(&findings_log);
                let api_counts = Arc::clone(&api_counts);
                let bin = bin.clone();
                let budgets = budgets.clone();
                let crash_dir = crash_dir.clone();
                thread::spawn(move || {
                    let mut worker = ResourceWorker::spawn(&bin).expect("spawn worker");
                    let mut local = Agg {
                        base_rss: worker.base_rss_kb,
                        peak_rss: worker.base_rss_kb,
                        ..Default::default()
                    };
                    loop {
                        if Instant::now() >= deadline_t {
                            break;
                        }
                        let done = stop_iters.fetch_add(1, Ordering::Relaxed);
                        if done >= target {
                            break;
                        }
                        let seed = next_seed.fetch_add(1, Ordering::Relaxed);
                        let job = make_job(seed);
                        if let Ok(mut g) = api_counts.lock() {
                            *g.entry(job.api.as_str()).or_insert(0) += 1;
                        }
                        local.iters += 1;
                        match worker.job(job.api, &job.opts, &job.data) {
                            Err(e) => {
                                local.findings += 1;
                                local.worker_errs += 1;
                                let path = crash_dir.join(format!(
                                    "crash-worker-err-{}-{}.bin",
                                    job.api.as_str(),
                                    job.seed
                                ));
                                let _ = fs::write(&path, &job.data);
                                if let Ok(mut g) = findings_log.lock() {
                                    g.push(format!(
                                        "worker_err api={} seed={}: {e}",
                                        job.api.as_str(),
                                        job.seed
                                    ));
                                }
                            }
                            Ok(s) => {
                                local.observe(&s);
                                if let Err(gf) = check_resource(
                                    format!("res:{}:{}", job.api.as_str(), job.seed),
                                    &budgets,
                                    local.base_rss,
                                    &s,
                                ) {
                                    local.findings += 1;
                                    let path = crash_dir.join(format!(
                                        "crash-resource-{}-{}.bin",
                                        job.api.as_str(),
                                        job.seed
                                    ));
                                    let _ = fs::write(&path, &job.data);
                                    if let Ok(mut g) = findings_log.lock() {
                                        g.push(format!(
                                            "resource api={} seed={}: {gf}",
                                            job.api.as_str(),
                                            job.seed
                                        ));
                                    }
                                } else {
                                    local.ok += 1;
                                }
                            }
                        }
                        if local.iters % 100 == 0 {
                            let left =
                                deadline_t.saturating_duration_since(Instant::now()).as_secs();
                            eprintln!(
                                "… [tid] local_iters={} peak_rss_kb={} left≈{left}s",
                                local.iters, local.peak_rss
                            );
                        }
                    }
                    worker.quit();
                    local
                })
            })
            .collect();

        let mut agg = Agg::default();
        for h in handles {
            let local = h.join().expect("worker thread");
            if agg.base_rss <= 0 {
                agg.base_rss = local.base_rss;
            }
            agg.iters += local.iters;
            agg.ok += local.ok;
            agg.findings += local.findings;
            agg.worker_errs += local.worker_errs;
            if local.peak_rss > agg.peak_rss {
                agg.peak_rss = local.peak_rss;
            }
            agg.sum_rss_delta += local.sum_rss_delta;
            agg.sum_rss_delta_sq += local.sum_rss_delta_sq;
            agg.sum_elapsed += local.sum_elapsed;
            agg.sum_cpu += local.sum_cpu;
            if local.max_threads > agg.max_threads {
                agg.max_threads = local.max_threads;
            }
            if local.max_fds > agg.max_fds {
                agg.max_fds = local.max_fds;
            }
        }
        if let Ok(log) = findings_log.lock() {
            for line in log.iter().take(20) {
                eprintln!("FINDING {line}");
            }
        }
        if let Ok(g) = api_counts.lock() {
            per_api = g.clone();
        }
        agg
    };

    let wall = t0.elapsed().as_secs_f64();
    print_agg("resource_campaign", wall, &total, workers_n);
    println!("per_api:");
    for (k, v) in &per_api {
        println!("  {k}: {v}");
    }
    println!("host_after: {}", host_snapshot());

    if total.findings > 0 {
        std::process::exit(1);
    }
}
