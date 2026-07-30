//! Resource sampling oracles and persistent-worker client.
//!
//! **Why a worker?** Spawning a new process per case reclaims all heap/threads
//! on exit, so leak/growth bugs are invisible. `--worker` keeps one process and
//! reports `rss_delta_kb`, `threads`, `fds`, and CPU deltas after each job.
//!
//! **Parallelism:** default is **serial** (one job at a time on one worker) so
//! measurements are not confounded by sibling jobs. Optional `WorkerPool` runs
//! **N isolated workers** (separate processes) — each job still exclusive to one
//! worker; total throughput rises without sharing a single RSS baseline.

use crate::apis::LibXml2Api;
use crate::gates::{GateFailure, GateKind};
use crate::libxml2_target::LibXml2Options;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};

/// One post-job resource sample from the harness.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResourceSample {
    pub ok: bool,
    pub elapsed_ms: i64,
    pub rss_kb: i64,
    pub rss_delta_kb: i64,
    pub threads: i64,
    pub fds: i64,
    pub cpu_user_ms: i64,
    pub cpu_sys_ms: i64,
}

impl ResourceSample {
    pub fn parse_res_line(line: &str) -> Option<Self> {
        let line = line.trim();
        if !line.starts_with("RES ") {
            return None;
        }
        let mut s = ResourceSample::default();
        for tok in line.split_whitespace().skip(1) {
            if let Some((k, v)) = tok.split_once('=') {
                let n: i64 = v.parse().unwrap_or(-1);
                match k {
                    "ok" => s.ok = v == "1" || v == "true",
                    "elapsed_ms" => s.elapsed_ms = n,
                    "rss_kb" => s.rss_kb = n,
                    "rss_delta_kb" => s.rss_delta_kb = n,
                    "threads" => s.threads = n,
                    "fds" => s.fds = n,
                    "cpu_user_ms" => s.cpu_user_ms = n,
                    "cpu_sys_ms" => s.cpu_sys_ms = n,
                    _ => {}
                }
            }
        }
        Some(s)
    }

    pub fn cpu_total_ms(&self) -> i64 {
        let u = if self.cpu_user_ms >= 0 {
            self.cpu_user_ms
        } else {
            0
        };
        let s = if self.cpu_sys_ms >= 0 {
            self.cpu_sys_ms
        } else {
            0
        };
        u + s
    }
}

/// Budgets for resource oracles (any field `None` = ignore).
#[derive(Debug, Clone)]
pub struct ResourceBudgets {
    pub max_elapsed_ms: Option<i64>,
    pub max_rss_kb: Option<i64>,
    /// Max growth vs sample taken at worker start / baseline.
    pub max_rss_growth_kb: Option<i64>,
    pub max_rss_delta_kb: Option<i64>,
    pub max_threads: Option<i64>,
    pub max_fds: Option<i64>,
    pub max_cpu_ms: Option<i64>,
}

impl Default for ResourceBudgets {
    fn default() -> Self {
        Self {
            max_elapsed_ms: Some(5_000),
            max_rss_kb: Some(512 * 1024), // 512 MiB hard cap
            max_rss_growth_kb: Some(256 * 1024),
            max_rss_delta_kb: Some(128 * 1024), // single-job spike
            max_threads: Some(64),
            max_fds: Some(512),
            max_cpu_ms: Some(5_000),
        }
    }
}

impl ResourceBudgets {
    /// Loose defaults for ASan (higher baseline RSS).
    pub fn for_asan() -> Self {
        let mut b = Self::default();
        b.max_rss_kb = Some(1024 * 1024);
        b.max_rss_growth_kb = Some(512 * 1024);
        b
    }

    pub fn check(&self, label: &str, base_rss: i64, s: &ResourceSample) -> Result<(), GateFailure> {
        if let Some(m) = self.max_elapsed_ms {
            if s.elapsed_ms > m {
                return Err(GateFailure::new(
                    GateKind::InvariantViolation,
                    label,
                    format!("elapsed_ms {} > max {}", s.elapsed_ms, m),
                ));
            }
        }
        if let Some(m) = self.max_rss_kb {
            if s.rss_kb > m {
                return Err(GateFailure::new(
                    GateKind::InvariantViolation,
                    label,
                    format!("rss_kb {} > max {}", s.rss_kb, m),
                ));
            }
        }
        if let Some(m) = self.max_rss_delta_kb {
            if s.rss_delta_kb > m {
                return Err(GateFailure::new(
                    GateKind::InvariantViolation,
                    label,
                    format!("rss_delta_kb {} > max {}", s.rss_delta_kb, m),
                ));
            }
        }
        if let Some(m) = self.max_rss_growth_kb {
            if base_rss >= 0 && s.rss_kb >= 0 && s.rss_kb - base_rss > m {
                return Err(GateFailure::new(
                    GateKind::InvariantViolation,
                    label,
                    format!(
                        "rss growth {} kb (base {} -> {}) > max {}",
                        s.rss_kb - base_rss,
                        base_rss,
                        s.rss_kb,
                        m
                    ),
                ));
            }
        }
        if let Some(m) = self.max_threads {
            if s.threads > m {
                return Err(GateFailure::new(
                    GateKind::InvariantViolation,
                    label,
                    format!("threads {} > max {}", s.threads, m),
                ));
            }
        }
        if let Some(m) = self.max_fds {
            if s.fds > m {
                return Err(GateFailure::new(
                    GateKind::InvariantViolation,
                    label,
                    format!("fds {} > max {}", s.fds, m),
                ));
            }
        }
        if let Some(m) = self.max_cpu_ms {
            if s.cpu_total_ms() > m {
                return Err(GateFailure::new(
                    GateKind::InvariantViolation,
                    label,
                    format!("cpu_ms {} > max {}", s.cpu_total_ms(), m),
                ));
            }
        }
        Ok(())
    }
}

/// Encode [`LibXml2Options`] into the integer mask the multi harness expects
/// (same bits as `XML_PARSE_*` in `include/libxml/parser.h`).
pub fn libxml_options_mask(o: &LibXml2Options) -> u32 {
    // Values from include/libxml/parser.h (libxml2 2.13+)
    const XML_PARSE_RECOVER: u32 = 1 << 0;
    const XML_PARSE_NOENT: u32 = 1 << 1;
    const XML_PARSE_DTDLOAD: u32 = 1 << 2;
    const XML_PARSE_DTDATTR: u32 = 1 << 3;
    const XML_PARSE_XINCLUDE: u32 = 1 << 10;
    const XML_PARSE_NONET: u32 = 1 << 11;
    const XML_PARSE_HUGE: u32 = 1 << 19;
    const XML_PARSE_NO_XXE: u32 = 1 << 23;

    let mut v = 0u32;
    if o.recover {
        v |= XML_PARSE_RECOVER;
    }
    if o.noent {
        v |= XML_PARSE_NOENT;
    }
    if o.dtdload {
        v |= XML_PARSE_DTDLOAD;
    }
    if o.dtdattr {
        v |= XML_PARSE_DTDATTR;
    }
    if o.xinclude {
        v |= XML_PARSE_XINCLUDE;
    }
    if o.nonet {
        v |= XML_PARSE_NONET;
    }
    if o.huge {
        v |= XML_PARSE_HUGE;
    }
    if o.no_xxe {
        v |= XML_PARSE_NO_XXE;
    }
    v
}

fn prepare_worker_command(binary: &Path) -> Command {
    let mut cmd = Command::new(binary);
    cmd.arg("--worker");
    // ASan harnesses linked against instrumented libxml2: keep campaigns going
    // when intentional leak noise is present, and surface real crashes only.
    if std::env::var_os("ASAN_OPTIONS").is_none() {
        cmd.env(
            "ASAN_OPTIONS",
            "detect_leaks=0:halt_on_error=0:abort_on_error=0",
        );
    }
    if std::env::var_os("UBSAN_OPTIONS").is_none() {
        cmd.env("UBSAN_OPTIONS", "print_stacktrace=1:halt_on_error=0");
    }
    cmd
}

/// Persistent harness worker (one process, serial jobs).
pub struct ResourceWorker {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    pub base_rss_kb: i64,
    pub binary: PathBuf,
}

impl ResourceWorker {
    pub fn spawn(binary: impl AsRef<Path>) -> std::io::Result<Self> {
        let binary = binary.as_ref().to_path_buf();
        let mut child = prepare_worker_command(&binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null()) // keep protocol clean; enable for debug
            .spawn()?;
        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let mut w = Self {
            child,
            stdin,
            stdout,
            base_rss_kb: -1,
            binary,
        };
        // Baseline: empty xml-memory job
        if let Ok(s) = w.job(LibXml2Api::XmlMemory, &LibXml2Options::safe_untrusted(), b"<r/>")
        {
            w.base_rss_kb = s.rss_kb;
        }
        Ok(w)
    }

    pub fn spawn_with_stderr(binary: impl AsRef<Path>) -> std::io::Result<Self> {
        let binary = binary.as_ref().to_path_buf();
        let mut child = prepare_worker_command(&binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        Ok(Self {
            child,
            stdin,
            stdout,
            base_rss_kb: -1,
            binary,
        })
    }

    pub fn job(
        &mut self,
        api: LibXml2Api,
        opts: &LibXml2Options,
        data: &[u8],
    ) -> Result<ResourceSample, String> {
        let mask = libxml_options_mask(opts);
        let chunk = opts.chunk_size.unwrap_or(17);
        let header = format!(
            "JOB {} {} {} {}\n",
            api.as_str(),
            mask,
            chunk,
            data.len()
        );
        self.stdin
            .write_all(header.as_bytes())
            .map_err(|e| format!("write header: {e}"))?;
        self.stdin
            .write_all(data)
            .map_err(|e| format!("write body: {e}"))?;
        self.stdin.flush().map_err(|e| format!("flush: {e}"))?;

        let mut line = String::new();
        // Read until RES line
        loop {
            line.clear();
            let n = self
                .stdout
                .read_line(&mut line)
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("worker EOF".into());
            }
            if let Some(s) = ResourceSample::parse_res_line(&line) {
                return Ok(s);
            }
        }
    }

    pub fn quit(&mut self) {
        let _ = self.stdin.write_all(b"QUIT\n");
        let _ = self.stdin.flush();
        let _ = self.child.wait();
    }
}

impl Drop for ResourceWorker {
    fn drop(&mut self) {
        let _ = self.stdin.write_all(b"QUIT\n");
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Pool of isolated workers for parallel throughput without shared RSS noise.
/// Each `job` takes a free worker (mutex), runs serially on that process.
pub struct WorkerPool {
    workers: Vec<Arc<Mutex<ResourceWorker>>>,
    next: Mutex<usize>,
}

impl WorkerPool {
    pub fn spawn(binary: impl AsRef<Path>, n: usize) -> Result<Self, String> {
        let n = n.max(1);
        let mut workers = Vec::with_capacity(n);
        for _ in 0..n {
            let w = ResourceWorker::spawn(binary.as_ref()).map_err(|e| e.to_string())?;
            workers.push(Arc::new(Mutex::new(w)));
        }
        Ok(Self {
            workers,
            next: Mutex::new(0),
        })
    }

    pub fn job(
        &self,
        api: LibXml2Api,
        opts: &LibXml2Options,
        data: &[u8],
    ) -> Result<ResourceSample, String> {
        let idx = {
            let mut n = self.next.lock().map_err(|e| e.to_string())?;
            let i = *n % self.workers.len();
            *n += 1;
            i
        };
        let mut w = self.workers[idx].lock().map_err(|e| e.to_string())?;
        w.job(api, opts, data)
    }

    pub fn base_rss_kb(&self) -> i64 {
        self.workers
            .first()
            .and_then(|w| w.lock().ok().map(|g| g.base_rss_kb))
            .unwrap_or(-1)
    }
}

/// Check sample against budgets with baseline RSS.
pub fn check_resource(
    label: impl Into<String>,
    budgets: &ResourceBudgets,
    base_rss_kb: i64,
    sample: &ResourceSample,
) -> Result<(), GateFailure> {
    budgets.check(&label.into(), base_rss_kb, sample)
}

/// Discover multi-API binary (prefers FAST if XML_FUZZ_FAST=1).
pub fn discover_multi_harness() -> Option<PathBuf> {
    crate::libxml2_multi::LibXml2MultiHarness::discover().map(|h| h.binary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_res_line() {
        let s = ResourceSample::parse_res_line(
            "RES ok=1 elapsed_ms=3 rss_kb=12000 rss_delta_kb=40 threads=1 fds=12 cpu_user_ms=1 cpu_sys_ms=0",
        )
        .unwrap();
        assert!(s.ok);
        assert_eq!(s.rss_kb, 12000);
        assert_eq!(s.rss_delta_kb, 40);
        assert_eq!(s.cpu_total_ms(), 1);
    }

    #[test]
    fn budget_flags_growth() {
        let b = ResourceBudgets {
            max_rss_growth_kb: Some(100),
            max_elapsed_ms: None,
            max_rss_kb: None,
            max_rss_delta_kb: None,
            max_threads: None,
            max_fds: None,
            max_cpu_ms: None,
        };
        let s = ResourceSample {
            rss_kb: 500,
            ..Default::default()
        };
        assert!(b.check("t", 100, &s).is_err());
        assert!(b.check("t", 450, &s).is_ok());
    }

    #[test]
    fn options_mask_recover_is_bit0() {
        let mut o = LibXml2Options::safe_untrusted();
        o.recover = true;
        let m = libxml_options_mask(&o);
        assert_eq!(m & 1, 1, "XML_PARSE_RECOVER must be 1<<0");
        assert_ne!(m & (1 << 5), 1 << 5, "must not set NOERROR for recover");
        assert_eq!(m & (1 << 11), 1 << 11); // NONET
        assert_eq!(m & (1 << 23), 1 << 23); // NO_XXE
    }
}
