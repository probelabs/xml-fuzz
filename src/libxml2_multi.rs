//! Drive **every** libxml2 API surface via `harness/libxml2_all_apis`.

use crate::apis::{gen_for_api, LibXml2Api};
use crate::fuzz::{ParseOutcome, XmlParseTarget};
use crate::gates::{self, GateFailure};
use crate::libxml2_target::LibXml2Options;
use crate::mutate;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Multi-API harness wrapper.
#[derive(Debug, Clone)]
pub struct LibXml2MultiHarness {
    pub binary: PathBuf,
    pub api: LibXml2Api,
    pub options: LibXml2Options,
}

impl LibXml2MultiHarness {
    pub fn discover() -> Option<Self> {
        let candidates = [
            std::env::var_os("XML_FUZZ_LIBXML2_ALL").map(PathBuf::from),
            Some(PathBuf::from("harness/libxml2_all_apis")),
            Some(PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/harness/libxml2_all_apis"
            ))),
            Some(PathBuf::from(
                "/tmp/grok-goal-4c506ec6e592/implementer/libxml2_all_apis",
            )),
        ];
        for c in candidates.into_iter().flatten() {
            if c.is_file() {
                return Some(Self {
                    binary: c,
                    api: LibXml2Api::XmlMemory,
                    options: LibXml2Options::safe_untrusted(),
                });
            }
        }
        None
    }

    pub fn with_binary(path: impl AsRef<Path>) -> Self {
        Self {
            binary: path.as_ref().to_path_buf(),
            api: LibXml2Api::XmlMemory,
            options: LibXml2Options::safe_untrusted(),
        }
    }

    fn build_args(&self) -> Vec<String> {
        let mut a = vec![format!("--api={}", self.api.as_str())];
        if self.options.noent {
            a.push("--noent".into());
        }
        if self.options.dtdload {
            a.push("--dtdload".into());
        }
        if self.options.dtdattr {
            a.push("--dtdattr".into());
        }
        if self.options.huge {
            a.push("--huge".into());
        }
        if self.options.nonet {
            a.push("--nonet".into());
        }
        if self.options.xinclude {
            a.push("--xinclude".into());
        }
        if self.options.recover {
            a.push("--recover".into());
        }
        if self.options.no_xxe {
            a.push("--no-xxe".into());
        }
        if let Some(c) = self.options.chunk_size {
            a.push(format!("--chunk={c}"));
        }
        a
    }

    fn parse_stderr(stderr: &str, code: i32, elapsed: u64, api: &str) -> ParseOutcome {
        let mut root = String::new();
        let mut text = String::new();
        let mut mode = api.to_string();
        let mut elapsed_ms = elapsed;
        for line in stderr.lines() {
            if let Some(v) = line.strip_prefix("root=") {
                root = v.to_string();
            } else if let Some(v) = line.strip_prefix("text=") {
                text = v.to_string();
            } else if let Some(v) = line.strip_prefix("elapsed_ms=") {
                if let Ok(n) = v.parse() {
                    elapsed_ms = n;
                }
            } else if let Some(v) = line.strip_prefix("mode=") {
                mode = v.to_string();
            }
        }
        // Surface ASan / UBSan markers so long campaigns can classify findings.
        let asan_like = stderr.contains("AddressSanitizer")
            || stderr.contains("ERROR: AddressSanitizer")
            || stderr.contains("UndefinedBehaviorSanitizer")
            || stderr.contains("SUMMARY: AddressSanitizer");
        if asan_like && text.is_empty() {
            // Keep a short fingerprint of the sanitizer banner for crash logs.
            text = stderr.chars().take(512).collect();
        }
        if code == 0 && !asan_like {
            ParseOutcome::Accepted {
                root_hint: root,
                text_fingerprint: text,
                elapsed_ms,
                mode,
            }
        } else {
            let code_s = if asan_like {
                format!("asan:exit={code}")
            } else if code >= 128 {
                format!("signal={}:exit={code}", code - 128)
            } else {
                format!("exit={code}")
            };
            ParseOutcome::Rejected {
                code: code_s,
                text_fingerprint: text,
                elapsed_ms,
                mode,
            }
        }
    }
}

impl XmlParseTarget for LibXml2MultiHarness {
    fn parse(&self, data: &[u8]) -> Result<ParseOutcome, String> {
        let start = Instant::now();
        let mut child = Command::new(&self.binary)
            .args(self.build_args())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn multi harness: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(data);
        }
        let timeout = self.options.timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    use std::io::Read;
                    let mut buf = Vec::new();
                    if let Some(mut e) = child.stderr.take() {
                        let _ = e.read_to_end(&mut buf);
                    }
                    let stderr = String::from_utf8_lossy(&buf).into_owned();
                    // Prefer real exit code; on signal death use 128+sig (ASan often SIGABRT).
                    let code = status.code().unwrap_or_else(|| {
                        #[cfg(unix)]
                        {
                            use std::os::unix::process::ExitStatusExt;
                            if let Some(sig) = status.signal() {
                                return 128 + sig;
                            }
                        }
                        1
                    });
                    return Ok(Self::parse_stderr(
                        &stderr,
                        code,
                        start.elapsed().as_millis() as u64,
                        self.api.as_str(),
                    ));
                }
                Ok(None) => {
                    if start.elapsed() > timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Ok(ParseOutcome::Timeout {
                            elapsed_ms: start.elapsed().as_millis() as u64,
                        });
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(format!("wait: {e}")),
            }
        }
    }

    fn sample_profile(&mut self, rng: &mut dyn rand::RngCore) {
        self.api = LibXml2Api::sample(rng);
        self.options = LibXml2Options::sample(rng);
        // push API implies chunking options
        if matches!(self.api, LibXml2Api::XmlPush | LibXml2Api::HtmlPush) {
            self.options.chunk_size = Some([1, 7, 17, 64][rng.gen_range(0..4)]);
        }
    }

    fn is_libxml2_harness(&self) -> bool {
        true
    }
}

/// Run structure-aware fuzzing once per API (full surface coverage).
pub fn fuzz_all_apis(
    binary: &Path,
    iterations_per_api: usize,
) -> Result<(), GateFailure> {
    for (ai, &api) in LibXml2Api::ALL.iter().enumerate() {
        let mut h = LibXml2MultiHarness {
            binary: binary.to_path_buf(),
            api,
            options: LibXml2Options::safe_untrusted(),
        };
        // Enable recover for more HTML/XML coverage; keep nonet/no_xxe.
        h.options.recover = true;
        for i in 0..iterations_per_api {
            let mut rng = StdRng::seed_from_u64((ai as u64 + 1) * 1000 + i as u64);
            let mut data = gen_for_api(&mut rng, api);
            if rng.gen_bool(0.5) {
                data = mutate::apply_mutation(&mut rng, &data);
            }
            h.api = api;
            gates::clean_fail(format!("{}:{}", api.as_str(), i), || {
                let _ = h.parse(&data);
            })?;
            // timeout is fail-closed, not a gate failure for fuzzer liveness
            let out = h
                .parse(&data)
                .map_err(|e| GateFailure::new(gates::GateKind::InvariantViolation, api.as_str(), e))?;
            if out.elapsed_ms() > 10_000 {
                return Err(GateFailure::new(
                    gates::GateKind::InvariantViolation,
                    api.as_str(),
                    format!("slow parse {}ms", out.elapsed_ms()),
                ));
            }
        }
    }
    Ok(())
}

/// One structure-aware iteration that picks a random API + mutates.
pub fn fuzz_one_random_api(h: &mut LibXml2MultiHarness, seed: u64) -> Result<(), GateFailure> {
    let mut rng = StdRng::seed_from_u64(seed);
    h.sample_profile(&mut rng);
    let mut data = gen_for_api(&mut rng, h.api);
    let n = rng.gen_range(0..3usize);
    data = mutate::apply_mutations(&mut rng, &data, n);
    gates::clean_fail(format!("rand:{}", h.api.as_str()), || {
        let _ = h.parse(&data);
    })?;
    Ok(())
}
