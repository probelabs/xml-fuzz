//! Libxml2 consumer adapter via the C harness subprocess.
//!
//! Drives real `xmlReadMemory` / push / reader paths. Parses harness stderr
//! fingerprints (`root=`, `text=`, `elapsed_ms=`) so XXE/entity gates can see
//! expanded document text — not just the root element name.

use crate::fuzz::{ParseOutcome, XmlParseTarget};
use rand::Rng;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Parse option flags mirrored to `harness/libxml2_parse.c` CLI.
#[derive(Debug, Clone)]
pub struct LibXml2Options {
    pub push: bool,
    pub reader: bool,
    pub noent: bool,
    pub dtdload: bool,
    pub dtdattr: bool,
    pub huge: bool,
    pub nonet: bool,
    pub xinclude: bool,
    pub recover: bool,
    pub no_xxe: bool,
    pub chunk_size: Option<u32>,
    /// Wall-clock budget; **kill child** if exceeded (real hang/amplification control).
    pub timeout: Duration,
}

impl Default for LibXml2Options {
    fn default() -> Self {
        Self {
            push: false,
            reader: false,
            noent: false,
            dtdload: false,
            dtdattr: false,
            huge: false,
            nonet: false,
            xinclude: false,
            recover: false,
            no_xxe: false,
            chunk_size: None,
            timeout: Duration::from_secs(2),
        }
    }
}

impl LibXml2Options {
    pub fn safe_untrusted() -> Self {
        Self {
            nonet: true,
            no_xxe: true,
            timeout: Duration::from_secs(2),
            ..Default::default()
        }
    }

    pub fn with_push(mut self) -> Self {
        self.push = true;
        self.reader = false;
        self
    }

    pub fn with_reader(mut self) -> Self {
        self.reader = true;
        self.push = false;
        self
    }

    /// Sample a whitelist of option/chunk profiles for structure-aware loops.
    pub fn sample(rng: &mut (impl Rng + ?Sized)) -> Self {
        let mut o = Self::safe_untrusted();
        match rng.gen_range(0..8u8) {
            0 => {} // safe defaults
            1 => {
                o.push = true;
                o.chunk_size = Some(1);
            }
            2 => {
                o.push = true;
                o.chunk_size = Some(17);
            }
            3 => {
                o.push = true;
                o.chunk_size = Some(64);
            }
            4 => {
                o.reader = true;
            }
            5 => {
                o.noent = true;
                o.no_xxe = true; // NOENT but blocked XXE
            }
            6 => {
                o.recover = true;
            }
            _ => {
                o.huge = true;
                o.timeout = Duration::from_secs(3);
            }
        }
        o
    }
}

/// Subprocess-backed target.
#[derive(Debug, Clone)]
pub struct LibXml2Harness {
    pub binary: PathBuf,
    pub options: LibXml2Options,
}

impl LibXml2Harness {
    pub fn discover() -> Option<Self> {
        let candidates = [
            std::env::var_os("XML_FUZZ_LIBXML2_HARNESS").map(PathBuf::from),
            Some(PathBuf::from("harness/libxml2_parse")),
            Some(PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/harness/libxml2_parse"
            ))),
            Some(PathBuf::from(
                "/tmp/grok-goal-4c506ec6e592/implementer/libxml2_parse",
            )),
        ];
        for c in candidates.into_iter().flatten() {
            if c.is_file() {
                return Some(Self {
                    binary: c,
                    options: LibXml2Options::safe_untrusted(),
                });
            }
        }
        None
    }

    pub fn with_binary(path: impl AsRef<Path>) -> Self {
        Self {
            binary: path.as_ref().to_path_buf(),
            options: LibXml2Options::safe_untrusted(),
        }
    }

    fn build_args(&self) -> Vec<String> {
        let mut a = Vec::new();
        if self.options.push {
            a.push("--push".into());
        }
        if self.options.reader {
            a.push("--reader".into());
        }
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

    fn parse_stderr(stderr: &str, code: i32, elapsed_fallback_ms: u64) -> ParseOutcome {
        let mut root = String::new();
        let mut text = String::new();
        let mut elapsed_ms = elapsed_fallback_ms;
        let mut mode = String::new();
        for line in stderr.lines() {
            if let Some(v) = line.strip_prefix("root=") {
                root = v.to_string();
            } else if let Some(v) = line.strip_prefix("text=") {
                // last text= wins (harness emits text_len then text=)
                text = v.to_string();
            } else if let Some(v) = line.strip_prefix("elapsed_ms=") {
                if let Ok(n) = v.parse::<u64>() {
                    elapsed_ms = n;
                }
            } else if let Some(v) = line.strip_prefix("mode=") {
                mode = v.to_string();
            }
        }
        if code == 0 {
            ParseOutcome::Accepted {
                root_hint: root,
                text_fingerprint: text,
                elapsed_ms,
                mode,
            }
        } else {
            ParseOutcome::Rejected {
                code: format!("exit={code}"),
                text_fingerprint: text,
                elapsed_ms,
                mode,
            }
        }
    }
}

impl XmlParseTarget for LibXml2Harness {
    fn parse(&self, data: &[u8]) -> Result<ParseOutcome, String> {
        let start = Instant::now();
        let mut child = Command::new(&self.binary)
            .args(self.build_args())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn harness: {e}"))?;

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(data);
            // drop stdin to close pipe so child sees EOF
        }

        let timeout = self.options.timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let code = status.code().unwrap_or(1);
                    let stderr = {
                        use std::io::Read;
                        let mut buf = Vec::new();
                        if let Some(mut err) = child.stderr.take() {
                            let _ = err.read_to_end(&mut buf);
                        }
                        String::from_utf8_lossy(&buf).into_owned()
                    };
                    let elapsed = start.elapsed().as_millis() as u64;
                    return Ok(Self::parse_stderr(&stderr, code, elapsed));
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
        self.options = LibXml2Options::sample(rng);
    }

    fn is_libxml2_harness(&self) -> bool {
        true
    }
}
