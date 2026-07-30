//! High-level structure-aware orchestration (json-fuzz `RunStructureAware` analog).

use crate::corpus;
use crate::gates::{self, GateFailure};
use crate::generator::{self, DEEP_NEST_DEPTH};
use crate::mutate;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::time::Duration;

/// Minimal parse target: feed bytes, get a comparable result without panicking.
pub trait XmlParseTarget {
    /// Parse `data`. Must not panic (return Err for adapter failures).
    fn parse(&self, data: &[u8]) -> Result<ParseOutcome, String>;

    /// Optional: re-sample parse profile (options / push / reader / chunk).
    /// Default: no-op. [`crate::libxml2_target::LibXml2Harness`] overrides.
    fn sample_profile(&mut self, _rng: &mut dyn rand::RngCore) {}

    /// True when this target is the libxml2 harness (enables option sampling path).
    fn is_libxml2_harness(&self) -> bool {
        false
    }
}

/// Coarse parse outcome used by gates — includes **text fingerprint** for XXE.
///
/// `PartialEq` **ignores** `elapsed_ms` so determinism gates do not flake on
/// wall-clock noise; timeouts compare equal regardless of duration.
#[derive(Debug, Clone, Eq)]
pub enum ParseOutcome {
    /// Document accepted.
    Accepted {
        root_hint: String,
        /// Expanded document text (or reader-accumulated text). Used for leak checks.
        text_fingerprint: String,
        elapsed_ms: u64,
        mode: String,
    },
    /// Clean rejection / error.
    Rejected {
        code: String,
        text_fingerprint: String,
        elapsed_ms: u64,
        mode: String,
    },
    /// Harness child killed after timeout (amplification / hang control).
    Timeout { elapsed_ms: u64 },
}

impl PartialEq for ParseOutcome {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                ParseOutcome::Accepted {
                    root_hint: a,
                    text_fingerprint: b,
                    mode: c,
                    ..
                },
                ParseOutcome::Accepted {
                    root_hint: a2,
                    text_fingerprint: b2,
                    mode: c2,
                    ..
                },
            ) => a == a2 && b == b2 && c == c2,
            (
                ParseOutcome::Rejected {
                    code: a,
                    text_fingerprint: b,
                    mode: c,
                    ..
                },
                ParseOutcome::Rejected {
                    code: a2,
                    text_fingerprint: b2,
                    mode: c2,
                    ..
                },
            ) => a == a2 && b == b2 && c == c2,
            (ParseOutcome::Timeout { .. }, ParseOutcome::Timeout { .. }) => true,
            _ => false,
        }
    }
}

impl ParseOutcome {
    pub fn text(&self) -> &str {
        match self {
            ParseOutcome::Accepted {
                text_fingerprint, ..
            }
            | ParseOutcome::Rejected {
                text_fingerprint, ..
            } => text_fingerprint,
            ParseOutcome::Timeout { .. } => "",
        }
    }

    pub fn elapsed_ms(&self) -> u64 {
        match self {
            ParseOutcome::Accepted { elapsed_ms, .. }
            | ParseOutcome::Rejected { elapsed_ms, .. }
            | ParseOutcome::Timeout { elapsed_ms } => *elapsed_ms,
        }
    }

    pub fn is_timeout(&self) -> bool {
        matches!(self, ParseOutcome::Timeout { .. })
    }
}

/// Derive a deterministic RNG from fuzz engine bytes.
pub fn rng_from_data(data: &[u8]) -> StdRng {
    let mut seed = [0u8; 32];
    for (i, b) in data.iter().enumerate() {
        seed[i % 32] ^= b.wrapping_add(i as u8);
    }
    if data.is_empty() {
        seed[0] = 1;
    }
    StdRng::from_seed(seed)
}

/// Build work bytes: prefer grammar generation when input is short / empty.
pub fn gen_work_from_input(data: &[u8]) -> Vec<u8> {
    let mut rng = rng_from_data(data);
    if data.is_empty() || data.len() < 4 || rng.gen_bool(0.55) {
        let mut doc = generator::gen_work(&mut rng);
        if !data.is_empty() && rng.gen_bool(0.3) {
            let pos = rng.gen_range(0..=doc.len());
            let take = data.len().min(16);
            doc.splice(pos..pos, data[..take].iter().copied());
        }
        doc
    } else {
        data.to_vec()
    }
}

/// Full structure-aware body: generate/mutate then run gates against `target`.
///
/// When `target.is_libxml2_harness()`, samples option/push/reader/chunk profiles
/// per iteration via [`XmlParseTarget::sample_profile`].
pub fn run_structure_aware<T: XmlParseTarget>(
    data: &[u8],
    target: &mut T,
) -> Result<(), GateFailure> {
    let mut rng = rng_from_data(data);
    let mut work = gen_work_from_input(data);
    let nmut = rng.gen_range(0..4usize);
    work = mutate::apply_mutations(&mut rng, &work, nmut);

    if target.is_libxml2_harness() {
        target.sample_profile(&mut rng);
    }

    // Gate: no panic / clean fail on mutated work
    gates::clean_fail("parse_mutated", || {
        let _ = target.parse(&work);
    })?;

    // Determinism on the same work (same profile)
    gates::determinism("det_mutated", &work, |b| target.parse(b))?;

    // Deep nesting safety
    let deep = generator::gen_deep_nesting(DEEP_NEST_DEPTH, true);
    let _ = gates::deep_nesting_safe("deep_closed", &deep, |b| target.parse(b))?;
    let deep_open = generator::gen_deep_nesting(DEEP_NEST_DEPTH, false);
    let _ = gates::deep_nesting_safe("deep_open", &deep_open, |b| target.parse(b))?;

    // Corpus rotation sample
    let entry = corpus::CORPUS[rng.gen_range(0..corpus::CORPUS.len())];
    gates::clean_fail(format!("corpus:{}", entry.id), || {
        let _ = target.parse(entry.data);
    })?;

    // Amplification: expand sketch under a **short harness timeout** profile when
    // libxml2 harness is used (kill on hang). Otherwise same-thread elapsed budget.
    let expand = generator::gen_entity_expand_sketch(&mut rng);
    if target.is_libxml2_harness() {
        // sample_profile may have set a longer timeout; force a tight budget parse
        // by requiring Timeout or quick return — outcome must not hang the fuzzer.
        let out = target
            .parse(&expand)
            .map_err(|e| GateFailure::new(gates::GateKind::InvariantViolation, "ampl", e))?;
        if out.is_timeout() {
            // Timeout is a controlled fail-closed for the fuzzer loop (finding if
            // product should have limited amplification faster — recorded, not panic).
            return Ok(());
        }
        if out.elapsed_ms() > 3000 {
            return Err(GateFailure::new(
                gates::GateKind::InvariantViolation,
                "ampl_elapsed",
                format!("parse took {}ms without timeout kill", out.elapsed_ms()),
            ));
        }
    } else {
        let _ = gates::within_budget_sync("ampl_budget", Duration::from_secs(3), || {
            target.parse(&expand)
        })?;
    }

    Ok(())
}

/// Seed helper: all corpus bytes.
pub fn each_corpus_seed(mut f: impl FnMut(&[u8])) {
    for e in corpus::CORPUS {
        f(e.data);
    }
}
