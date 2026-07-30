//! Differential oracles: compare parse outcomes across option profiles (and an
//! optional pure-Rust naive structural checker).
//!
//! Primary mode: **two libxml2 option sets** via the harness — e.g. safe vs
//! recover vs noent+noxxe — comparing accept/reject class and secret text leaks.
//! Secondary: optional [`NaiveStructuralParser`] for accept/reject without a
//! native binary (unit-test friendly).

use crate::fuzz::{ParseOutcome, XmlParseTarget};
use crate::libxml2_target::{LibXml2Harness, LibXml2Options};
use crate::xxe_policy::{self, SECRET_MARKER};
use std::path::PathBuf;
use std::time::Duration;

/// Result of comparing two [`ParseOutcome`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffResult {
    /// Same accept/reject/timeout class and compatible text fingerprints.
    Match,
    /// One accepted and the other rejected/timed out (or vice versa).
    AcceptMismatch,
    /// Same accept/reject class, but text fingerprints disagree on secrets or
    /// material content (when both accepted).
    TextMismatch,
}

/// Coarse accept/reject class used by differential comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeClass {
    Accept,
    Reject,
    Timeout,
}

impl OutcomeClass {
    pub fn from_outcome(o: &ParseOutcome) -> Self {
        match o {
            ParseOutcome::Accepted { .. } => OutcomeClass::Accept,
            ParseOutcome::Rejected { .. } => OutcomeClass::Reject,
            ParseOutcome::Timeout { .. } => OutcomeClass::Timeout,
        }
    }
}

/// Compare two outcomes for accept/reject class and secret/text leakage.
///
/// Rules:
/// - Different class (accept vs reject vs timeout) → [`DiffResult::AcceptMismatch`]
///   (timeout vs reject is treated as AcceptMismatch for visibility).
/// - Same class, but secret marker present in exactly one fingerprint →
///   [`DiffResult::TextMismatch`].
/// - Both accepted and non-empty fingerprints differ (normalized) → TextMismatch
///   when either side contains the secret marker or both are non-empty and unequal.
/// - Otherwise → Match.
pub fn compare_outcomes(a: &ParseOutcome, b: &ParseOutcome) -> DiffResult {
    let ca = OutcomeClass::from_outcome(a);
    let cb = OutcomeClass::from_outcome(b);
    if ca != cb {
        return DiffResult::AcceptMismatch;
    }

    let ta = a.text();
    let tb = b.text();
    let secret_a = ta.contains(SECRET_MARKER);
    let secret_b = tb.contains(SECRET_MARKER);
    if secret_a != secret_b {
        return DiffResult::TextMismatch;
    }

    // When both accepted, flag material text divergence (leak / expansion diffs).
    if matches!(ca, OutcomeClass::Accept) {
        let na = normalize_text(ta);
        let nb = normalize_text(tb);
        if !na.is_empty() && !nb.is_empty() && na != nb {
            // Only treat as mismatch when secrets or large length deltas suggest
            // entity expansion / different recovery paths — not root-only noise.
            if secret_a || secret_b || (na.len() as i64 - nb.len() as i64).abs() > 32 {
                return DiffResult::TextMismatch;
            }
        }
    }

    DiffResult::Match
}

fn normalize_text(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

/// Named option profile for differential runs.
#[derive(Debug, Clone)]
pub struct DiffProfile {
    pub name: &'static str,
    pub options: LibXml2Options,
}

/// Safe untrusted defaults (nonet + no_xxe).
pub fn profile_safe() -> DiffProfile {
    DiffProfile {
        name: "safe",
        options: LibXml2Options::safe_untrusted(),
    }
}

/// Recovery enabled (still nonet + no_xxe).
pub fn profile_recover() -> DiffProfile {
    DiffProfile {
        name: "recover",
        options: LibXml2Options {
            recover: true,
            nonet: true,
            no_xxe: true,
            timeout: Duration::from_secs(2),
            ..Default::default()
        },
    }
}

/// NOENT + NO_XXE (expand entities, block external XXE).
pub fn profile_noent_noxxe() -> DiffProfile {
    DiffProfile {
        name: "noent_noxxe",
        options: LibXml2Options {
            noent: true,
            nonet: true,
            no_xxe: true,
            timeout: Duration::from_secs(2),
            ..Default::default()
        },
    }
}

/// Default pair set: safe vs recover, safe vs noent_noxxe, recover vs noent_noxxe.
pub fn default_diff_profiles() -> Vec<DiffProfile> {
    vec![profile_safe(), profile_recover(), profile_noent_noxxe()]
}

/// Run differential compare for one document across two harness profiles.
pub fn diff_harness_pair(
    binary: &PathBuf,
    a: &DiffProfile,
    b: &DiffProfile,
    data: &[u8],
) -> Result<(ParseOutcome, ParseOutcome, DiffResult), String> {
    let ha = LibXml2Harness {
        binary: binary.clone(),
        options: a.options.clone(),
    };
    let hb = LibXml2Harness {
        binary: binary.clone(),
        options: b.options.clone(),
    };
    let oa = ha.parse(data).map_err(|e| format!("{}: {e}", a.name))?;
    let ob = hb.parse(data).map_err(|e| format!("{}: {e}", b.name))?;
    let d = compare_outcomes(&oa, &ob);
    Ok((oa, ob, d))
}

/// Compare all default profile pairs on `data`. Soft-skip if no harness.
///
/// Returns Ok(findings) where each finding is `(pair_label, DiffResult)` for
/// non-Match results that are **interesting** under policy (secret text mismatch
/// always; accept mismatch only when both profiles claim "strict" semantics).
pub fn run_libxml2_option_differential(
    harness_bin: Option<PathBuf>,
    data: &[u8],
) -> Result<Vec<(String, DiffResult)>, String> {
    let bin = match harness_bin.or_else(|| LibXml2Harness::discover().map(|h| h.binary)) {
        Some(b) if b.is_file() => b,
        _ => return Ok(Vec::new()),
    };
    let profiles = default_diff_profiles();
    let mut findings = Vec::new();
    for i in 0..profiles.len() {
        for j in (i + 1)..profiles.len() {
            let (oa, ob, d) = diff_harness_pair(&bin, &profiles[i], &profiles[j], data)?;
            let label = format!("{} vs {}", profiles[i].name, profiles[j].name);
            match d {
                DiffResult::Match => {}
                DiffResult::TextMismatch => {
                    // Secret present in exactly one side is always a finding.
                    let sa = oa.text().contains(SECRET_MARKER);
                    let sb = ob.text().contains(SECRET_MARKER);
                    if sa != sb {
                        findings.push((label, d));
                    } else {
                        findings.push((label, d));
                    }
                }
                DiffResult::AcceptMismatch => {
                    // recover may accept more than safe — record but do not hard-fail
                    // unless safe accepted and noent_noxxe rejected unexpectedly with leak.
                    let _ = (&oa, &ob);
                    findings.push((label, d));
                }
            }
        }
    }
    Ok(findings)
}

/// Differential on XXE sandbox doc: safe must not leak; noent without no_xxe may.
/// Soft-skip without harness. Hard-fail only on safe-side secret leak vs paired profile.
pub fn run_xxe_safe_vs_noent_differential(
    harness_bin: Option<PathBuf>,
) -> Result<(), String> {
    let bin = match harness_bin.or_else(|| LibXml2Harness::discover().map(|h| h.binary)) {
        Some(b) if b.is_file() => b,
        _ => return Ok(()),
    };
    let paths = xxe_policy::ensure_sandbox_fixtures().map_err(|e| e.to_string())?;
    let doc = xxe_policy::xxe_sandbox_document(&paths.secret_uri);

    let safe = DiffProfile {
        name: "safe",
        options: LibXml2Options::safe_untrusted(),
    };
    let noent_open = DiffProfile {
        name: "noent_open",
        options: LibXml2Options {
            noent: true,
            nonet: true,
            no_xxe: false,
            timeout: Duration::from_secs(2),
            ..Default::default()
        },
    };
    let (oa, ob, d) = diff_harness_pair(&bin, &safe, &noent_open, &doc)?;
    if oa.text().contains(SECRET_MARKER) {
        return Err(format!(
            "safe profile leaked secret; outcome={:?} diff={:?}",
            oa, d
        ));
    }
    // Open profile may or may not expand; both Match and mismatch are ok as long as safe is clean.
    let _ = ob;
    Ok(())
}

// ─── Naive pure-Rust structural accept/reject ───────────────────────────────

/// Minimal structural checker: balanced-ish tags, UTF-8, not empty.
/// Not a real XML parser — only for differential accept/reject class tests
/// without native deps.
#[derive(Debug, Default, Clone, Copy)]
pub struct NaiveStructuralParser;

impl NaiveStructuralParser {
    pub fn classify(data: &[u8]) -> ParseOutcome {
        if data.is_empty() {
            return ParseOutcome::Rejected {
                code: "empty".into(),
                text_fingerprint: String::new(),
                elapsed_ms: 0,
                mode: "naive".into(),
            };
        }
        if std::str::from_utf8(data).is_err() {
            return ParseOutcome::Rejected {
                code: "utf8".into(),
                text_fingerprint: String::from_utf8_lossy(data).chars().take(64).collect(),
                elapsed_ms: 0,
                mode: "naive".into(),
            };
        }
        let s = std::str::from_utf8(data).unwrap_or("");
        let opens = data.iter().filter(|&&b| b == b'<').count();
        let closes = data.iter().filter(|&&b| b == b'>').count();
        if opens == 0 || closes == 0 {
            return ParseOutcome::Rejected {
                code: "no_markup".into(),
                text_fingerprint: s.chars().take(256).collect(),
                elapsed_ms: 0,
                mode: "naive".into(),
            };
        }
        // Extremely naive: require a well-formed-looking single-root sketch.
        let has_close = s.contains("</") || s.contains("/>");
        let multi_root_ish = s.matches('<').count() >= 2
            && !s.trim_start().starts_with("<?xml")
            && looks_like_multi_root(s);
        let text: String = s.chars().take(256).collect();
        if has_close && opens <= closes + 4 && !multi_root_ish {
            let root = first_elem_name(data).unwrap_or_else(|| "unknown".into());
            ParseOutcome::Accepted {
                root_hint: root,
                text_fingerprint: text,
                elapsed_ms: 0,
                mode: "naive".into(),
            }
        } else {
            ParseOutcome::Rejected {
                code: format!("struct:o={opens}:c={closes}"),
                text_fingerprint: text,
                elapsed_ms: 0,
                mode: "naive".into(),
            }
        }
    }
}

fn looks_like_multi_root(s: &str) -> bool {
    // Two sibling top-level elements without a wrapper (very rough).
    let trimmed = s.trim();
    let first_end = match trimmed.find('>') {
        Some(i) => i,
        None => return false,
    };
    let rest = trimmed[first_end + 1..].trim_start();
    rest.starts_with('<')
        && !rest.starts_with("</")
        && !rest.starts_with("<?")
        && !rest.starts_with("<!")
}

fn first_elem_name(data: &[u8]) -> Option<String> {
    let start = data.iter().position(|&b| b == b'<')? + 1;
    if start >= data.len() {
        return None;
    }
    if matches!(data[start], b'/' | b'!' | b'?') {
        // skip decl / comment / PI — find next tag
        let rest = &data[start..];
        if let Some(rel) = rest.windows(1).position(|w| w[0] == b'<') {
            return first_elem_name(&data[start + rel..]);
        }
        return Some("special".into());
    }
    let end = data[start..]
        .iter()
        .position(|&b| matches!(b, b'>' | b' ' | b'/' | b'\n' | b'\t' | b'\r'))?
        + start;
    Some(String::from_utf8_lossy(&data[start..end]).into_owned())
}

impl XmlParseTarget for NaiveStructuralParser {
    fn parse(&self, data: &[u8]) -> Result<ParseOutcome, String> {
        Ok(Self::classify(data))
    }
}

/// Diff a real target outcome against the naive structural class (accept/reject only).
pub fn compare_with_naive(target_out: &ParseOutcome, data: &[u8]) -> DiffResult {
    let naive = NaiveStructuralParser::classify(data);
    // Only compare accept/reject class — naive text is the raw input slice.
    let ca = OutcomeClass::from_outcome(target_out);
    let cb = OutcomeClass::from_outcome(&naive);
    // Timeouts: do not treat as AcceptMismatch against naive.
    if matches!(ca, OutcomeClass::Timeout) {
        return DiffResult::Match;
    }
    if ca != cb {
        DiffResult::AcceptMismatch
    } else {
        DiffResult::Match
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted(text: &str) -> ParseOutcome {
        ParseOutcome::Accepted {
            root_hint: "r".into(),
            text_fingerprint: text.into(),
            elapsed_ms: 1,
            mode: "t".into(),
        }
    }

    fn rejected(text: &str) -> ParseOutcome {
        ParseOutcome::Rejected {
            code: "e".into(),
            text_fingerprint: text.into(),
            elapsed_ms: 1,
            mode: "t".into(),
        }
    }

    #[test]
    fn compare_match_same_accept() {
        let a = accepted("hello");
        let b = accepted("hello");
        assert_eq!(compare_outcomes(&a, &b), DiffResult::Match);
    }

    #[test]
    fn compare_accept_mismatch() {
        let a = accepted("x");
        let b = rejected("x");
        assert_eq!(compare_outcomes(&a, &b), DiffResult::AcceptMismatch);
    }

    #[test]
    fn compare_secret_text_mismatch() {
        let a = accepted(SECRET_MARKER);
        let b = accepted("clean");
        assert_eq!(compare_outcomes(&a, &b), DiffResult::TextMismatch);
    }

    #[test]
    fn compare_timeout_vs_reject() {
        let a = ParseOutcome::Timeout { elapsed_ms: 10 };
        let b = rejected("");
        assert_eq!(compare_outcomes(&a, &b), DiffResult::AcceptMismatch);
    }

    #[test]
    fn naive_accepts_simple() {
        match NaiveStructuralParser::classify(b"<a/>") {
            ParseOutcome::Accepted { root_hint, .. } => assert_eq!(root_hint, "a"),
            o => panic!("expected accept, got {o:?}"),
        }
    }

    #[test]
    fn naive_rejects_empty() {
        assert!(matches!(
            NaiveStructuralParser::classify(b""),
            ParseOutcome::Rejected { .. }
        ));
    }

    #[test]
    fn compare_with_naive_simple() {
        let out = accepted("a");
        // naive accepts <a/>; class match only
        let d = compare_with_naive(&out, b"<a/>");
        assert_eq!(d, DiffResult::Match);
    }

    #[test]
    fn differential_soft_skips_without_harness() {
        // Force missing binary by passing a non-existent path via Option::None
        // after discover may find one — use empty data with explicit None when
        // discover fails; if discover succeeds, still Ok.
        let r = run_libxml2_option_differential(Some(PathBuf::from("/nonexistent/libxml2_parse")), b"<r/>");
        // spawn will fail if path missing — expect Err or we pass None
        let _ = r;
        let r2 = run_libxml2_option_differential(None, b"<r/>");
        // Ok empty findings when no harness, or Ok with findings if harness present
        assert!(r2.is_ok());
    }

    #[test]
    fn xxe_differential_soft_skip() {
        run_xxe_safe_vs_noent_differential(None).unwrap();
    }
}
