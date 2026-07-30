//! Correctness gates for an XML parser under test.
//!
//! | Gate | Invariant |
//! |------|-----------|
//! | [`no_panic`] | Function returns normally (no unwind). |
//! | [`clean_fail`] | Untrusted/malformed input yields Ok(parsed) or Ok(None/error), never panic. |
//! | [`determinism`] | Two runs produce identical results. |
//! | [`deep_nesting_safe`] | Deep nesting fails closed (error or success) without stack blow / panic. |
//! | [`round_trip`] | parse → serialize → parse equivalent when both succeed. |
//! | [`output_valid`] | Optional validation returns typed result, never panics. |
//! | [`resource_bound`] | Amplification heuristic on elapsed + text fingerprint length. |
//! | [`semantic_schema_valid`] | Schema+instance well-formed-looking + validate Ok. |

use std::fmt::Debug;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateKind {
    Panic,
    OutputInvalid,
    RoundTripMismatch,
    NonDeterminism,
    InvariantViolation,
}

#[derive(Debug, Clone)]
pub struct GateFailure {
    pub kind: GateKind,
    pub label: String,
    pub message: String,
}

impl GateFailure {
    pub fn new(kind: GateKind, label: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind,
            label: label.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for GateFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}] {}: {}", self.kind, self.label, self.message)
    }
}

impl std::error::Error for GateFailure {}

fn panic_to_string(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

/// Gate 1 — NO-PANIC.
pub fn no_panic<F, R>(label: impl Into<String>, f: F) -> Result<R, GateFailure>
where
    F: FnOnce() -> R,
{
    let label = label.into();
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(v) => Ok(v),
        Err(payload) => Err(GateFailure::new(
            GateKind::Panic,
            label,
            format!("panicked: {}", panic_to_string(&payload)),
        )),
    }
}

/// Gate 2 — CLEAN-FAIL: parse may accept or reject, but must not panic.
///
/// `parse` should return `Ok(Some(ast))` / `Ok(true)` style success, or
/// `Ok(None)` / `Err` for clean rejection. Panic is a finding.
pub fn clean_fail<F, R>(label: impl Into<String>, f: F) -> Result<R, GateFailure>
where
    F: FnOnce() -> R,
{
    no_panic(label, f)
}

/// Gate 3 — DETERMINISM: two pure parses of the same input must match.
pub fn determinism<F, R>(label: impl Into<String>, input: &[u8], parse: F) -> Result<(), GateFailure>
where
    F: Fn(&[u8]) -> R,
    R: PartialEq + Debug,
{
    let label = label.into();
    let a = no_panic(format!("{label}/a"), || parse(input))?;
    let b = no_panic(format!("{label}/b"), || parse(input))?;
    if a == b {
        Ok(())
    } else {
        Err(GateFailure::new(
            GateKind::NonDeterminism,
            label,
            format!("mismatch: {a:?} vs {b:?}"),
        ))
    }
}

/// Gate 4 — DEEP-NESTING-SAFE: deep document must not panic (error or success OK).
pub fn deep_nesting_safe<F, R>(label: impl Into<String>, deep_input: &[u8], parse: F) -> Result<R, GateFailure>
where
    F: FnOnce(&[u8]) -> R,
{
    let label = label.into();
    no_panic(label, || parse(deep_input))
}

/// Gate 5 — ROUND-TRIP: if parse succeeds and print succeeds, re-parse equals first.
pub fn round_trip<P, S, A>(
    label: impl Into<String>,
    input: &[u8],
    parse: P,
    serialize: S,
) -> Result<(), GateFailure>
where
    P: Fn(&[u8]) -> Result<A, String>,
    S: Fn(&A) -> Result<Vec<u8>, String>,
    A: PartialEq + Debug,
{
    let label = label.into();
    let first = match no_panic(format!("{label}/parse1"), || parse(input))? {
        Ok(ast) => ast,
        Err(_) => return Ok(()), // clean reject — round-trip N/A
    };
    let printed = match no_panic(format!("{label}/print"), || serialize(&first))? {
        Ok(b) => b,
        Err(e) => {
            return Err(GateFailure::new(
                GateKind::OutputInvalid,
                label,
                format!("serialize failed: {e}"),
            ));
        }
    };
    let second = match no_panic(format!("{label}/parse2"), || parse(&printed))? {
        Ok(ast) => ast,
        Err(e) => {
            return Err(GateFailure::new(
                GateKind::RoundTripMismatch,
                label,
                format!("re-parse failed: {e}"),
            ));
        }
    };
    if first == second {
        Ok(())
    } else {
        Err(GateFailure::new(
            GateKind::RoundTripMismatch,
            label,
            format!("AST mismatch after print"),
        ))
    }
}

/// Gate 6 — OUTPUT-VALID: validate returns Ok/Err without panic.
pub fn output_valid<F, E>(label: impl Into<String>, validate: F) -> Result<(), GateFailure>
where
    F: FnOnce() -> Result<(), E>,
    E: Debug,
{
    let label = label.into();
    match no_panic(label.clone(), validate)? {
        Ok(()) | Err(_) => Ok(()),
    }
}

/// Gate 7 — RESOURCE BUDGET: `f` must complete within `budget` (wall clock).
///
/// Catches amplification / hang DoS that no-panic alone misses. Uses a worker
/// thread + `recv_timeout`; on timeout returns a finding (the worker may still
/// run until process exit — pair with harness-level kill for hard caps).
pub fn within_budget<F, R>(
    label: impl Into<String>,
    budget: std::time::Duration,
    f: F,
) -> Result<R, GateFailure>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    use std::sync::mpsc;
    use std::thread;

    let label = label.into();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let v = f();
        let _ = tx.send(v);
    });
    match rx.recv_timeout(budget) {
        Ok(v) => Ok(v),
        Err(_) => Err(GateFailure::new(
            GateKind::InvariantViolation,
            label,
            format!("exceeded budget {:?}", budget),
        )),
    }
}

/// Same-thread budget check (no kill). Fails if elapsed > budget after `f` returns.
pub fn within_budget_sync<F, R>(
    label: impl Into<String>,
    budget: std::time::Duration,
    f: F,
) -> Result<R, GateFailure>
where
    F: FnOnce() -> R,
{
    use std::time::Instant;
    let label = label.into();
    let start = Instant::now();
    let v = no_panic(format!("{label}/run"), f)?;
    let elapsed = start.elapsed();
    if elapsed > budget {
        Err(GateFailure::new(
            GateKind::InvariantViolation,
            label,
            format!("took {:?} > budget {:?}", elapsed, budget),
        ))
    } else {
        Ok(v)
    }
}

/// Gate 8 — RESOURCE BOUND: amplification heuristic on a finished outcome.
///
/// Fails when wall-clock `elapsed_ms` exceeds `max_elapsed` **or** the text
/// fingerprint length exceeds `max_text_len` (entity expansion / billion laughs
/// class). Timeouts are treated as resource violations when elapsed is known.
pub fn resource_bound(
    label: impl Into<String>,
    max_elapsed: std::time::Duration,
    max_text_len: usize,
    outcome: &crate::fuzz::ParseOutcome,
) -> Result<(), GateFailure> {
    use crate::fuzz::ParseOutcome;
    let label = label.into();
    let max_ms = max_elapsed.as_millis() as u64;
    let elapsed = outcome.elapsed_ms();
    let text_len = outcome.text().len();

    if matches!(outcome, ParseOutcome::Timeout { .. }) && elapsed > max_ms {
        return Err(GateFailure::new(
            GateKind::InvariantViolation,
            label,
            format!(
                "timeout after {}ms > max_elapsed {}ms (amplification heuristic)",
                elapsed, max_ms
            ),
        ));
    }
    if elapsed > max_ms {
        return Err(GateFailure::new(
            GateKind::InvariantViolation,
            label,
            format!("elapsed {}ms > max_elapsed {}ms", elapsed, max_ms),
        ));
    }
    if text_len > max_text_len {
        return Err(GateFailure::new(
            GateKind::InvariantViolation,
            label,
            format!(
                "text fingerprint len {} > max_text_len {} (possible expansion)",
                text_len, max_text_len
            ),
        ));
    }
    Ok(())
}

/// Gate 9 — SEMANTIC SCHEMA VALID (structural prefilter + harness validate).
///
/// When both `schema` and `instance` look well-formed (naive structural accept),
/// and `validate` returns `Ok(())`, the gate passes. If either side is not
/// well-formed-looking, the gate is a soft pass (N/A). If both look well-formed
/// but validate returns `Err`, that is a finding only when `strict` is true;
/// otherwise soft-pass (schema may be incomplete sketches).
///
/// `validate` is typically a closure that runs the multi-API harness
/// `--api=schema-valid` with `schema\n---SPLIT---\ninstance`.
pub fn semantic_schema_valid<F, E>(
    label: impl Into<String>,
    schema: &[u8],
    instance: &[u8],
    strict: bool,
    validate: F,
) -> Result<(), GateFailure>
where
    F: FnOnce(&[u8], &[u8]) -> Result<(), E>,
    E: Debug,
{
    use crate::differential::NaiveStructuralParser;
    use crate::fuzz::ParseOutcome;

    let label = label.into();
    let schema_ok = matches!(
        NaiveStructuralParser::classify(schema),
        ParseOutcome::Accepted { .. }
    );
    let instance_ok = matches!(
        NaiveStructuralParser::classify(instance),
        ParseOutcome::Accepted { .. }
    );

    if !schema_ok || !instance_ok {
        // Not both well-formed-looking — semantic validate N/A.
        return Ok(());
    }

    match no_panic(format!("{label}/validate"), || validate(schema, instance))? {
        Ok(()) => Ok(()),
        Err(e) => {
            if strict {
                Err(GateFailure::new(
                    GateKind::OutputInvalid,
                    label,
                    format!("schema+instance well-formed-looking but validate failed: {e:?}"),
                ))
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzz::ParseOutcome;
    use std::time::Duration;

    #[test]
    fn no_panic_ok() {
        assert_eq!(no_panic("x", || 42).unwrap(), 42);
    }

    #[test]
    fn no_panic_catches() {
        let err = no_panic("x", || panic!("boom")).unwrap_err();
        assert_eq!(err.kind, GateKind::Panic);
    }

    #[test]
    fn determinism_ok() {
        determinism("d", b"<a/>", |b| b.to_vec()).unwrap();
    }

    #[test]
    fn resource_bound_ok() {
        let out = ParseOutcome::Accepted {
            root_hint: "r".into(),
            text_fingerprint: "hi".into(),
            elapsed_ms: 5,
            mode: "t".into(),
        };
        resource_bound("rb", Duration::from_millis(100), 64, &out).unwrap();
    }

    #[test]
    fn resource_bound_elapsed_fail() {
        let out = ParseOutcome::Accepted {
            root_hint: "r".into(),
            text_fingerprint: String::new(),
            elapsed_ms: 5000,
            mode: "t".into(),
        };
        let e = resource_bound("rb", Duration::from_millis(10), 1_000_000, &out).unwrap_err();
        assert_eq!(e.kind, GateKind::InvariantViolation);
    }

    #[test]
    fn resource_bound_text_len_fail() {
        let out = ParseOutcome::Accepted {
            root_hint: "r".into(),
            text_fingerprint: "x".repeat(100),
            elapsed_ms: 1,
            mode: "t".into(),
        };
        let e = resource_bound("rb", Duration::from_secs(1), 10, &out).unwrap_err();
        assert!(e.message.contains("text fingerprint"));
    }

    #[test]
    fn semantic_schema_skips_malformed() {
        semantic_schema_valid("s", b"<not", b"<r/>", true, |_, _| {
            Err::<(), &str>("should not run")
        })
        .unwrap();
    }

    #[test]
    fn semantic_schema_ok_when_validate_ok() {
        semantic_schema_valid("s", b"<schema/>", b"<r/>", true, |_, _| Ok::<(), &str>(()))
            .unwrap();
    }

    #[test]
    fn semantic_schema_strict_fails_validate_err() {
        let e = semantic_schema_valid("s", b"<schema/>", b"<r/>", true, |_, _| {
            Err::<(), &str>("bad")
        })
        .unwrap_err();
        assert_eq!(e.kind, GateKind::OutputInvalid);
    }

    #[test]
    fn semantic_schema_nonstrict_soft_pass() {
        semantic_schema_valid("s", b"<schema/>", b"<r/>", false, |_, _| {
            Err::<(), &str>("bad")
        })
        .unwrap();
    }
}
