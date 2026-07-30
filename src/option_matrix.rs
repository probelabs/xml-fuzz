//! Option × API expectation matrix for libxml2 harness soft-checks.
//!
//! Each row names a profile (`LibXml2Options` + optional `LibXml2Api`), a
//! fixed probe document, and an expectation (`Accept`, `Reject`, or
//! `NoSecretLeak`). Missing harness binary soft-skips the whole matrix.

use crate::apis::LibXml2Api;
use crate::fuzz::{ParseOutcome, XmlParseTarget};
use crate::libxml2_multi::LibXml2MultiHarness;
use crate::libxml2_target::{LibXml2Harness, LibXml2Options};
use crate::xxe_policy::{self, SECRET_MARKER};
use std::path::PathBuf;
use std::time::Duration;

/// What a matrix row expects from a single harness invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixExpect {
    /// Parse must accept (exit 0).
    Accept,
    /// Parse must reject (non-zero exit) or timeout is tolerated only if
    /// `allow_timeout` is set on the row.
    Reject,
    /// Accept or reject, but secret marker must not appear in text fingerprint.
    NoSecretLeak,
    /// Accept or reject; timeout not a hard fail (observe only).
    AcceptOrReject,
}

/// One matrix cell.
#[derive(Debug, Clone)]
pub struct OptionMatrixRow {
    pub name: &'static str,
    pub options: LibXml2Options,
    /// When `Some`, use multi-API harness with this API; else single parse harness.
    pub api: Option<LibXml2Api>,
    pub expect: MatrixExpect,
    /// Built-in probe document kind.
    pub doc: MatrixDoc,
    pub allow_timeout: bool,
}

/// Probe document selector for matrix rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixDoc {
    /// Minimal well-formed `<r/>`.
    MinimalWellformed,
    /// Clearly broken markup.
    BrokenMarkup,
    /// XXE sandbox entity expansion attempt.
    XxeSandbox,
    /// Empty input.
    Empty,
}

impl MatrixDoc {
    pub fn bytes(self, paths: Option<&xxe_policy::SandboxPaths>) -> Vec<u8> {
        match self {
            MatrixDoc::MinimalWellformed => b"<r/>".to_vec(),
            MatrixDoc::BrokenMarkup => b"<r><unclosed".to_vec(),
            MatrixDoc::Empty => Vec::new(),
            MatrixDoc::XxeSandbox => {
                let uri = paths
                    .map(|p| p.secret_uri.as_str())
                    .unwrap_or("file:///nonexistent-xml-fuzz-secret");
                xxe_policy::xxe_sandbox_document(uri)
            }
        }
    }
}

/// Default option matrix covering safe / recover / noent+noxxe and basic APIs.
pub fn default_option_matrix() -> Vec<OptionMatrixRow> {
    let timeout = Duration::from_secs(2);
    vec![
        OptionMatrixRow {
            name: "safe_accepts_minimal",
            options: LibXml2Options {
                nonet: true,
                no_xxe: true,
                timeout,
                ..Default::default()
            },
            api: None,
            expect: MatrixExpect::Accept,
            doc: MatrixDoc::MinimalWellformed,
            allow_timeout: false,
        },
        OptionMatrixRow {
            name: "safe_rejects_broken",
            options: LibXml2Options {
                nonet: true,
                no_xxe: true,
                timeout,
                ..Default::default()
            },
            api: None,
            expect: MatrixExpect::Reject,
            doc: MatrixDoc::BrokenMarkup,
            allow_timeout: false,
        },
        OptionMatrixRow {
            name: "recover_accept_or_reject_broken",
            options: LibXml2Options {
                recover: true,
                nonet: true,
                no_xxe: true,
                timeout,
                ..Default::default()
            },
            api: None,
            expect: MatrixExpect::AcceptOrReject,
            doc: MatrixDoc::BrokenMarkup,
            allow_timeout: false,
        },
        OptionMatrixRow {
            name: "noent_noxxe_no_secret_on_xxe",
            options: LibXml2Options {
                noent: true,
                nonet: true,
                no_xxe: true,
                timeout,
                ..Default::default()
            },
            api: None,
            expect: MatrixExpect::NoSecretLeak,
            doc: MatrixDoc::XxeSandbox,
            allow_timeout: true,
        },
        OptionMatrixRow {
            name: "safe_no_secret_on_xxe",
            options: LibXml2Options::safe_untrusted(),
            api: None,
            expect: MatrixExpect::NoSecretLeak,
            doc: MatrixDoc::XxeSandbox,
            allow_timeout: true,
        },
        OptionMatrixRow {
            name: "empty_reject",
            options: LibXml2Options::safe_untrusted(),
            api: None,
            expect: MatrixExpect::Reject,
            doc: MatrixDoc::Empty,
            allow_timeout: false,
        },
        OptionMatrixRow {
            name: "xml_memory_minimal_accept",
            options: LibXml2Options::safe_untrusted(),
            api: Some(LibXml2Api::XmlMemory),
            expect: MatrixExpect::Accept,
            doc: MatrixDoc::MinimalWellformed,
            allow_timeout: false,
        },
        OptionMatrixRow {
            name: "xml_reader_minimal_accept",
            options: LibXml2Options::safe_untrusted(),
            api: Some(LibXml2Api::XmlReader),
            expect: MatrixExpect::Accept,
            doc: MatrixDoc::MinimalWellformed,
            allow_timeout: false,
        },
        OptionMatrixRow {
            name: "xml_push_minimal_accept",
            options: LibXml2Options {
                nonet: true,
                no_xxe: true,
                chunk_size: Some(1),
                timeout,
                ..Default::default()
            },
            api: Some(LibXml2Api::XmlPush),
            expect: MatrixExpect::Accept,
            doc: MatrixDoc::MinimalWellformed,
            allow_timeout: false,
        },
    ]
}

fn outcome_leaks(out: &ParseOutcome) -> bool {
    out.text().contains(SECRET_MARKER)
        || match out {
            ParseOutcome::Accepted { root_hint, .. } => root_hint.contains(SECRET_MARKER),
            ParseOutcome::Rejected { code, .. } => code.contains(SECRET_MARKER),
            ParseOutcome::Timeout { .. } => false,
        }
}

fn check_row(row: &OptionMatrixRow, out: &ParseOutcome) -> Result<(), String> {
    if matches!(out, ParseOutcome::Timeout { .. }) {
        if row.allow_timeout {
            return Ok(());
        }
        return Err(format!("{}: unexpected timeout", row.name));
    }
    match row.expect {
        MatrixExpect::Accept => match out {
            ParseOutcome::Accepted { .. } => Ok(()),
            ParseOutcome::Rejected { code, .. } => {
                Err(format!("{}: expected Accept, got Rejected({code})", row.name))
            }
            ParseOutcome::Timeout { .. } => unreachable!(),
        },
        MatrixExpect::Reject => match out {
            ParseOutcome::Rejected { .. } => Ok(()),
            ParseOutcome::Accepted { .. } => {
                Err(format!("{}: expected Reject, got Accept", row.name))
            }
            ParseOutcome::Timeout { .. } => unreachable!(),
        },
        MatrixExpect::NoSecretLeak => {
            if outcome_leaks(out) {
                Err(format!(
                    "{}: SECRET leaked in outcome={:?}",
                    row.name, out
                ))
            } else {
                Ok(())
            }
        }
        MatrixExpect::AcceptOrReject => match out {
            ParseOutcome::Accepted { .. } | ParseOutcome::Rejected { .. } => Ok(()),
            ParseOutcome::Timeout { .. } => unreachable!(),
        },
    }
}

/// Run the option matrix. Soft-skip (Ok) if neither parse nor multi harness binary exists.
///
/// `harness_bin` is the single-parse harness (`libxml2_parse`). Multi-API rows
/// use `LibXml2MultiHarness::discover()` independently when `api` is set.
pub fn run_option_matrix(harness_bin: Option<PathBuf>) -> Result<(), String> {
    let parse_bin = harness_bin.or_else(|| LibXml2Harness::discover().map(|h| h.binary));
    let multi_bin = LibXml2MultiHarness::discover().map(|h| h.binary);

    if parse_bin.is_none() && multi_bin.is_none() {
        return Ok(());
    }

    let needs_sandbox = default_option_matrix()
        .iter()
        .any(|r| matches!(r.doc, MatrixDoc::XxeSandbox));
    let paths = if needs_sandbox {
        Some(xxe_policy::ensure_sandbox_fixtures().map_err(|e| e.to_string())?)
    } else {
        None
    };

    for row in default_option_matrix() {
        let doc = row.doc.bytes(paths.as_ref());
        let out = if let Some(api) = row.api {
            let bin = match &multi_bin {
                Some(b) => b.clone(),
                None => continue, // soft-skip multi rows without multi harness
            };
            let h = LibXml2MultiHarness {
                binary: bin,
                api,
                options: row.options.clone(),
            };
            h.parse(&doc)
                .map_err(|e| format!("{}: {e}", row.name))?
        } else {
            let bin = match &parse_bin {
                Some(b) => b.clone(),
                None => continue,
            };
            let h = LibXml2Harness {
                binary: bin,
                options: row.options.clone(),
            };
            h.parse(&doc)
                .map_err(|e| format!("{}: {e}", row.name))?
        };
        check_row(&row, &out)?;
    }
    Ok(())
}

/// Pure-logic evaluation of a row against a synthetic outcome (unit tests).
pub fn evaluate_row_outcome(row: &OptionMatrixRow, out: &ParseOutcome) -> Result<(), String> {
    check_row(row, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_nonempty() {
        assert!(default_option_matrix().len() >= 5);
    }

    #[test]
    fn evaluate_accept_ok() {
        let row = &default_option_matrix()[0];
        let out = ParseOutcome::Accepted {
            root_hint: "r".into(),
            text_fingerprint: String::new(),
            elapsed_ms: 0,
            mode: "t".into(),
        };
        evaluate_row_outcome(row, &out).unwrap();
    }

    #[test]
    fn evaluate_accept_fails_on_reject() {
        let row = &default_option_matrix()[0];
        assert_eq!(row.expect, MatrixExpect::Accept);
        let out = ParseOutcome::Rejected {
            code: "x".into(),
            text_fingerprint: String::new(),
            elapsed_ms: 0,
            mode: "t".into(),
        };
        assert!(evaluate_row_outcome(row, &out).is_err());
    }

    #[test]
    fn evaluate_no_secret_leak() {
        let row = default_option_matrix()
            .into_iter()
            .find(|r| r.expect == MatrixExpect::NoSecretLeak)
            .unwrap();
        let clean = ParseOutcome::Accepted {
            root_hint: "r".into(),
            text_fingerprint: "ok".into(),
            elapsed_ms: 0,
            mode: "t".into(),
        };
        evaluate_row_outcome(&row, &clean).unwrap();
        let leak = ParseOutcome::Accepted {
            root_hint: "r".into(),
            text_fingerprint: SECRET_MARKER.into(),
            elapsed_ms: 0,
            mode: "t".into(),
        };
        assert!(evaluate_row_outcome(&row, &leak).is_err());
    }

    #[test]
    fn matrix_doc_minimal() {
        assert_eq!(MatrixDoc::MinimalWellformed.bytes(None), b"<r/>");
    }

    #[test]
    fn run_matrix_soft_skip() {
        // Nonexistent bin: multi may still discover; force both missing by
        // calling with None — soft skip only when neither binary exists.
        run_option_matrix(None).unwrap();
    }
}
