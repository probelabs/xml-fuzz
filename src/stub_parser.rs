//! In-crate reference XML "parser" for exercising gates without libxml2.

use crate::fuzz::{ParseOutcome, XmlParseTarget};

/// Extremely small wellformed-ish checker + fingerprint.
#[derive(Debug, Default, Clone, Copy)]
pub struct StubXmlParser;

impl StubXmlParser {
    fn scan(data: &[u8]) -> ParseOutcome {
        if data.is_empty() {
            return ParseOutcome::Rejected {
                code: "empty".into(),
                text_fingerprint: String::new(),
                elapsed_ms: 0,
                mode: "stub".into(),
            };
        }
        let opens = data.iter().filter(|&&b| b == b'<').count();
        let closes = data.iter().filter(|&&b| b == b'>').count();
        let has_root_close =
            data.windows(2).any(|w| w == b"</") || data.windows(2).any(|w| w == b"/>");
        let invalid_utf8 = std::str::from_utf8(data).is_err();
        let text_fingerprint = String::from_utf8_lossy(data).chars().take(256).collect();

        if opens == 0 {
            return ParseOutcome::Rejected {
                code: "no_tag".into(),
                text_fingerprint,
                elapsed_ms: 0,
                mode: "stub".into(),
            };
        }
        if has_root_close && closes > 0 && opens <= closes + 3 && !invalid_utf8 {
            let root_hint = extract_first_name(data).unwrap_or_else(|| "unknown".into());
            ParseOutcome::Accepted {
                root_hint,
                text_fingerprint,
                elapsed_ms: 0,
                mode: "stub".into(),
            }
        } else {
            ParseOutcome::Rejected {
                code: format!("stub_reject:o={opens}:c={closes}:utf8={}", !invalid_utf8),
                text_fingerprint,
                elapsed_ms: 0,
                mode: "stub".into(),
            }
        }
    }
}

fn extract_first_name(data: &[u8]) -> Option<String> {
    let start = data.iter().position(|&b| b == b'<')? + 1;
    if start >= data.len() {
        return None;
    }
    if data[start] == b'/' || data[start] == b'!' || data[start] == b'?' {
        return Some(format!("special:{}", data[start] as char));
    }
    let end = data[start..]
        .iter()
        .position(|&b| b == b'>' || b == b' ' || b == b'/' || b == b'\n' || b == b'\t')?
        + start;
    Some(String::from_utf8_lossy(&data[start..end]).into_owned())
}

impl XmlParseTarget for StubXmlParser {
    fn parse(&self, data: &[u8]) -> Result<ParseOutcome, String> {
        Ok(Self::scan(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_simple() {
        let p = StubXmlParser;
        match p.parse(b"<a/>").unwrap() {
            ParseOutcome::Accepted { root_hint, .. } => assert_eq!(root_hint, "a"),
            _ => panic!("expected accept"),
        }
    }

    #[test]
    fn rejects_empty() {
        let p = StubXmlParser;
        assert!(matches!(
            p.parse(b"").unwrap(),
            ParseOutcome::Rejected { .. }
        ));
    }
}
