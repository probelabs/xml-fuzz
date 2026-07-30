//! Curated seed corpus covering major XML bug-class / nuance families.
//!
//! Families (verification inventory):
//! - (a) encoding / BOM / invalid UTF-8
//! - (b) element / attribute / name edges
//! - (c) deep nesting
//! - (d) DTD / entity constructs
//! - (e) namespaces
//! - (f) CDATA / comment / PI
//! - (g) structural truncation / unbalanced markup

/// One corpus seed with a stable id and family tags.
#[derive(Debug, Clone, Copy)]
pub struct CorpusEntry {
    pub id: &'static str,
    pub family: &'static str,
    pub data: &'static [u8],
}

/// Full seed table.
pub const CORPUS: &[CorpusEntry] = &[
    // --- (a) encoding / BOM / invalid UTF-8 ---
    CorpusEntry {
        id: "enc-utf8-decl",
        family: "encoding",
        data: b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><r/>",
    },
    CorpusEntry {
        id: "enc-bom-utf8",
        family: "encoding",
        data: b"\xEF\xBB\xBF<?xml version=\"1.0\"?><r/>",
    },
    CorpusEntry {
        id: "enc-overlong",
        family: "encoding",
        data: b"<?xml version=\"1.0\"?><r>\xC0\xAF</r>",
    },
    CorpusEntry {
        id: "enc-ff-byte",
        family: "encoding",
        data: b"<?xml version=\"1.0\"?><r>\xFF</r>",
    },
    CorpusEntry {
        id: "enc-trunc-utf8",
        family: "encoding",
        data: b"<?xml version=\"1.0\"?><r>\xE2\x82</r>",
    },
    CorpusEntry {
        id: "enc-latin1-nbsp",
        family: "encoding",
        data: b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><r>\xA0</r>",
    },
    CorpusEntry {
        id: "enc-nul-text",
        family: "encoding",
        data: b"<?xml version=\"1.0\"?><r>a\0b</r>",
    },
    // --- (b) names / attributes ---
    CorpusEntry {
        id: "name-simple",
        family: "names",
        data: b"<a-b.c_x/>",
    },
    CorpusEntry {
        id: "name-digit-start",
        family: "names",
        data: b"<1bad/>",
    },
    CorpusEntry {
        id: "name-colon-lead",
        family: "names",
        data: b"<:x/>",
    },
    CorpusEntry {
        id: "attr-dup",
        family: "names",
        data: b"<r a=\"1\" a=\"2\"/>",
    },
    CorpusEntry {
        id: "attr-entities",
        family: "names",
        data: b"<r a=\"&lt;&amp;&gt;\"/>",
    },
    CorpusEntry {
        id: "attr-charref",
        family: "names",
        data: b"<r a=\"&#65;&#x42;\"/>",
    },
    CorpusEntry {
        id: "attr-unterm",
        family: "names",
        data: b"<r a=\"unterminated>x</r>",
    },
    // --- (c) deep nesting ---
    CorpusEntry {
        id: "nest-10-closed",
        family: "nesting",
        data: b"<?xml version=\"1.0\"?><n><n><n><n><n><n><n><n><n><n>x</n></n></n></n></n></n></n></n></n></n>",
    },
    CorpusEntry {
        id: "nest-unclosed",
        family: "nesting",
        data: b"<n><n><n><n><n>x",
    },
    // --- (d) DTD / entities ---
    CorpusEntry {
        id: "dtd-int-subset",
        family: "dtd_entity",
        data: b"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY e \"hi\">]><r>&e;</r>",
    },
    CorpusEntry {
        id: "dtd-attlist-default",
        family: "dtd_entity",
        data: b"<?xml version=\"1.0\"?><!DOCTYPE r [<!ATTLIST r a CDATA \"d\">]><r/>",
    },
    CorpusEntry {
        // Sandbox path placeholder — runtime xxe_policy rewrites to real fixture URI.
        // Static corpus uses a clearly non-host path under fixtures/sandbox/.
        id: "dtd-xxe-sketch",
        family: "dtd_entity",
        data: b"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file://./fixtures/sandbox/secret.txt\">]><r>&xxe;</r>",
    },
    CorpusEntry {
        id: "dtd-pe-depth-internal",
        family: "dtd_entity",
        data: b"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % a \"<!ENTITY % b '<!ENTITY e \"hi\">'>\"> %a; %b;]><r>&e;</r>",
    },
    CorpusEntry {
        id: "dtd-pe-external-sandbox",
        family: "dtd_entity",
        data: b"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % ext SYSTEM \"file://./fixtures/sandbox/pe.dtd\"> %ext;]><r>&e;</r>",
    },
    CorpusEntry {
        id: "dtd-expand-small",
        family: "dtd_entity",
        data: b"<!DOCTYPE r [<!ENTITY a \"aa\"><!ENTITY b \"&a;&a;&a;&a;\">]><r>&b;</r>",
    },
    CorpusEntry {
        id: "dtd-pe-sketch",
        family: "dtd_entity",
        data: b"<!DOCTYPE r [<!ENTITY % p \"<!ENTITY e 'z'>\"> %p;]><r>&e;</r>",
    },
    // --- (e) namespaces ---
    CorpusEntry {
        id: "ns-default",
        family: "namespaces",
        data: b"<r xmlns=\"urn:x\"><c/></r>",
    },
    CorpusEntry {
        id: "ns-prefixed",
        family: "namespaces",
        data: b"<a:r xmlns:a=\"urn:a\"><a:c a:v=\"1\"/></a:r>",
    },
    CorpusEntry {
        id: "ns-xml-lang",
        family: "namespaces",
        data: b"<r xml:lang=\"en\" xmlns:xml=\"http://www.w3.org/XML/1998/namespace\"/>",
    },
    CorpusEntry {
        id: "ns-rebind",
        family: "namespaces",
        data: b"<r xmlns:a=\"urn:1\"><c xmlns:a=\"urn:2\"><a:x/></c></r>",
    },
    // --- (f) CDATA / comment / PI ---
    CorpusEntry {
        id: "cdata-basic",
        family: "cdata_comment_pi",
        data: b"<r><![CDATA[1 < 2 & 3]]></r>",
    },
    CorpusEntry {
        id: "cdata-unclosed",
        family: "cdata_comment_pi",
        data: b"<r><![CDATA[oops</r>",
    },
    CorpusEntry {
        id: "comment-basic",
        family: "cdata_comment_pi",
        data: b"<r><!-- hello --></r>",
    },
    CorpusEntry {
        id: "comment-bad-double-dash",
        family: "cdata_comment_pi",
        data: b"<r><!-- -- --></r>",
    },
    CorpusEntry {
        id: "pi-basic",
        family: "cdata_comment_pi",
        data: b"<?xml version=\"1.0\"?><?pi data?><r/>",
    },
    CorpusEntry {
        id: "pi-stylesheet",
        family: "cdata_comment_pi",
        data: b"<?xml-stylesheet type=\"text/xsl\" href=\"a.xsl\"?><r/>",
    },
    // --- (g) structural truncation / unbalanced ---
    CorpusEntry {
        id: "struct-open-only",
        family: "structural",
        data: b"<root>",
    },
    CorpusEntry {
        id: "struct-mismatched",
        family: "structural",
        data: b"<a></b>",
    },
    CorpusEntry {
        id: "struct-multi-root",
        family: "structural",
        data: b"<a/><b/>",
    },
    CorpusEntry {
        id: "struct-decl-trunc",
        family: "structural",
        data: b"<?xml version=\"1.0\"",
    },
    CorpusEntry {
        id: "struct-lt-only",
        family: "structural",
        data: b"<",
    },
    // --- well-formed baselines ---
    CorpusEntry {
        id: "wf-minimal",
        family: "wellformed",
        data: b"<?xml version=\"1.0\"?><root>ok</root>",
    },
    CorpusEntry {
        id: "wf-mixed",
        family: "wellformed",
        data: b"<p>a<em>b</em>c</p>",
    },
    CorpusEntry {
        id: "wf-empty-selfclose",
        family: "wellformed",
        data: b"<a b=\"c\"/>",
    },
    // --- extended surfaces (ADHD depth) ---
    CorpusEntry {
        id: "xinclude-basic",
        family: "xinclude",
        data: b"<r xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"m.xml\"/></r>",
    },
    CorpusEntry {
        id: "xml11-space",
        family: "xml11_space",
        data: b"<?xml version=\"1.1\"?><r xml:space=\"preserve\">  x  </r>",
    },
    CorpusEntry {
        id: "xml-base",
        family: "xml11_space",
        data: b"<r xml:base=\"http://example.test/\"><c/></r>",
    },
    CorpusEntry {
        id: "xsi-schema",
        family: "schema_xsi",
        data: b"<r xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:noNamespaceSchemaLocation=\"r.xsd\"/>",
    },
    CorpusEntry {
        id: "chunk-friendly",
        family: "structural",
        data: b"<?xml version=\"1.0\"?>\n<root>\n<a/>\n</root>\n",
    },
    // --- deeper XInclude / PE / XML 1.1 / xsi:type ---
    CorpusEntry {
        id: "xinclude-fallback-text",
        family: "xinclude",
        data: b"<r xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"t.txt\" parse=\"text\"><xi:fallback>fb</xi:fallback></xi:include></r>",
    },
    CorpusEntry {
        id: "xinclude-multi-sibling",
        family: "xinclude",
        data: b"<r xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"a.xml\"/><xi:include href=\"b.xml\" parse=\"text\"/></r>",
    },
    CorpusEntry {
        id: "xinclude-nested-fallback",
        family: "xinclude",
        data: b"<r xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"o.xml\"><xi:fallback><xi:include href=\"i.xml\"><xi:fallback>end</xi:fallback></xi:include></xi:fallback></xi:include></r>",
    },
    CorpusEntry {
        id: "dtd-pe-chain-flat",
        family: "dtd_entity",
        data: b"<!DOCTYPE r [<!ENTITY % p0 \"<!ENTITY e 'deep'>\"><!ENTITY % p1 \"%p0;\"><!ENTITY % p2 \"%p1;\"> %p2;]><r>&e;</r>",
    },
    CorpusEntry {
        id: "xml11-restricted-charrefs",
        family: "xml11_space",
        data: b"<?xml version=\"1.1\"?><r>&#x1;&#x8;&#xB;&#xC;&#xE;&#x1F;</r>",
    },
    CorpusEntry {
        id: "xml11-nel-ls-refs",
        family: "xml11_space",
        data: b"<?xml version=\"1.1\"?><r>a&#x85;b&#x2028;c</r>",
    },
    CorpusEntry {
        id: "xsi-type-circle",
        family: "schema_xsi",
        data: b"<shape xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:t=\"urn:shapes\" xsi:type=\"t:Circle\"><radius>1</radius></shape>",
    },
    CorpusEntry {
        id: "xsi-nil",
        family: "schema_xsi",
        data: b"<r xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:nil=\"true\"/>",
    },
    // Optional inventory tags (not in REQUIRED_FAMILIES): HTML / XPath / RNG seeds
    CorpusEntry {
        id: "html-rawtext-script",
        family: "html",
        data: b"<html><body><script>var x=\"</script>\";</script></body></html>",
    },
    CorpusEntry {
        id: "html-meta-table",
        family: "html",
        data: b"<html><head><meta charset=utf-8></head><body><table><tr><td>1<td>2</table></body></html>",
    },
    CorpusEntry {
        id: "xpath-axes-union",
        family: "xpath",
        data: b"//a:* | //b:* | count(//*)",
    },
    CorpusEntry {
        id: "rng-interleave-sketch",
        family: "rng",
        data: b"<element name=\"r\" xmlns=\"http://relaxng.org/ns/structure/1.0\"><interleave><element name=\"a\"><text/></element><optional><element name=\"b\"><text/></element></optional></interleave></element>",
    },
    CorpusEntry {
        id: "xsd-abstract-type-sketch",
        family: "schema_xsi",
        data: b"<?xml version=\"1.0\"?><xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"><xs:complexType name=\"Shape\" abstract=\"true\"><xs:sequence><xs:element name=\"id\" type=\"xs:string\"/></xs:sequence></xs:complexType></xs:schema>",
    },
];

/// Iterate all seed byte slices (for `cargo fuzz` / harness AddCorpus style).
pub fn corpus_bytes() -> impl Iterator<Item = &'static [u8]> {
    CORPUS.iter().map(|e| e.data)
}

/// Entries with metadata.
pub fn corpus_entries() -> &'static [CorpusEntry] {
    CORPUS
}

/// Families present in the corpus (for coverage inventory tests).
pub fn corpus_families() -> Vec<&'static str> {
    let mut v: Vec<&str> = CORPUS.iter().map(|e| e.family).collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// Required verification families.
pub const REQUIRED_FAMILIES: &[&str] = &[
    "encoding",
    "names",
    "nesting",
    "dtd_entity",
    "namespaces",
    "cdata_comment_pi",
    "structural",
    "xinclude",
    "xml11_space",
    "schema_xsi",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_families_present() {
        let fams = corpus_families();
        for req in REQUIRED_FAMILIES {
            assert!(
                fams.iter().any(|f| f == req),
                "missing corpus family {req}, have {fams:?}"
            );
        }
    }

    #[test]
    fn corpus_nonempty() {
        assert!(CORPUS.len() >= 30);
        for e in CORPUS {
            assert!(!e.data.is_empty(), "{}", e.id);
        }
    }
}
