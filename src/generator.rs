//! Grammar-based XML document generators.
//!
//! Always emit **byte sequences** that are structurally motivated XML
//! (well-formed when requested, or controlled near-malformed families).
//! Mutations then break boundaries; corpus seeds cover known bug classes.

use rand::Rng;

/// Default max generation depth for nested elements.
pub const MAX_GEN_DEPTH: usize = 6;

/// Deep-nesting stress depth (stack / recursion surfaces).
pub const DEEP_NEST_DEPTH: usize = 120;

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Generate a full XML document (optionally with prolog) at random depth.
pub fn gen_document(r: &mut impl Rng) -> Vec<u8> {
    let depth = r.gen_range(0..=MAX_GEN_DEPTH);
    gen_document_at_depth(r, depth)
}

/// Generate at an explicit nesting budget.
pub fn gen_document_at_depth(r: &mut impl Rng, depth: usize) -> Vec<u8> {
    let family = r.gen_range(0..28u8);
    match family {
        0 => gen_minimal_wellformed(r),
        1 => gen_with_encoding_decl(r),
        2 => gen_namespaced(r, depth),
        3 => gen_with_dtd_entities(r),
        4 => gen_cdata_comments_pi(r, depth),
        5 => gen_attribute_heavy(r, depth),
        6 => gen_mixed_content(r, depth),
        7 => gen_deep_nesting(DEEP_NEST_DEPTH.min(40 + depth * 10), true),
        8 => gen_deep_nesting(DEEP_NEST_DEPTH, false), // unclosed — controlled malformed
        9 => gen_encoding_adversarial(r),
        10 => gen_name_adversarial(r),
        11 => gen_entity_expand_sketch(r),
        12 => gen_empty_and_self_close(r),
        13 => gen_whitespace_and_newlines(r, depth),
        14 => gen_processing_instructions(r),
        15 => gen_doctype_public_system(r),
        16 => gen_attr_entity_refs(r),
        17 => gen_xinclude_sketch(r),
        18 => gen_xml11_and_space_base(r),
        19 => gen_qname_and_attr_normalize(r),
        20 => gen_chunk_friendly_fragments(r),
        21 => gen_schema_instance_sketch(r),
        22 => gen_xml11_restricted_chars(r),
        23 => gen_pe_multilevel_internal(r),
        24 => gen_xinclude_nested_multi(r),
        25 => gen_xsi_type_instance_sketch(r),
        _ => gen_mixed_family(r, depth),
    }
}

/// Generate a well-formed document only (no intentional unclosed trees).
pub fn gen_wellformed(r: &mut impl Rng) -> Vec<u8> {
    let depth = r.gen_range(0..=MAX_GEN_DEPTH);
    match r.gen_range(0..12u8) {
        0 => gen_minimal_wellformed(r),
        1 => gen_with_encoding_decl(r),
        2 => gen_namespaced(r, depth),
        3 => gen_with_dtd_entities(r),
        4 => gen_cdata_comments_pi(r, depth),
        5 => gen_attribute_heavy(r, depth),
        6 => gen_mixed_content(r, depth),
        7 => gen_deep_nesting(r.gen_range(5..40), true),
        8 => gen_empty_and_self_close(r),
        9 => gen_whitespace_and_newlines(r, depth),
        10 => gen_doctype_public_system(r),
        _ => gen_attr_entity_refs(r),
    }
}

/// Controlled **malformed** families (still structure-aware, not random noise).
pub fn gen_malformed(r: &mut impl Rng) -> Vec<u8> {
    match r.gen_range(0..10u8) {
        0 => gen_deep_nesting(DEEP_NEST_DEPTH, false),
        1 => b"<root><unclosed>".to_vec(),
        2 => b"<?xml version='1.0'?><a></b>".to_vec(),
        3 => b"<a attr='unterminated>text</a>".to_vec(),
        4 => b"<a:b xmlns:a='urn:x'><a:c/></a:b><orphan/>".to_vec(),
        5 => {
            let mut v = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>".to_vec();
            v.extend_from_slice(&[0xC0, 0xAF]); // overlong
            v.extend_from_slice(b"<r/>");
            v
        }
        6 => b"<![CDATA[unterminated".to_vec(),
        7 => b"<!-- comment -- --><r/>".to_vec(),
        8 => b"<!DOCTYPE r [<!ENTITY e '&e;'>]><r>&e;</r>".to_vec(),
        _ => {
            let mut v = gen_wellformed(r);
            // strip last closer if present
            if let Some(i) = v.iter().rposition(|&b| b == b'>') {
                v.truncate(i);
            }
            v
        }
    }
}

// ---------------------------------------------------------------------------
// Families
// ---------------------------------------------------------------------------

pub fn gen_minimal_wellformed(r: &mut impl Rng) -> Vec<u8> {
    match r.gen_range(0..5u8) {
        0 => b"<a/>".to_vec(),
        1 => b"<a></a>".to_vec(),
        2 => b"<?xml version=\"1.0\"?><root/>".to_vec(),
        3 => b"<?xml version='1.0' encoding='UTF-8' standalone='yes'?><r/>".to_vec(),
        _ => b"<root>text</root>".to_vec(),
    }
}

pub fn gen_with_encoding_decl(r: &mut impl Rng) -> Vec<u8> {
    let enc = match r.gen_range(0..6u8) {
        0 => "UTF-8",
        1 => "utf-8",
        2 => "ISO-8859-1",
        3 => "UTF-16",
        4 => "US-ASCII",
        _ => "UTF-8",
    };
    format!("<?xml version=\"1.0\" encoding=\"{enc}\"?><doc id=\"1\">ok</doc>").into_bytes()
}

/// BOM + encoding edges (well-formed when content matches).
pub fn gen_encoding_adversarial(r: &mut impl Rng) -> Vec<u8> {
    match r.gen_range(0..8u8) {
        0 => {
            // UTF-8 BOM
            let mut v = vec![0xEF, 0xBB, 0xBF];
            v.extend_from_slice(b"<?xml version=\"1.0\"?><r/>");
            v
        }
        1 => {
            // UTF-16LE BOM + minimal (may fail without correct encoding path)
            let mut v = vec![0xFF, 0xFE];
            for c in "<?xml version='1.0'?><r/>".chars() {
                v.push(c as u8);
                v.push(0);
            }
            v
        }
        2 => {
            let mut v = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>".to_vec();
            v.push(0xFF); // never-valid UTF-8 in body
            v.extend_from_slice(b"<r/>");
            v
        }
        3 => {
            let mut v = b"<?xml version=\"1.0\"?><r>".to_vec();
            v.extend_from_slice(&[0xE2, 0x82]); // truncated euro
            v.extend_from_slice(b"</r>");
            v
        }
        4 => {
            let mut v = b"<?xml version=\"1.0\"?><r>".to_vec();
            v.extend_from_slice(&[0xF0, 0x9F, 0x98]); // truncated 4-byte
            v.extend_from_slice(b"</r>");
            v
        }
        5 => {
            // NUL in text (libxml often maps / rejects)
            b"<?xml version=\"1.0\"?><r>a\0b</r>".to_vec()
        }
        6 => {
            let mut v = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><r>".to_vec();
            v.push(0xA0); // nbsp in latin1
            v.extend_from_slice(b"</r>");
            v
        }
        _ => {
            let mut v = gen_with_encoding_decl(r);
            if r.gen_bool(0.5) {
                v.insert(0, 0xEF);
                v.insert(1, 0xBB);
                v.insert(2, 0xBF);
            }
            v
        }
    }
}

pub fn gen_namespaced(r: &mut impl Rng, depth: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"<?xml version=\"1.0\"?>");
    out.extend_from_slice(b"<root xmlns=\"urn:default\" xmlns:a=\"urn:a\" xmlns:b=\"urn:b\">");
    gen_element_body(r, &mut out, depth, Some("a"));
    out.extend_from_slice(b"</root>");
    out
}

pub fn gen_with_dtd_entities(r: &mut impl Rng) -> Vec<u8> {
    match r.gen_range(0..5u8) {
        0 => b"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY e \"hello\">]><r>&e;</r>".to_vec(),
        1 => b"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY e \"xx\"><!ENTITY f \"&e;&e;\">]><r>&f;</r>".to_vec(),
        2 => b"<?xml version=\"1.0\"?><!DOCTYPE r [<!ATTLIST r a CDATA \"def\">]><r/>".to_vec(),
        3 => b"<?xml version=\"1.0\"?><!DOCTYPE r [<!ELEMENT r (#PCDATA)>]><r>t</r>".to_vec(),
        _ => {
            // parameter entity sketch (may be rejected without DTDLOAD)
            b"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % p \"<!ENTITY e 'z'>\"> %p;]><r>&e;</r>"
                .to_vec()
        }
    }
}

pub fn gen_doctype_public_system(r: &mut impl Rng) -> Vec<u8> {
    // Use sandbox-relative URIs (fixtures/sandbox), never /etc/passwd.
    let sandbox = concat!(
        "file://",
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/sandbox/secret.txt"
    );
    match r.gen_range(0..4u8) {
        0 => b"<?xml version=\"1.0\"?><!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\"><html/>".to_vec(),
        1 => b"<?xml version=\"1.0\"?><!DOCTYPE r SYSTEM \"file:///nonexistent.dtd\"><r/>".to_vec(),
        2 => format!(
            "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"{sandbox}\">]><r>&xxe;</r>"
        )
        .into_bytes(),
        _ => gen_pe_depth_sketch(r),
    }
}

/// Multi-level parameter-entity / external subset sketches (sandbox paths).
pub fn gen_pe_depth_sketch(r: &mut impl Rng) -> Vec<u8> {
    let pe = concat!(
        "file://",
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/sandbox/pe.dtd"
    );
    let pe2 = concat!(
        "file://",
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/sandbox/pe2.dtd"
    );
    match r.gen_range(0..5u8) {
        0 => format!(
            "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % ext SYSTEM \"{pe}\"> %ext;]><r>&e;</r>"
        )
        .into_bytes(),
        1 => format!(
            "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % ext SYSTEM \"{pe2}\"> %ext;]><r>&e;</r>"
        )
        .into_bytes(),
        2 => {
            // Internal multi-level PE chain (no external file)
            b"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % a \"<!ENTITY % b '<!ENTITY e \"z\">'>\"> %a; %b;]><r>&e;</r>"
                .to_vec()
        }
        3 => gen_pe_multilevel_internal(r),
        _ => {
            // Nested external + internal PE references
            format!(
                "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % ext SYSTEM \"{pe}\"> %ext; <!ENTITY % wrap \"<!ENTITY f '&e;'>\"> %wrap;]><r>&f;</r>"
            )
            .into_bytes()
        }
    }
}

/// Longer internal parameter-entity chains (bounded depth 3–6 levels).
///
/// Builds nested PE definitions that eventually declare a general entity `e`.
/// Deliberately structure-aware (not random noise); may be rejected depending
/// on DTD / PE expansion options.
pub fn gen_pe_multilevel_internal(r: &mut impl Rng) -> Vec<u8> {
    let levels = r.gen_range(3..=6usize);
    match r.gen_range(0..3u8) {
        0 => {
            // Chain: %p0 expands to define %p1 ... until %pN defines general entity e
            // Uses progressive nesting of quoted PE bodies (DTD PE classic pattern).
            let mut dtd = String::from("<?xml version=\"1.0\"?><!DOCTYPE r [");
            // innermost: defines general entity
            let mut body = String::from("<!ENTITY e \"z\">");
            for i in (0..levels).rev() {
                // escape quotes for PE value nesting: alternate quote styles
                if i % 2 == 0 {
                    body = format!("<!ENTITY % p{i} '{body}'>");
                } else {
                    // double-quote body with single-quoted PE decl content
                    let esc = body.replace('"', "&quot;");
                    body = format!("<!ENTITY % p{i} \"{esc}\">");
                }
            }
            dtd.push_str(&body);
            for i in 0..levels {
                dtd.push_str(&format!(" %p{i};"));
            }
            dtd.push_str("]><r>&e;</r>");
            dtd.into_bytes()
        }
        1 => {
            // Flat multi-level PE refs: each PE expands to next PE reference + content
            let mut dtd = String::from("<?xml version=\"1.0\"?><!DOCTYPE r [");
            dtd.push_str("<!ENTITY % p0 \"<!ENTITY e 'deep'>\">");
            for i in 1..levels {
                dtd.push_str(&format!("<!ENTITY % p{i} \"%p{};\">", i - 1));
            }
            dtd.push_str(&format!(" %p{};]><r>&e;</r>", levels - 1));
            dtd.into_bytes()
        }
        _ => {
            // Mixed PE + general entity ladder
            let mut dtd = String::from("<?xml version=\"1.0\"?><!DOCTYPE r [");
            dtd.push_str("<!ENTITY % peA \"<!ENTITY % peB '<!ENTITY % peC \\\"<!ENTITY e 'ok'>\\\">'>\">");
            dtd.push_str(" %peA; %peB; %peC;");
            dtd.push_str("]><r>&e;</r>");
            dtd.into_bytes()
        }
    }
}

pub fn gen_entity_expand_sketch(r: &mut impl Rng) -> Vec<u8> {
    // Bounded "lol" sketch — parsers with ampl limits should fail closed.
    let levels = r.gen_range(2..6usize);
    let mut dtd = String::from("<!DOCTYPE r [");
    dtd.push_str("<!ENTITY a0 \"aaaaaaaaaa\">");
    for i in 1..levels {
        dtd.push_str(&format!(
            "<!ENTITY a{i} \"&a{};&a{};&a{};&a{};&a{};\">",
            i - 1,
            i - 1,
            i - 1,
            i - 1,
            i - 1
        ));
    }
    dtd.push_str(&format!("]><r>&a{};</r>", levels - 1));
    let mut out = b"<?xml version=\"1.0\"?>".to_vec();
    out.extend_from_slice(dtd.as_bytes());
    out
}

pub fn gen_cdata_comments_pi(r: &mut impl Rng, depth: usize) -> Vec<u8> {
    let mut out = b"<?xml version=\"1.0\"?><root>".to_vec();
    out.extend_from_slice(b"<!-- comment - ok -->");
    out.extend_from_slice(b"<![CDATA[1 < 2 && 3 > 0]]>");
    out.extend_from_slice(b"<?pi target data?>");
    if depth > 0 {
        gen_element_body(r, &mut out, depth - 1, None);
    }
    out.extend_from_slice(b"</root>");
    out
}

pub fn gen_processing_instructions(r: &mut impl Rng) -> Vec<u8> {
    match r.gen_range(0..4u8) {
        0 => b"<?xml version=\"1.0\"?><?xsl-stylesheet type=\"text/xsl\" href=\"a.xsl\"?><r/>".to_vec(),
        1 => b"<?xml version=\"1.0\"?><r><?pi?></r>".to_vec(),
        2 => b"<?xml version=\"1.0\"?><r><?pi a=\"b\" c?></r>".to_vec(),
        _ => b"<?xml version=\"1.0\"?><r><?xml-stylesheet href='x'?></r>".to_vec(),
    }
}

pub fn gen_attribute_heavy(r: &mut impl Rng, depth: usize) -> Vec<u8> {
    let mut out = b"<?xml version=\"1.0\"?><r".to_vec();
    let n = r.gen_range(1..12usize);
    for i in 0..n {
        let q = if r.gen_bool(0.5) { b'\'' } else { b'"' };
        out.extend_from_slice(format!(" a{i}=").as_bytes());
        out.push(q);
        gen_attr_value(r, &mut out);
        out.push(q);
    }
    if r.gen_bool(0.4) {
        out.extend_from_slice(b"/>");
    } else {
        out.push(b'>');
        if depth > 0 {
            gen_element_body(r, &mut out, depth - 1, None);
        }
        out.extend_from_slice(b"</r>");
    }
    out
}

pub fn gen_attr_entity_refs(r: &mut impl Rng) -> Vec<u8> {
    match r.gen_range(0..4u8) {
        0 => b"<r a=\"&lt;&gt;&amp;&quot;&apos;\"/>".to_vec(),
        1 => b"<!DOCTYPE r [<!ENTITY e \"v\">]><r a=\"&e;\"/>".to_vec(),
        2 => b"<r a=\"&#65;&#x42;\"/>".to_vec(),
        _ => b"<r a=\"normal\" b='mixed \" quotes'/>".to_vec(),
    }
}

pub fn gen_mixed_content(r: &mut impl Rng, depth: usize) -> Vec<u8> {
    let mut out = b"<?xml version=\"1.0\"?><p>".to_vec();
    out.extend_from_slice(b"text ");
    out.extend_from_slice(b"<em>x</em>");
    out.extend_from_slice(b" more");
    if depth > 0 && r.gen_bool(0.5) {
        out.extend_from_slice(b"<span>");
        gen_element_body(r, &mut out, depth - 1, None);
        out.extend_from_slice(b"</span>");
    }
    out.extend_from_slice(b"</p>");
    out
}

pub fn gen_empty_and_self_close(r: &mut impl Rng) -> Vec<u8> {
    match r.gen_range(0..4u8) {
        0 => b"<a/>".to_vec(),
        1 => b"<a></a>".to_vec(),
        2 => b"<a   />".to_vec(),
        _ => b"<a b='c'/>".to_vec(),
    }
}

pub fn gen_whitespace_and_newlines(r: &mut impl Rng, depth: usize) -> Vec<u8> {
    let mut out = b"<?xml version=\"1.0\"?>\n\n".to_vec();
    out.extend_from_slice(b"<root\n  >");
    out.extend_from_slice(b"\ttext\r\n");
    if depth > 0 {
        gen_element_body(r, &mut out, depth - 1, None);
    }
    out.extend_from_slice(b"</root>\n");
    out
}

pub fn gen_name_adversarial(r: &mut impl Rng) -> Vec<u8> {
    match r.gen_range(0..8u8) {
        0 => b"<_x/>".to_vec(),
        1 => b"<a-b.c/>".to_vec(),
        2 => {
            // long name
            let mut out = b"<".to_vec();
            out.extend(std::iter::repeat(b'n').take(256));
            out.extend_from_slice(b"/>");
            out
        }
        3 => b"<a xmlns:xml=\"http://www.w3.org/XML/1998/namespace\" xml:lang=\"en\"/>".to_vec(),
        4 => b"<ns:tag xmlns:ns=\"urn:x\"/>".to_vec(),
        5 => b"<a:b:c xmlns:a=\"urn:a\"/>".to_vec(), // often invalid NCName local
        6 => b"<:bad/>".to_vec(),
        _ => b"<123/>".to_vec(), // digit-start — invalid Name
    }
}

/// Deep nesting of elements: `closed` controls whether closers are emitted.
pub fn gen_deep_nesting(depth: usize, closed: bool) -> Vec<u8> {
    let mut out = b"<?xml version=\"1.0\"?>".to_vec();
    for _ in 0..depth {
        out.extend_from_slice(b"<n>");
    }
    out.extend_from_slice(b"x");
    if closed {
        for _ in 0..depth {
            out.extend_from_slice(b"</n>");
        }
    }
    out
}

fn gen_mixed_family(r: &mut impl Rng, depth: usize) -> Vec<u8> {
    let mut out = gen_wellformed(r);
    // occasionally append a second rootish fragment (malformed multi-root)
    if r.gen_bool(0.2) {
        out.extend_from_slice(b"<extra/>");
    }
    if depth > 3 && r.gen_bool(0.3) {
        // wrap
        let mut w = b"<wrap>".to_vec();
        w.append(&mut out);
        w.extend_from_slice(b"</wrap>");
        return w;
    }
    out
}

fn gen_element_body(r: &mut impl Rng, out: &mut Vec<u8>, depth: usize, pref: Option<&str>) {
    if depth == 0 {
        out.extend_from_slice(b"leaf");
        return;
    }
    let kids = r.gen_range(0..4usize);
    for i in 0..kids {
        let name = match pref {
            Some(p) => format!("{p}:e{i}"),
            None => format!("e{i}"),
        };
        if r.gen_bool(0.25) {
            out.extend_from_slice(format!("<{name}/>").as_bytes());
        } else {
            out.extend_from_slice(format!("<{name}>").as_bytes());
            if r.gen_bool(0.5) {
                gen_text(r, out);
            }
            gen_element_body(r, out, depth - 1, pref);
            out.extend_from_slice(format!("</{name}>").as_bytes());
        }
    }
}

fn gen_text(r: &mut impl Rng, out: &mut Vec<u8>) {
    match r.gen_range(0..6u8) {
        0 => out.extend_from_slice(b"hello"),
        1 => out.extend_from_slice(b"a &amp; b"),
        2 => out.extend_from_slice(b"1 &lt; 2"),
        3 => out.extend_from_slice(b"  spaced  "),
        4 => {
            // unicode
            out.extend_from_slice("café".as_bytes());
        }
        _ => out.extend_from_slice(b"x"),
    }
}

fn gen_attr_value(r: &mut impl Rng, out: &mut Vec<u8>) {
    match r.gen_range(0..6u8) {
        0 => out.extend_from_slice(b"v"),
        1 => out.extend_from_slice(b"&lt;"),
        2 => out.extend_from_slice(b"&#x20;"),
        3 => out.extend_from_slice(b""),
        4 => out.extend(std::iter::repeat(b'A').take(r.gen_range(1..64))),
        _ => out.extend_from_slice(b"a b"),
    }
}

/// XInclude-shaped document (parser may need XINCLUDE option to expand).
pub fn gen_xinclude_sketch(r: &mut impl Rng) -> Vec<u8> {
    match r.gen_range(0..8u8) {
        0 => b"<?xml version=\"1.0\"?><r xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"missing.xml\"/></r>".to_vec(),
        1 => b"<?xml version=\"1.0\"?><r xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"data.xml\" parse=\"text\"/></r>".to_vec(),
        2 => b"<?xml version=\"1.0\"?><r xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"a.xml\"><xi:fallback>fb</xi:fallback></xi:include></r>".to_vec(),
        3 => b"<?xml version=\"1.0\"?><r xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"a.xml\" parse=\"xml\"><xi:fallback><empty/></xi:fallback></xi:include></r>".to_vec(),
        4 => b"<?xml version=\"1.0\"?><r xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"t.txt\" parse=\"text\" encoding=\"UTF-8\"><xi:fallback>missing-text</xi:fallback></xi:include></r>".to_vec(),
        5 => gen_xinclude_nested_multi(r),
        6 => {
            // xpointer attribute sketch on include
            b"<?xml version=\"1.0\"?><r xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"doc.xml\" xpointer=\"xpointer(/r/a)\"><xi:fallback/></xi:include></r>".to_vec()
        }
        _ => {
            // default namespace form (unprefixed include)
            b"<?xml version=\"1.0\"?><r xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"b.xml\" parse=\"text\"/></r>".to_vec()
        }
    }
}

/// Multi-include and nested XInclude sketches.
pub fn gen_xinclude_nested_multi(r: &mut impl Rng) -> Vec<u8> {
    match r.gen_range(0..4u8) {
        0 => {
            // Multiple sibling includes
            b"<?xml version=\"1.0\"?><r xmlns:xi=\"http://www.w3.org/2001/XInclude\">\
              <xi:include href=\"a.xml\" parse=\"xml\"/><xi:include href=\"b.xml\" parse=\"text\"/>\
              <xi:include href=\"c.xml\"><xi:fallback>c-fb</xi:fallback></xi:include></r>"
                .to_vec()
        }
        1 => {
            // Nested: fallback contains another include
            b"<?xml version=\"1.0\"?><r xmlns:xi=\"http://www.w3.org/2001/XInclude\">\
              <xi:include href=\"outer.xml\"><xi:fallback>\
                <xi:include href=\"inner.xml\" parse=\"text\"><xi:fallback>deep-fb</xi:fallback></xi:include>\
              </xi:fallback></xi:include></r>"
                .to_vec()
        }
        2 => {
            // Nested includes in element tree
            let n = r.gen_range(2..5usize);
            let mut out = b"<?xml version=\"1.0\"?><r xmlns:xi=\"http://www.w3.org/2001/XInclude\">".to_vec();
            for i in 0..n {
                out.extend_from_slice(
                    format!(
                        "<sec id=\"{i}\"><xi:include href=\"part{i}.xml\" parse=\"xml\">\
                         <xi:fallback><p>missing-{i}</p></xi:fallback></xi:include></sec>"
                    )
                    .as_bytes(),
                );
            }
            out.extend_from_slice(b"</r>");
            out
        }
        _ => {
            // Include with parse=text siblings + one nested fallback chain
            b"<?xml version=\"1.0\"?><doc xmlns:xi=\"http://www.w3.org/2001/XInclude\">\
              <xi:include href=\"raw.txt\" parse=\"text\"/>\
              <wrap><xi:include href=\"nest.xml\"><xi:fallback>\
                <xi:include href=\"nest2.xml\"><xi:fallback>end</xi:fallback></xi:include>\
              </xi:fallback></xi:include></wrap></doc>"
                .to_vec()
        }
    }
}

/// XML 1.1 version sketch + xml:space / xml:base.
pub fn gen_xml11_and_space_base(r: &mut impl Rng) -> Vec<u8> {
    match r.gen_range(0..6u8) {
        0 => b"<?xml version=\"1.1\" encoding=\"UTF-8\"?><r xml:space=\"preserve\">  a  </r>".to_vec(),
        1 => b"<?xml version=\"1.0\"?><r xml:base=\"http://example.test/base/\"><c/></r>".to_vec(),
        2 => b"<?xml version=\"1.1\"?><r xml:space=\"default\">\tx\n</r>".to_vec(),
        3 => b"<?xml version=\"1.0\"?><r xml:lang=\"en-US\" xml:space=\"preserve\">y</r>".to_vec(),
        4 => gen_xml11_restricted_chars(r),
        _ => b"<?xml version=\"1.1\" encoding=\"UTF-8\"?><r xml:base=\"http://example.test/\" xml:space=\"preserve\">z</r>".to_vec(),
    }
}

/// XML 1.1 restricted / discouraged character sketches as raw bytes.
///
/// XML 1.1 allows C0 controls (except NUL) as restricted chars that must be
/// written as character references in some contexts; parsers differ on raw
/// control bytes. These sketches carefully place restricted codepoints in text
/// and (where useful) as numeric character references.
pub fn gen_xml11_restricted_chars(r: &mut impl Rng) -> Vec<u8> {
    match r.gen_range(0..8u8) {
        0 => {
            // Char refs for C0 controls legal as refs in XML 1.0/1.1 text (except NUL)
            b"<?xml version=\"1.1\"?><r>&#x1;&#x8;&#xB;&#xC;&#xE;&#x1F;</r>".to_vec()
        }
        1 => {
            // Raw DEL and C1 controls as bytes in UTF-8 body (often rejected)
            let mut v = b"<?xml version=\"1.1\" encoding=\"UTF-8\"?><r>".to_vec();
            v.push(0x7F); // DEL
            v.push(0x80); // invalid UTF-8 / C1 lead — intentional edge
            v.extend_from_slice(b"</r>");
            v
        }
        2 => {
            // Restricted chars as character references (NEL, etc.)
            b"<?xml version=\"1.1\"?><r>a&#x85;b&#x2028;c</r>".to_vec()
        }
        3 => {
            // Raw C0 control bytes (0x01, 0x0B, 0x0C) in text — carefully bounded
            let mut v = b"<?xml version=\"1.1\"?><r>".to_vec();
            v.push(0x01);
            v.push(b'x');
            v.push(0x0B);
            v.push(b'y');
            v.push(0x0C);
            v.extend_from_slice(b"</r>");
            v
        }
        4 => {
            // Attribute value with restricted char refs
            b"<?xml version=\"1.1\"?><r a=\"&#x1;&#x1F;\"/>".to_vec()
        }
        5 => {
            // Mix: version 1.1 + BOM + NEL char ref
            let mut v = vec![0xEF, 0xBB, 0xBF];
            v.extend_from_slice(b"<?xml version=\"1.1\"?><r>line1&#x85;line2</r>");
            v
        }
        6 => {
            // Unicode non-characters / discouraged planes as refs
            b"<?xml version=\"1.1\"?><r>&#xFFFE;&#xFFFF;&#xFDD0;</r>".to_vec()
        }
        _ => {
            // UTF-8 encoding of U+0085 (NEL) and U+2028 (line separator) raw
            let mut v = b"<?xml version=\"1.1\" encoding=\"UTF-8\"?><r>".to_vec();
            v.extend_from_slice("\u{85}".as_bytes()); // C2 85
            v.push(b'|');
            v.extend_from_slice("\u{2028}".as_bytes()); // E2 80 A8
            v.extend_from_slice(b"</r>");
            v
        }
    }
}

/// QName edges and attribute whitespace normalization sketches.
pub fn gen_qname_and_attr_normalize(r: &mut impl Rng) -> Vec<u8> {
    match r.gen_range(0..4u8) {
        0 => b"<a:b xmlns:a=\"urn:a\" a:c=\"  spaced  \"/>".to_vec(),
        1 => b"<r a=\"&#xD;&#xA;tab&#x9;\"/>".to_vec(),
        2 => b"<r xmlns:a=\"urn:a\" xmlns:b=\"urn:b\" a:x=\"1\" b:x=\"2\"/>".to_vec(),
        _ => b"<a:b:c xmlns:a=\"urn:a\"/>".to_vec(),
    }
}

/// Documents that stress progressive/chunk parsers (natural split points).
pub fn gen_chunk_friendly_fragments(r: &mut impl Rng) -> Vec<u8> {
    match r.gen_range(0..4u8) {
        0 => b"<?xml version=\"1.0\"?>\n<root>\n  <a>one</a>\n  <b>two</b>\n</root>\n".to_vec(),
        1 => b"<?xml version=\"1.0\"?><r><![CDATA[aaaabbbbcccc]]></r>".to_vec(),
        2 => b"<?xml version=\"1.0\"?><r attr=\"long-value-here\">text</r>".to_vec(),
        _ => {
            let mut out = b"<?xml version=\"1.0\"?><r>".to_vec();
            for i in 0..r.gen_range(5..20) {
                out.extend_from_slice(format!("<e{i}/>").as_bytes());
            }
            out.extend_from_slice(b"</r>");
            out
        }
    }
}

/// XSI / schemaLocation sketches (no full XSD compile required).
pub fn gen_schema_instance_sketch(r: &mut impl Rng) -> Vec<u8> {
    match r.gen_range(0..5u8) {
        0 => b"<?xml version=\"1.0\"?><r xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:noNamespaceSchemaLocation=\"r.xsd\"/>".to_vec(),
        1 => b"<?xml version=\"1.0\"?><r xmlns=\"urn:x\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"urn:x r.xsd\"/>".to_vec(),
        2 => gen_xsi_type_instance_sketch(r),
        3 => b"<?xml version=\"1.0\"?><r xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:nil=\"true\"/>".to_vec(),
        _ => b"<?xml version=\"1.0\"?><r xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:t=\"urn:t\" xsi:type=\"t:Special\" xsi:schemaLocation=\"urn:t t.xsd\">x</r>".to_vec(),
    }
}

/// Instance documents using `xsi:type` (pairs with adversarial XSD abstract types).
pub fn gen_xsi_type_instance_sketch(r: &mut impl Rng) -> Vec<u8> {
    match r.gen_range(0..4u8) {
        0 => b"<?xml version=\"1.0\"?><shape xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:t=\"urn:shapes\" xsi:type=\"t:Circle\"><radius>1</radius></shape>".to_vec(),
        1 => b"<?xml version=\"1.0\"?><item xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\">hello</item>".to_vec(),
        2 => b"<?xml version=\"1.0\"?><r xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:e=\"urn:e\" xsi:type=\"e:Ext\"><a>1</a><b>2</b></r>".to_vec(),
        _ => {
            let n = r.gen_range(1..4usize);
            let mut out = b"<?xml version=\"1.0\"?><list xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:t=\"urn:t\">".to_vec();
            for i in 0..n {
                out.extend_from_slice(
                    format!("<item xsi:type=\"t:T{i}\">v{i}</item>").as_bytes(),
                );
            }
            out.extend_from_slice(b"</list>");
            out
        }
    }
}

/// One-shot orchestration helper used by fuzz loops: wellformed or malformed.
pub fn gen_work(r: &mut impl Rng) -> Vec<u8> {
    if r.gen_bool(0.75) {
        gen_document(r)
    } else {
        gen_malformed(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn generates_nonempty() {
        let mut r = StdRng::seed_from_u64(1);
        for _ in 0..50 {
            let d = gen_document(&mut r);
            assert!(!d.is_empty());
        }
    }

    #[test]
    fn deep_closed_has_closers() {
        let d = gen_deep_nesting(5, true);
        let s = String::from_utf8_lossy(&d);
        assert!(s.contains("</n>"));
        assert_eq!(s.matches("<n>").count(), s.matches("</n>").count());
    }

    #[test]
    fn deep_open_unbalanced() {
        let d = gen_deep_nesting(5, false);
        let s = String::from_utf8_lossy(&d);
        assert!(!s.contains("</n>"));
    }

    #[test]
    fn pe_multilevel_and_xinclude_nonempty() {
        let mut r = StdRng::seed_from_u64(7);
        for _ in 0..20 {
            assert!(!gen_pe_multilevel_internal(&mut r).is_empty());
            assert!(!gen_xinclude_nested_multi(&mut r).is_empty());
            assert!(!gen_xml11_restricted_chars(&mut r).is_empty());
            assert!(!gen_xsi_type_instance_sketch(&mut r).is_empty());
        }
    }
}
