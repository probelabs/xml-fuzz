//! Every libxml2 public surface we drive via the multi-API harness.
//!
//! Aligned with upstream `fuzz/{xml,html,reader,xpath,schema,regexp,uri,valid,xinclude}`
//! plus save, c14n, rng, catalog, tree, reader-ops, io-callback, reader-schema/rng.

use crate::generator;
use rand::Rng;

/// One fuzzable libxml2 API / mode string for `--api=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LibXml2Api {
    XmlMemory,
    XmlPush,
    XmlReader,
    XmlValid,
    HtmlMemory,
    HtmlPush,
    XPath,
    XPointer,
    SchemaParse,
    SchemaValid,
    RngParse,
    RngValid,
    Regexp,
    Uri,
    XInclude,
    Save,
    C14n,
    Catalog,
    Tree,
    ReaderOps,
    IoCallback,
    ReaderSchema,
    ReaderRng,
}

impl LibXml2Api {
    pub const ALL: &'static [LibXml2Api] = &[
        LibXml2Api::XmlMemory,
        LibXml2Api::XmlPush,
        LibXml2Api::XmlReader,
        LibXml2Api::XmlValid,
        LibXml2Api::HtmlMemory,
        LibXml2Api::HtmlPush,
        LibXml2Api::XPath,
        LibXml2Api::XPointer,
        LibXml2Api::SchemaParse,
        LibXml2Api::SchemaValid,
        LibXml2Api::RngParse,
        LibXml2Api::RngValid,
        LibXml2Api::Regexp,
        LibXml2Api::Uri,
        LibXml2Api::XInclude,
        LibXml2Api::Save,
        LibXml2Api::C14n,
        LibXml2Api::Catalog,
        LibXml2Api::Tree,
        LibXml2Api::ReaderOps,
        LibXml2Api::IoCallback,
        LibXml2Api::ReaderSchema,
        LibXml2Api::ReaderRng,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            LibXml2Api::XmlMemory => "xml-memory",
            LibXml2Api::XmlPush => "xml-push",
            LibXml2Api::XmlReader => "xml-reader",
            LibXml2Api::XmlValid => "xml-valid",
            LibXml2Api::HtmlMemory => "html-memory",
            LibXml2Api::HtmlPush => "html-push",
            LibXml2Api::XPath => "xpath",
            LibXml2Api::XPointer => "xpointer",
            LibXml2Api::SchemaParse => "schema-parse",
            LibXml2Api::SchemaValid => "schema-valid",
            LibXml2Api::RngParse => "rng-parse",
            LibXml2Api::RngValid => "rng-valid",
            LibXml2Api::Regexp => "regexp",
            LibXml2Api::Uri => "uri",
            LibXml2Api::XInclude => "xinclude",
            LibXml2Api::Save => "save",
            LibXml2Api::C14n => "c14n",
            LibXml2Api::Catalog => "catalog",
            LibXml2Api::Tree => "tree",
            LibXml2Api::ReaderOps => "reader-ops",
            LibXml2Api::IoCallback => "io-callback",
            LibXml2Api::ReaderSchema => "reader-schema",
            LibXml2Api::ReaderRng => "reader-rng",
        }
    }

    pub fn sample(rng: &mut (impl Rng + ?Sized)) -> Self {
        Self::ALL[rng.gen_range(0..Self::ALL.len())]
    }

    /// Whether this API expects dual payload with `---SPLIT---`.
    pub fn needs_split(self) -> bool {
        matches!(
            self,
            LibXml2Api::XPath
                | LibXml2Api::XPointer
                | LibXml2Api::SchemaValid
                | LibXml2Api::RngValid
                | LibXml2Api::Regexp
                | LibXml2Api::ReaderSchema
                | LibXml2Api::ReaderRng
        )
    }
}

const SPLIT: &[u8] = b"\n---SPLIT---\n";

/// Generate structure-aware bytes appropriate for `api`.
pub fn gen_for_api(rng: &mut impl Rng, api: LibXml2Api) -> Vec<u8> {
    match api {
        LibXml2Api::XmlMemory
        | LibXml2Api::XmlPush
        | LibXml2Api::XmlReader
        | LibXml2Api::XmlValid
        | LibXml2Api::Save
        | LibXml2Api::C14n
        | LibXml2Api::Tree
        | LibXml2Api::IoCallback => {
            if rng.gen_bool(0.15) {
                generator::gen_malformed(rng)
            } else {
                generator::gen_document(rng)
            }
        }
        LibXml2Api::XInclude => {
            // Prefer XInclude-shaped docs; occasional general / malformed
            match rng.gen_range(0..5u8) {
                0 => generator::gen_xinclude_sketch(rng),
                1 => generator::gen_xinclude_nested_multi(rng),
                2 => generator::gen_malformed(rng),
                _ => generator::gen_document(rng),
            }
        }
        LibXml2Api::ReaderOps => {
            // Optional binary op prefix + document (harness also accepts bare docs).
            if rng.gen_bool(0.4) {
                let mut ops = vec![0u8; rng.gen_range(4..48)];
                rng.fill_bytes(&mut ops);
                let doc = if rng.gen_bool(0.2) {
                    generator::gen_malformed(rng)
                } else {
                    generator::gen_document(rng)
                };
                join_split(&ops, &doc)
            } else if rng.gen_bool(0.15) {
                generator::gen_malformed(rng)
            } else {
                generator::gen_document(rng)
            }
        }
        LibXml2Api::HtmlMemory | LibXml2Api::HtmlPush => gen_html(rng),
        LibXml2Api::XPath | LibXml2Api::XPointer => {
            let doc = if rng.gen_bool(0.35) {
                // namespaced / structured docs exercise axes and prefixes
                let depth = rng.gen_range(1..4);
                generator::gen_namespaced(rng, depth)
            } else {
                generator::gen_wellformed(rng)
            };
            let expr = gen_xpath_expr(rng, api == LibXml2Api::XPointer);
            join_split(&doc, expr.as_bytes())
        }
        LibXml2Api::SchemaParse => gen_xsd_schema(rng),
        LibXml2Api::SchemaValid | LibXml2Api::ReaderSchema => {
            let (schema, inst) = gen_xsd_schema_and_instance(rng);
            join_split(&schema, &inst)
        }
        LibXml2Api::RngParse => gen_rng_schema(rng),
        LibXml2Api::RngValid | LibXml2Api::ReaderRng => {
            let (schema, inst) = gen_rng_schema_and_instance(rng);
            join_split(&schema, &inst)
        }
        LibXml2Api::Regexp => {
            let pat = gen_regexp_pattern(rng);
            let s = gen_regexp_string(rng);
            join_split(pat.as_bytes(), s.as_bytes())
        }
        LibXml2Api::Uri => gen_uri(rng),
        LibXml2Api::Catalog => gen_catalog(rng),
    }
}

fn join_split(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut v = a.to_vec();
    v.extend_from_slice(SPLIT);
    v.extend_from_slice(b);
    v
}

fn gen_html(rng: &mut impl Rng) -> Vec<u8> {
    match rng.gen_range(0..16u8) {
        0 => b"<html><body><p>hi</p></body></html>".to_vec(),
        1 => b"<div><span>a</span></div>".to_vec(),
        2 => b"<html><body><script>x</script></body></html>".to_vec(),
        3 => b"<table><tr><td>1</td></tr></table>".to_vec(),
        4 => b"<html><head><meta charset=utf-8></head><body>x</body></html>".to_vec(),
        5 => {
            let mut v = b"<html><body>".to_vec();
            for i in 0..rng.gen_range(1..20) {
                v.extend_from_slice(format!("<p id=\"{i}\">t</p>").as_bytes());
            }
            v.extend_from_slice(b"</body></html>");
            v
        }
        6 => b"<html><body><div><p>unclosed".to_vec(),
        7 => {
            // Rawtext script: markup-looking content must not be tokenized as HTML
            b"<html><body><script type=\"text/javascript\">\
              var x = \"</script>\"; if (a < b && c > d) { /* </div> */ }\
              document.write('<p>injected</p>');</script></body></html>"
                .to_vec()
        }
        8 => {
            // Rawtext style
            b"<html><head><style type=\"text/css\">\
              body { content: \"</style>\"; color: red; }\
              /* <div class=\"x\"> */ p > span { margin: 0; }\
              </style></head><body><p>styled</p></body></html>"
                .to_vec()
        }
        9 => {
            // Meta charset variants
            match rng.gen_range(0..3u8) {
                0 => b"<html><head><meta charset=\"UTF-8\"><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"></head><body>ok</body></html>".to_vec(),
                1 => b"<html><head><meta charset=iso-8859-1></head><body>\xA0nbsp</body></html>".to_vec(),
                _ => b"<!DOCTYPE html><html><head><meta charset=utf-8></head><body><p>html5</p></body></html>".to_vec(),
            }
        }
        10 => {
            // Many attributes on one element
            let mut v = b"<html><body><div".to_vec();
            let n = rng.gen_range(8..40usize);
            for i in 0..n {
                v.extend_from_slice(format!(" data-a{i}=\"v{i}\"").as_bytes());
            }
            v.extend_from_slice(b" id=\"heavy\" class=\"a b c\">x</div></body></html>");
            v
        }
        11 => {
            // Tables: nested, rowspan/colspan, unclosed cells
            match rng.gen_range(0..3u8) {
                0 => b"<table><thead><tr><th>A</th><th>B</th></tr></thead><tbody>\
                      <tr><td rowspan=\"2\">1</td><td>2</td></tr>\
                      <tr><td colspan=\"1\">3</td></tr></tbody></table>"
                    .to_vec(),
                1 => b"<table><tr><td><table><tr><td>nested</td></tr></table></td><td>x</td></tr></table>".to_vec(),
                _ => b"<table><tr><td>open<tr><td>row".to_vec(),
            }
        }
        12 => {
            // Unclosed tags / optional end-tag stress
            match rng.gen_range(0..4u8) {
                0 => b"<html><body><p>one<p>two<li>item<br><hr><img src=x>".to_vec(),
                1 => b"<div><span><b>bold<i>italic</div>".to_vec(),
                2 => b"<html><body><ul><li>a<li>b<li>c</body>".to_vec(),
                _ => b"<form><input type=text name=q><button>go".to_vec(),
            }
        }
        13 => {
            // Script + style together + noscript
            b"<html><head><meta charset=utf-8>\
              <style>/* </script> */ a{}</style>\
              <script>/* </style> */ var t='<div>';</script>\
              </head><body><noscript><p>no-js</p></noscript></body></html>"
                .to_vec()
        }
        14 => {
            // Many attrs + table + unclosed mix
            let mut v = b"<html><body><table border=1 cellpadding=2".to_vec();
            for i in 0..rng.gen_range(3..12) {
                v.extend_from_slice(format!(" data-c{i}={i}").as_bytes());
            }
            v.extend_from_slice(b"><tr><td>a<td>b<tr><td colspan=2>c</table><p>trail");
            v
        }
        _ => generator::gen_document(rng), // XML as HTML input
    }
}

fn gen_xpath_expr(rng: &mut impl Rng, xptr: bool) -> String {
    if xptr {
        return match rng.gen_range(0..10u8) {
            0 => "xpointer(//*)".into(),
            1 => "xpointer(/r)".into(),
            2 => "xmlns(a=urn:x) xpointer(//a:*)".into(),
            3 => "xpointer(//node())".into(),
            4 => "xpointer(id('x'))".into(),
            5 => "xmlns(a=urn:a) xmlns(b=urn:b) xpointer(//a:e | //b:e)".into(),
            6 => "xpointer(//*[count(child::*)>0])".into(),
            7 => "xpointer(/descendant::*/child::*[position()=1])".into(),
            8 => "xpointer(//r/attribute::*)".into(),
            _ => "xpointer(//*[local-name()='e0'])".into(),
        };
    }
    match rng.gen_range(0..28u8) {
        // Original simple set
        0 => "//*".into(),
        1 => "/r".into(),
        2 => "//r/@*".into(),
        3 => "count(//*)".into(),
        4 => "string(//r)".into(),
        5 => "//*[1]".into(),
        6 => "//r[position()=1]".into(),
        7 => "true()".into(),
        8 => "//namespace::*".into(),
        9 => "/*/*".into(),
        10 => "//*[local-name()='r']".into(),
        11 => "concat('a','b')".into(),
        // Axes
        12 => "/descendant::e0".into(),
        13 => "//e0/ancestor::*".into(),
        14 => "//e0/following-sibling::*".into(),
        15 => "//e0/preceding::e0".into(),
        16 => "child::*/attribute::*".into(),
        17 => "self::node()/parent::*".into(),
        // Predicates
        18 => "//*[position() mod 2 = 1]".into(),
        19 => "//*[@id or @class]".into(),
        20 => "//*[contains(name(),'e')][last()]".into(),
        // Variables $x (bindings depend on host; still valid expr syntax stress)
        21 => "$x".into(),
        22 => "count($x) + sum(//*)".into(),
        23 => "//*[. = $x]".into(),
        // Namespace prefixes
        24 => "//a:*".into(),
        25 => "//a:e0 | //b:e0".into(),
        // Union / count / sum
        26 => "count(//a | //b | //*)".into(),
        _ => match rng.gen_range(0..4u8) {
            0 => "sum(//*/@*)".into(),
            1 => "//* | /r | //text()".into(),
            2 => "count(//namespace::*) + count(//attribute::*)".into(),
            _ => "//*[not(parent::a)]/child::*[position()<3]".into(),
        },
    }
}

fn gen_xsd_schema(rng: &mut impl Rng) -> Vec<u8> {
    gen_xsd_schema_and_instance(rng).0
}

/// Adversarial / deep XSD sketches: abstract types, xsi:type, IDC, sequences, attr groups.
fn gen_xsd_schema_and_instance(rng: &mut impl Rng) -> (Vec<u8>, Vec<u8>) {
    match rng.gen_range(0..10u8) {
        0 => (
            br#"<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="r" type="xs:string"/>
</xs:schema>"#
                .to_vec(),
            b"<r>hi</r>".to_vec(),
        ),
        1 => (
            br#"<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="r">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="a" type="xs:int" minOccurs="0"/>
      </xs:sequence>
      <xs:attribute name="id" type="xs:ID"/>
    </xs:complexType>
  </xs:element>
</xs:schema>"#
                .to_vec(),
            b"<r id=\"i1\"><a>3</a></r>".to_vec(),
        ),
        2 => (
            br#"<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="r">
    <xs:complexType>
      <xs:choice>
        <xs:element name="a" type="xs:string"/>
        <xs:element name="b" type="xs:string"/>
      </xs:choice>
    </xs:complexType>
  </xs:element>
</xs:schema>"#
                .to_vec(),
            b"<r><b>x</b></r>".to_vec(),
        ),
        // Abstract type + xsi:type substitution
        3 => (
            br#"<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           targetNamespace="urn:shapes" xmlns:t="urn:shapes"
           elementFormDefault="qualified">
  <xs:complexType name="Shape" abstract="true">
    <xs:sequence>
      <xs:element name="id" type="xs:string"/>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="Circle">
    <xs:complexContent>
      <xs:extension base="t:Shape">
        <xs:sequence>
          <xs:element name="radius" type="xs:double"/>
        </xs:sequence>
      </xs:extension>
    </xs:complexContent>
  </xs:complexType>
  <xs:element name="shape" type="t:Shape"/>
</xs:schema>"#
                .to_vec(),
            b"<?xml version=\"1.0\"?><shape xmlns=\"urn:shapes\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:t=\"urn:shapes\" xsi:type=\"t:Circle\"><id>c1</id><radius>2.5</radius></shape>".to_vec(),
        ),
        // key / keyref / unique IDC sketches
        4 => (
            br#"<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="root">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="item" maxOccurs="unbounded">
          <xs:complexType>
            <xs:sequence>
              <xs:element name="code" type="xs:string"/>
              <xs:element name="ref" type="xs:string" minOccurs="0"/>
            </xs:sequence>
            <xs:attribute name="id" type="xs:ID"/>
          </xs:complexType>
        </xs:element>
      </xs:sequence>
    </xs:complexType>
    <xs:key name="kCode">
      <xs:selector xpath="item"/>
      <xs:field xpath="code"/>
    </xs:key>
    <xs:unique name="uId">
      <xs:selector xpath="item"/>
      <xs:field xpath="@id"/>
    </xs:unique>
    <xs:keyref name="krRef" refer="kCode">
      <xs:selector xpath="item"/>
      <xs:field xpath="ref"/>
    </xs:keyref>
  </xs:element>
</xs:schema>"#
                .to_vec(),
            b"<root><item id=\"i1\"><code>A</code></item><item id=\"i2\"><code>B</code><ref>A</ref></item></root>".to_vec(),
        ),
        // Deep sequences (bounded)
        5 => {
            let depth = rng.gen_range(3..8usize);
            let mut schema = String::from(
                r#"<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="r" type="t0"/>
"#,
            );
            for i in 0..depth {
                let next = if i + 1 < depth {
                    format!("t{}", i + 1)
                } else {
                    "xs:string".into()
                };
                let child = format!("e{i}");
                schema.push_str(&format!(
                    r#"  <xs:complexType name="t{i}">
    <xs:sequence>
      <xs:element name="{child}" type="{next}" minOccurs="0" maxOccurs="2"/>
    </xs:sequence>
  </xs:complexType>
"#
                ));
            }
            schema.push_str("</xs:schema>");
            // Matching shallow instance
            let mut inst = String::from("<r>");
            for i in 0..depth {
                inst.push_str(&format!("<e{i}>"));
            }
            inst.push('x');
            for i in (0..depth).rev() {
                inst.push_str(&format!("</e{i}>"));
            }
            inst.push_str("</r>");
            (schema.into_bytes(), inst.into_bytes())
        }
        // Attribute groups
        6 => (
            br#"<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:attributeGroup name="common">
    <xs:attribute name="id" type="xs:ID"/>
    <xs:attribute name="lang" type="xs:language"/>
    <xs:attribute name="rev" type="xs:int" default="0"/>
  </xs:attributeGroup>
  <xs:attributeGroup name="more">
    <xs:attributeGroup ref="common"/>
    <xs:attribute name="flag" type="xs:boolean"/>
  </xs:attributeGroup>
  <xs:element name="r">
    <xs:complexType>
      <xs:simpleContent>
        <xs:extension base="xs:string">
          <xs:attributeGroup ref="more"/>
        </xs:extension>
      </xs:simpleContent>
    </xs:complexType>
  </xs:element>
</xs:schema>"#
                .to_vec(),
            b"<r id=\"x1\" lang=\"en\" flag=\"true\">body</r>".to_vec(),
        ),
        // Nested attribute groups + complex type extension
        7 => (
            br#"<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           targetNamespace="urn:e" xmlns:e="urn:e"
           elementFormDefault="qualified">
  <xs:complexType name="Base">
    <xs:sequence>
      <xs:element name="a" type="xs:int"/>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="Ext">
    <xs:complexContent>
      <xs:extension base="e:Base">
        <xs:sequence>
          <xs:element name="b" type="xs:int"/>
        </xs:sequence>
      </xs:extension>
    </xs:complexContent>
  </xs:complexType>
  <xs:element name="r" type="e:Base"/>
</xs:schema>"#
                .to_vec(),
            b"<?xml version=\"1.0\"?><r xmlns=\"urn:e\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:e=\"urn:e\" xsi:type=\"e:Ext\"><a>1</a><b>2</b></r>".to_vec(),
        ),
        // IDC with nested selectors
        8 => (
            br#"<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="doc">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="section" maxOccurs="unbounded">
          <xs:complexType>
            <xs:sequence>
              <xs:element name="entry" maxOccurs="unbounded">
                <xs:complexType>
                  <xs:attribute name="key" type="xs:string" use="required"/>
                  <xs:attribute name="see" type="xs:string"/>
                </xs:complexType>
              </xs:element>
            </xs:sequence>
          </xs:complexType>
        </xs:element>
      </xs:sequence>
    </xs:complexType>
    <xs:unique name="uKeys">
      <xs:selector xpath=".//entry"/>
      <xs:field xpath="@key"/>
    </xs:unique>
    <xs:key name="kKeys">
      <xs:selector xpath="section/entry"/>
      <xs:field xpath="@key"/>
    </xs:key>
    <xs:keyref name="krSee" refer="kKeys">
      <xs:selector xpath="section/entry"/>
      <xs:field xpath="@see"/>
    </xs:keyref>
  </xs:element>
</xs:schema>"#
                .to_vec(),
            b"<doc><section><entry key=\"k1\"/><entry key=\"k2\" see=\"k1\"/></section></doc>".to_vec(),
        ),
        // Adversarial non-schema / random document
        _ => {
            let d = generator::gen_document(rng);
            let inst = generator::gen_xsi_type_instance_sketch(rng);
            (d, inst)
        }
    }
}

fn gen_rng_schema(rng: &mut impl Rng) -> Vec<u8> {
    gen_rng_schema_and_instance(rng).0
}

/// RELAX NG sketches: interleave, optional, oneOrMore, define/ref chains (bounded).
fn gen_rng_schema_and_instance(rng: &mut impl Rng) -> (Vec<u8>, Vec<u8>) {
    match rng.gen_range(0..8u8) {
        0 => (
            br#"<?xml version="1.0"?>
<element name="r" xmlns="http://relaxng.org/ns/structure/1.0">
  <empty/>
</element>"#
                .to_vec(),
            b"<r/>".to_vec(),
        ),
        1 => (
            br#"<?xml version="1.0"?>
<element name="r" xmlns="http://relaxng.org/ns/structure/1.0">
  <element name="a"><text/></element>
</element>"#
                .to_vec(),
            b"<r><a>x</a></r>".to_vec(),
        ),
        // interleave
        2 => (
            br#"<?xml version="1.0"?>
<element name="r" xmlns="http://relaxng.org/ns/structure/1.0">
  <interleave>
    <element name="a"><text/></element>
    <element name="b"><text/></element>
    <optional>
      <element name="c"><text/></element>
    </optional>
  </interleave>
</element>"#
                .to_vec(),
            b"<r><b>2</b><a>1</a></r>".to_vec(),
        ),
        // optional + oneOrMore
        3 => (
            br#"<?xml version="1.0"?>
<element name="r" xmlns="http://relaxng.org/ns/structure/1.0">
  <optional>
    <element name="meta"><text/></element>
  </optional>
  <oneOrMore>
    <element name="item">
      <attribute name="id"><text/></attribute>
      <text/>
    </element>
  </oneOrMore>
</element>"#
                .to_vec(),
            b"<r><item id=\"1\">a</item><item id=\"2\">b</item></r>".to_vec(),
        ),
        // define / ref chain (grammar form)
        4 => (
            br#"<?xml version="1.0"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <ref name="root"/>
  </start>
  <define name="root">
    <element name="r">
      <ref name="body"/>
    </element>
  </define>
  <define name="body">
    <optional>
      <ref name="child"/>
    </optional>
    <zeroOrMore>
      <element name="n"><text/></element>
    </zeroOrMore>
  </define>
  <define name="child">
    <element name="child">
      <ref name="body"/>
    </element>
  </define>
</grammar>"#
                .to_vec(),
            b"<r><child><n>x</n></child><n>y</n></r>".to_vec(),
        ),
        // Longer define/ref chain (bounded depth)
        5 => {
            let levels = rng.gen_range(2..5usize);
            let mut g = String::from(
                r#"<?xml version="1.0"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start><ref name="d0"/></start>
"#,
            );
            for i in 0..levels {
                let next = if i + 1 < levels {
                    format!("<ref name=\"d{}\"/>", i + 1)
                } else {
                    "<text/>".into()
                };
                g.push_str(&format!(
                    r#"  <define name="d{i}">
    <element name="e{i}">
      {next}
    </element>
  </define>
"#
                ));
            }
            g.push_str("</grammar>");
            let mut inst = String::new();
            for i in 0..levels {
                inst.push_str(&format!("<e{i}>"));
            }
            inst.push('z');
            for i in (0..levels).rev() {
                inst.push_str(&format!("</e{i}>"));
            }
            (g.into_bytes(), inst.into_bytes())
        }
        // interleave + oneOrMore + attribute
        6 => (
            br#"<?xml version="1.0"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="r">
      <interleave>
        <oneOrMore>
          <element name="x"><text/></element>
        </oneOrMore>
        <optional>
          <attribute name="k"><text/></attribute>
        </optional>
        <zeroOrMore>
          <element name="y"><empty/></element>
        </zeroOrMore>
      </interleave>
    </element>
  </start>
</grammar>"#
                .to_vec(),
            b"<r k=\"v\"><y/><x>a</x><x>b</x></r>".to_vec(),
        ),
        _ => (
            generator::gen_document(rng),
            b"<r/>".to_vec(),
        ),
    }
}

fn gen_regexp_pattern(rng: &mut impl Rng) -> String {
    match rng.gen_range(0..8u8) {
        0 => "a+".into(),
        1 => "[a-z]*".into(),
        2 => "(a|b)+c".into(),
        3 => "\\d{1,3}".into(),
        4 => ".*".into(),
        5 => "a{0,10}".into(),
        6 => "(a|aa)+b".into(),
        _ => "[^<>]+".into(),
    }
}

fn gen_regexp_string(rng: &mut impl Rng) -> String {
    match rng.gen_range(0..5u8) {
        0 => "aaa".into(),
        1 => "abc".into(),
        2 => "123".into(),
        3 => "".into(),
        _ => "x".into(),
    }
}

fn gen_uri(rng: &mut impl Rng) -> Vec<u8> {
    match rng.gen_range(0..8u8) {
        0 => b"http://example.test/a?b=1#c".to_vec(),
        1 => b"file:///tmp/x".to_vec(),
        2 => b"urn:oasis:names:tc:entity".to_vec(),
        3 => b"//host/path".to_vec(),
        4 => b"http://[::1]/80/".to_vec(),
        5 => b"not a uri \xff".to_vec(),
        6 => b"".to_vec(),
        _ => "http://example.test/\u{1F600}".as_bytes().to_vec(),
    }
}

fn gen_catalog(rng: &mut impl Rng) -> Vec<u8> {
    match rng.gen_range(0..3u8) {
        0 => br#"<?xml version="1.0"?>
<!DOCTYPE catalog PUBLIC "-//OASIS//DTD Entity Resolution XML Catalog V1.0//EN"
 "http://www.oasis-open.org/committees/entity/release/1.0/catalog.dtd">
<catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">
  <public publicId="-//TEST//DTD Test//EN" uri="test.dtd"/>
</catalog>"#
            .to_vec(),
        1 => br#"<?xml version="1.0"?>
<catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">
  <system systemId="http://example.test/a.dtd" uri="local.dtd"/>
</catalog>"#
            .to_vec(),
        _ => generator::gen_document(rng),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn all_apis_have_names() {
        assert_eq!(LibXml2Api::ALL.len(), 23);
        for a in LibXml2Api::ALL {
            assert!(!a.as_str().is_empty());
            let mut r = StdRng::seed_from_u64(1);
            assert!(!gen_for_api(&mut r, *a).is_empty() || matches!(a, LibXml2Api::Uri));
        }
    }
}
