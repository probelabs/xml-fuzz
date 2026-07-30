//! Export corpus entries + a generated batch into `corpus_export/{family}/`.
//!
//! Also (re)writes `tools/xml-fuzz.dict` with XML/DTD/XPath keyword tokens.
//!
//! ```sh
//! cargo run --example export_seeds
//! # optional:
//! #   XML_FUZZ_EXPORT_DIR=corpus_export
//! #   XML_FUZZ_EXPORT_GEN=32   # generated docs per wellformed/malformed series
//! #   XML_FUZZ_DICT=tools/xml-fuzz.dict
//! ```

use rand::rngs::StdRng;
use rand::SeedableRng;
use std::fs;
use std::path::{Path, PathBuf};
use xml_fuzz::apis::{gen_for_api, LibXml2Api};
use xml_fuzz::{self as xfuzz};

fn main() {
    let export_root = PathBuf::from(
        std::env::var_os("XML_FUZZ_EXPORT_DIR").unwrap_or_else(|| "corpus_export".into()),
    );
    let gen_n: usize = std::env::var("XML_FUZZ_EXPORT_GEN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(32);
    let dict_path = PathBuf::from(
        std::env::var_os("XML_FUZZ_DICT").unwrap_or_else(|| "tools/xml-fuzz.dict".into()),
    );

    // --- corpus entries by family ---
    let mut corpus_count = 0usize;
    for entry in xfuzz::corpus_entries() {
        let dir = export_root.join(entry.family);
        fs::create_dir_all(&dir).expect("mkdir family");
        let path = dir.join(format!("{}.xml", entry.id));
        fs::write(&path, entry.data).expect("write corpus entry");
        corpus_count += 1;
    }

    // --- generated batch (document + malformed + per-API samples) ---
    let gen_dir = export_root.join("generated");
    fs::create_dir_all(&gen_dir).expect("mkdir generated");
    let mut rng = StdRng::seed_from_u64(0x005E_EDF0_22u64);
    let mut gen_count = 0usize;

    for i in 0..gen_n {
        let doc = xfuzz::gen_document(&mut rng);
        fs::write(gen_dir.join(format!("doc-{i:04}.xml")), &doc).expect("write gen doc");
        gen_count += 1;

        let mal = xfuzz::gen_malformed(&mut rng);
        fs::write(gen_dir.join(format!("mal-{i:04}.xml")), &mal).expect("write gen mal");
        gen_count += 1;
    }

    // One small batch per multi-API surface under generated/api-{name}/
    for (ai, &api) in LibXml2Api::ALL.iter().enumerate() {
        let dir = gen_dir.join(format!("api-{}", api.as_str()));
        fs::create_dir_all(&dir).expect("mkdir api");
        for j in 0..4u64 {
            let mut r = StdRng::seed_from_u64((ai as u64 + 1) * 10_000 + j);
            let data = gen_for_api(&mut r, api);
            fs::write(dir.join(format!("seed-{j}.bin")), &data).expect("write api seed");
            gen_count += 1;
        }
    }

    // --- dictionary ---
    if let Some(parent) = dict_path.parent() {
        fs::create_dir_all(parent).expect("mkdir tools");
    }
    fs::write(&dict_path, XML_FUZZ_DICT).expect("write dict");

    println!(
        "export_seeds: corpus_entries={corpus_count} generated_files={gen_count} root={} dict={}",
        export_root.display(),
        dict_path.display()
    );
    print_tree_summary(&export_root);
}

fn print_tree_summary(root: &Path) {
    let mut families: Vec<String> = Vec::new();
    if let Ok(rd) = fs::read_dir(root) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                let n = fs::read_dir(e.path()).map(|i| i.count()).unwrap_or(0);
                families.push(format!("{}={n}", e.file_name().to_string_lossy()));
            }
        }
    }
    families.sort();
    println!("families: {}", families.join(" "));
}

/// AFL/libFuzzer-style keyword dictionary for structure-aware XML fuzzing.
/// Uses `r##"..."##` so dictionary values like `"#REQUIRED"` do not terminate the string.
const XML_FUZZ_DICT: &str = r##"# xml-fuzz dictionary — tags, DTD, namespaces, XPath tokens
# Compatible with libFuzzer / AFL -x style keyword files.

# XML prolog / encoding
xml_decl="<?xml version=\"1.0\"?>"
xml_decl_enc="<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
xml_decl_11="<?xml version=\"1.1\"?>"
xml_standalone="<?xml version=\"1.0\" standalone=\"yes\"?>"
bom_utf8="\xEF\xBB\xBF"

# Elements / structure
elem_empty="<a/>"
elem_pair="<a></a>"
elem_nested="<a><b/></a>"
lt="<"
gt=">"
slash_gt="/>"
close="</"
amp="&"
quot="\""
apos="'"

# Attributes / names
attr_eq=" a=\""
attr_id=" id=\""
xmlns=" xmlns=\""
xmlns_p=" xmlns:a=\""
xml_lang=" xml:lang=\""
xml_space=" xml:space=\"preserve\""
xml_base=" xml:base=\""

# CDATA / comment / PI
cdata_open="<![CDATA["
cdata_close="]]>"
comment="<!-- -->"
comment_open="<!--"
pi_xml_stylesheet="<?xml-stylesheet"
pi_close="?>"

# DTD / entities
doctype="<!DOCTYPE "
doctype_sys="<!DOCTYPE a SYSTEM \""
doctype_pub="<!DOCTYPE a PUBLIC \""
elem_decl="<!ELEMENT "
attlist="<!ATTLIST "
entity="<!ENTITY "
entity_pe="<!ENTITY % "
notation="<!NOTATION "
pcdata="#PCDATA"
cdata_kw="CDATA"
required="#REQUIRED"
implied="#IMPLIED"
fixed="#FIXED"
system="SYSTEM"
public="PUBLIC"
include_sect="<![INCLUDE["
ignore_sect="<![IGNORE["
entity_ref="&amp;"
charref_dec="&#"
charref_hex="&#x"

# Namespaces / XInclude / XSI
ns_xml="http://www.w3.org/XML/1998/namespace"
ns_xmlns="http://www.w3.org/2000/xmlns/"
ns_xi="http://www.w3.org/2001/XInclude"
ns_xsi="http://www.w3.org/2001/XMLSchema-instance"
xi_include="<xi:include "
xi_fallback="<xi:fallback"
xsi_nons="xsi:noNamespaceSchemaLocation=\""
xsi_schema="xsi:schemaLocation=\""

# XPath / XPointer tokens
xpath_root="/"
xpath_desc="//"
xpath_attr="@"
xpath_dotdot=".."
xpath_wildcard="*"
xpath_union="|"
axis_child="child::"
axis_desc="descendant::"
axis_desc_or_self="descendant-or-self::"
axis_attr="attribute::"
axis_parent="parent::"
axis_self="self::"
axis_anc="ancestor::"
axis_fs="following-sibling::"
axis_ps="preceding-sibling::"
fn_text="text()"
fn_node="node()"
fn_pos="position()"
fn_last="last()"
fn_count="count("
fn_name="name("
fn_local="local-name("
fn_nsuri="namespace-uri("
fn_string="string("
fn_concat="concat("
fn_contains="contains("
fn_starts="starts-with("
fn_not="not("
fn_true="true()"
fn_false="false()"
xptr_range="xpointer("
xptr_xmlns="xmlns("

# Schema / RNG / regexp sketches
xsd_schema="<xs:schema"
xsd_elem="<xs:element"
xsd_attr="<xs:attribute"
xsd_complex="<xs:complexType"
rng_grammar="<grammar "
rng_element="<element "
regexp_dotstar=".*"
regexp_plus="[a-z]+"

# Split marker used by multi-API dual-input harness
split_marker="\n---SPLIT---\n"

# URI sketches
uri_http="http://"
uri_file="file://"
uri_urn="urn:"
"##;