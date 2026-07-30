//! `xml_fuzz` — structure-aware XML fuzzer (json-fuzz / graphql-fuzz analog).
//!
//! # Pillars
//!
//! - **Generators** ([`generator`]): grammar-based well-formed and controlled
//!   malformed XML covering encoding, names, nesting, DTD/entities, namespaces,
//!   CDATA/comment/PI, and more.
//! - **Mutations** ([`mutate`]): XML-aware operators that truncate/corrupt at
//!   tag, attribute, entity, CDATA, namespace, and UTF-8 boundaries.
//! - **Corpus** ([`corpus`]): curated seeds for major XML bug-class families.
//! - **Gates** ([`gates`]): no-panic, clean-fail, determinism, deep-nesting-safe,
//!   round-trip, output-valid.
//! - **Orchestration** ([`fuzz`]): [`fuzz::run_structure_aware`] + [`fuzz::XmlParseTarget`].
//!
//! # Quick start
//!
//! ```
//! use xml_fuzz as xfuzz;
//! use xml_fuzz::stub_parser::StubXmlParser;
//! use xml_fuzz::XmlParseTarget;
//! use rand::SeedableRng;
//! use rand::rngs::StdRng;
//!
//! let mut rng = StdRng::seed_from_u64(42);
//! let doc = xfuzz::gen_document(&mut rng);
//! let mutated = xfuzz::apply_mutation(&mut rng, &doc);
//! let target = StubXmlParser;
//! xfuzz::gates::no_panic("parse", || {
//!     let _ = target.parse(&mutated);
//! }).unwrap();
//! ```

#![forbid(unsafe_code)]

pub mod apis;
pub mod corpus;
pub mod differential;
pub mod fuzz;
pub mod gates;
pub mod generator;
pub mod libxml2_multi;
pub mod libxml2_target;
pub mod mutate;
pub mod option_matrix;
pub mod stub_parser;
pub mod xxe_policy;

pub use apis::{gen_for_api, LibXml2Api};
pub use differential::{
    compare_outcomes, compare_with_naive, run_libxml2_option_differential,
    run_xxe_safe_vs_noent_differential, DiffProfile, DiffResult, NaiveStructuralParser,
    OutcomeClass,
};
pub use libxml2_multi::{fuzz_all_apis, fuzz_one_random_api, LibXml2MultiHarness};
pub use option_matrix::{
    default_option_matrix, run_option_matrix, MatrixDoc, MatrixExpect, OptionMatrixRow,
};

// Re-exports for a flat consumer API (mirrors graphql_fuzz / jsonfuzz style).
pub use corpus::{corpus_bytes, corpus_entries, corpus_families, CorpusEntry, CORPUS, REQUIRED_FAMILIES};
pub use fuzz::{
    each_corpus_seed, gen_work_from_input, rng_from_data, run_structure_aware, ParseOutcome,
    XmlParseTarget,
};
pub use generator::{
    gen_deep_nesting, gen_document, gen_document_at_depth, gen_malformed, gen_wellformed, gen_work,
    DEEP_NEST_DEPTH, MAX_GEN_DEPTH,
};
pub use mutate::{apply_mutation, apply_mutations, MUTATION_OPS};

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
