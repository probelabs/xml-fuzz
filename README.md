# xml-fuzz

A standalone, structure-aware **XML** fuzzer for any XML parser (libxml2,
expat, quick-xml, …). It is the XML counterpart of
[`json-fuzz`](https://github.com/probelabs/json-fuzz) and
[`graphql-fuzz`](https://github.com/probelabs/graphql-fuzz):

| Pillar | Module | Role |
|--------|--------|------|
| **Generate** | `generator` | Grammar-based well-formed + controlled malformed XML |
| **Mutate** | `mutate` | **28** XML-aware operators (`MUTATION_OPS.len()`, asserted in tests) |
| **Corpus** | `corpus` | Seed bank for encoding, names, nesting, DTD, NS, CDATA/PI, structural |
| **Gates** | `gates` | no-panic, clean-fail, determinism, deep-nesting, round-trip, output-valid |
| **Orchestrate** | `fuzz` | `run_structure_aware` + `XmlParseTarget` |

**Standalone library** (like [`json-fuzz`](https://github.com/probelabs/json-fuzz) / [`graphql-fuzz`](https://github.com/probelabs/graphql-fuzz)): not tied to libxml2. Optional C harnesses under `harness/` exercise libxml2; any parser implements `XmlParseTarget`.

Blind byte fuzzing reaches XML state-machine edges only after huge trial counts.
`xml-fuzz` always emits *structure*, then breaks it where parsers branch.

## Bug classes / nuance families

| Family | Examples |
|--------|----------|
| **Encoding / BOM / UTF-8** | UTF-8 BOM, overlong `C0 AF`, truncated sequences, `0xFF`, Latin-1 |
| **Names / attributes** | digit-start names, dup attrs, charrefs, unterminated quotes |
| **Deep nesting** | 100+ element depth open/closed (stack DoS class) |
| **DTD / entities** | internal subset, PE sketch, XXE sketch, expand sketches |
| **Namespaces** | default NS, rebind, `xml:lang` |
| **CDATA / comment / PI** | unclosed CDATA, bad comments, stylesheets PI |
| **Structural** | truncation after `<`, multi-root, mismatched tags, decl cut |

## Quick start

```toml
[dev-dependencies]
xml_fuzz = { git = "https://github.com/probelabs/xml-fuzz" }
# crates.io: xml_fuzz = "0.1"
rand = "0.8"
```

```rust
use xml_fuzz as xfuzz;
use xml_fuzz::stub_parser::StubXmlParser;
use rand::{rngs::StdRng, SeedableRng};

fn fuzz_one(seed: u64) {
    let mut rng = StdRng::seed_from_u64(seed);
    let doc = xfuzz::gen_document(&mut rng);
    let mutated = xfuzz::apply_mutation(&mut rng, &doc);
    let target = StubXmlParser;
    xfuzz::gates::no_panic("parse", || {
        let _ = target.parse(&mutated);
    }).unwrap();
}
```

Wire a **real** parser by implementing `XmlParseTarget`:

```rust,ignore
struct LibXml2;
impl xml_fuzz::XmlParseTarget for LibXml2 {
    fn parse(&self, data: &[u8]) -> Result<xml_fuzz::ParseOutcome, String> {
        // call xmlReadMemory via FFI or the C harness
        unimplemented!()
    }
}
```

See `harness/libxml2_parse.c` for a stdin → `xmlReadMemory` / push consumer.

## Structure-aware loop

```rust
use xml_fuzz::{run_structure_aware, stub_parser::StubXmlParser};

let mut target = StubXmlParser;
run_structure_aware(b"<seed/>", &mut target).unwrap();
```

## Corpus inventory

`REQUIRED_FAMILIES`: `encoding`, `names`, `nesting`, `dtd_entity`, `namespaces`,
`cdata_comment_pi`, `structural` — enforced by unit tests.

## Fill libxml2 — all APIs

The multi-API harness exercises the same surfaces as upstream `fuzz/` plus more:

| API flag | libxml2 entry |
|----------|----------------|
| `xml-memory` / `xml-push` / `xml-reader` / `xml-valid` | `xmlReadMemory`, `xmlParseChunk`, `xmlTextReader*`, DTD valid |
| `html-memory` / `html-push` | `htmlReadMemory`, `htmlParseChunk` |
| `xpath` / `xpointer` | `xmlXPathEvalExpression`, `xmlXPtrEval` |
| `schema-parse` / `schema-valid` | `xmlSchemaParse`, `xmlSchemaValidateDoc` |
| `rng-parse` / `rng-valid` | `xmlRelaxNGParse`, `xmlRelaxNGValidateDoc` |
| `regexp` | `xmlRegexpCompile` / `xmlRegexpExec` |
| `uri` | `xmlParseURI`, `xmlSaveUri`, `xmlURIEscapeStr` |
| `xinclude` | `xmlXIncludeProcess` |
| `save` / `c14n` | `xmlSaveToBuffer`, `xmlC14NDocDumpMemory` |
| `catalog` | `xmlLoadACatalog` / resolve |
| `tree` | `xmlCopyNode`, `xmlAddChild`, … |
| `reader-ops` | bounded `xmlTextReader*` op stream (max 200; like `fuzz/reader.c`) |
| `io-callback` | `xmlReadIO` / `xmlCreateIOParserCtxt` with short-read callback |
| `reader-schema` / `reader-rng` | schema on reader (`SCHEMA` + `INSTANCE` split) |

```sh
cd xml-fuzz
bash harness/build_asan.sh
export XML_FUZZ_LIBXML2_ALL=$PWD/harness/libxml2_all_apis
cargo run --example fuzz_all_libxml2
# or one API:
echo '<r/>' | ./harness/libxml2_all_apis --api=xml-reader
./harness/libxml2_all_apis --all < seed.xml
```

Dual-input APIs use `\n---SPLIT---\n` (doc/expr, schema/instance, pattern/string).

## Long campaign

Timed multi-API structure-aware loop (random API + `gen_for_api` + mutations +
multi harness parse). Writes interesting inputs under `crashes/`:

| Env | Default | Meaning |
|-----|---------|---------|
| `XML_FUZZ_SECONDS` | `120` | Wall-clock budget |
| `XML_FUZZ_ITERS` | (none) | Optional hard iteration cap |
| `XML_FUZZ_LIBXML2_ALL` | discover | Path to `libxml2_all_apis` |
| `XML_FUZZ_CRASH_DIR` | `crashes` | Where to store findings |

Findings (Timeout, GateFailure, ASan-like exit) are saved as
`crashes/crash-{api}-{seed}.bin` and logged on stderr. End-of-run stats print
iters, per-api counts, timeouts, and findings.

```sh
cd xml-fuzz
bash harness/build_asan.sh
export XML_FUZZ_LIBXML2_ALL=$PWD/harness/libxml2_all_apis
XML_FUZZ_SECONDS=120 cargo run --example long_campaign --release
# short smoke:
XML_FUZZ_SECONDS=5 XML_FUZZ_ITERS=20 cargo run --example long_campaign
```

## Resource oracles (leaks / growth / threads / FDs)

Spawning a **new process per case** reclaims heap on exit, so leaks are
invisible. The multi-API harness supports a **persistent worker**:

```text
libxml2_all_apis --worker
  → JOB <api> <opts_mask> <chunk> <nbytes>\n  + raw body
  ← RES ok=… elapsed_ms=… rss_kb=… rss_delta_kb=… threads=… fds=… cpu_user_ms=… cpu_sys_ms=…
```

Rust side: `resource::{ResourceWorker, ResourceBudgets, check_resource}` and
`examples/resource_campaign.rs`.

### Parallelism policy

| Mode | How | When |
|------|-----|------|
| **`XML_FUZZ_WORKERS=1` (default)** | One long-lived process, serial jobs | **Leak / RSS growth oracles** — trustworthy baseline and cumulative growth |
| **`XML_FUZZ_WORKERS=N`** | N isolated processes, one thread each | Throughput only after measure looks clean |
| **`XML_FUZZ_MEASURE=1`** | Same job list, serial then N-way | Decide if multi-worker noise is acceptable |

Do **not** share one worker across threads without a lock. Multi-worker still
keeps **one job at a time per process**, so each process’s RSS domain stays pure;
host CPU contention can still inflate `elapsed_ms`.

```sh
bash harness/build.sh
export XML_FUZZ_LIBXML2_ALL=$PWD/harness/libxml2_all_apis
# accurate resource campaign (recommended)
XML_FUZZ_SECONDS=60 cargo run --example resource_campaign --release
# contention probe before enabling multi-worker for speed
XML_FUZZ_MEASURE=1 XML_FUZZ_WORKERS=4 XML_FUZZ_ITERS=200 \
  cargo run --example resource_campaign --release
```

Example measure verdict on a busy host (ASan harness): ~1.6× speedup with 4
workers, but higher `rss_delta` noise and ~2× mean elapsed — keep **workers=1**
for leak hunting; multi-worker is optional for throughput after the probe.

## Corpus export

Export curated corpus entries (by family) plus a generated batch, and refresh
the keyword dictionary used with external engines (AFL/libFuzzer `-x`):

```sh
cd xml-fuzz
cargo run --example export_seeds
# or:
bash scripts/export_corpus.sh
```

Layout:

```
corpus_export/
  encoding/…  names/…  nesting/…  dtd_entity/…  …
  generated/doc-0000.xml  mal-0000.xml  api-xpath/seed-0.bin …
tools/xml-fuzz.dict          # tags, DTD, XPath tokens
```

Env overrides: `XML_FUZZ_EXPORT_DIR`, `XML_FUZZ_EXPORT_GEN`, `XML_FUZZ_DICT`.

## CI

```sh
bash scripts/ci-xml-fuzz.sh
# rebuilds harness if LIBXML2_ASAN_BUILD / .proof/native/libxml2-asan-build exists,
# then cargo test + short fuzz_all_libxml2 (XML_FUZZ_ITERS=2)
```

## Tests & example

```sh
cd xml-fuzz
cargo test
cargo run --example fuzz_loop
cargo run --example fuzz_all_libxml2   # needs multi harness
cargo run --example export_seeds
XML_FUZZ_SECONDS=5 cargo run --example long_campaign   # needs multi harness
```

## Non-goals

- Replacing libxml2’s C `fuzz/` libFuzzer targets
- Claiming exhaustive discovery of all XML bugs (“perfect” means reference-class depth)
- Full HTML5 browser parsing (XML-first)
