# ADHD cycle notes (xml-fuzz)

## Diverge
See implementer scratch `adhd/diverge.md` (10 high-EV gaps).

## Critic (initial)
Ranked must-fix: libxml2 target options, budget gates, PE/XXE sandbox policy, inventory honesty.

## Addressed after critic
| Item | Action |
|------|--------|
| libxml2 options/push | `libxml2_target.rs` + harness CLI flags (`--noent`, `--push`, `--chunk=`, …) |
| Budget gate | `gates::within_budget` + `within_budget_sync`; wired in `run_structure_aware` |
| XXE policy | `xxe_policy.rs` with **sandbox** `fixtures/sandbox/secret.txt`, not `/etc/passwd` |
| Inventory | `MUTATION_OPS` asserted **28**; `REQUIRED_FAMILIES` includes xinclude/xml11/schema_xsi |
| Round-trip | gate available; full AST RT needs real serializer — deferred with rationale below |

## Explicit deferrals
- **Differential multi-parser oracle** (libxml2 vs expat vs quick-xml) — high EV, separate harnesses.
- **Full XSD/RNG compile+validate dual-input API** — needs schema+instance pair generator.
- **Hard kill of hung native parse inside the same Rust thread** — hang control is via **subprocess kill** on `LibXml2Harness` (`timeout` + `child.kill()`), not in-process interrupt of libxml2.
- **NDATA / unparsed entity / notation depth** beyond PE sketches — deferred; multi-level PE + sandbox external subset **implemented** (`gen_pe_depth_sketch`, `fixtures/sandbox/pe.dtd`/`pe2.dtd`, corpus `dtd-pe-*`).
- **Circular XInclude graphs** — generator has basic xi:include only.
- **Deep XML 1.1 NameChar inventory** — version 1.1 sketches only.

## Skeptic round fixes (same day)
- Harness emits `text=` document content + `mode=` + `elapsed_ms=`; XXE policy checks **text fingerprint**.
- `--reader` implemented via `xmlReaderForMemory` (no silent fall-through).
- Budget: harness **kill on timeout**; structure-aware samples options/push/reader/chunk.
- Removed `/etc/passwd` from corpus/generators; sandbox URIs only.

## Verdict after fixes
Reference-class **pillar structure** + **XML-depth generators/mutations/corpus** + **real libxml2 consumer path** when harness is built. Stub remains for pure unit tests. Not a claim of exhaustive bug discovery.

**Post-fix re-test:** `cargo test` green (incl. multi-API); `fuzz_loop` / `fuzz_all_libxml2` findings=0.

## Full libxml2 fill
All major public surfaces driven via `libxml2_all_apis` (23 modes): xml memory/push/reader/valid, html memory/push, xpath/xpointer, schema parse/valid, rng parse/valid, regexp, uri, xinclude, save, c14n, catalog, tree, reader-ops, io-callback, reader-schema, reader-rng. Structure-aware generators per API in `apis.rs`.
