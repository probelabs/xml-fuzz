# libxml2 harnesses for xml-fuzz

## Binaries

| Binary | Role |
|--------|------|
| `libxml2_parse` | Single-document parse (memory / push / reader) + text fingerprint / XXE |
| `libxml2_all_apis` | **Full surface**: 23 APIs matching upstream `fuzz/*` + save/c14n/rng/tree + reader-ops/io/schema |

## Build

```sh
bash harness/build_asan.sh
# or
LIBXML2_ASAN_BUILD=/path/to/asan-build bash harness/build_asan.sh
```

## Full API list (`libxml2_all_apis --api=…`)

xml-memory, xml-push, xml-reader, xml-valid, html-memory, html-push, xpath, xpointer, schema-parse, schema-valid, rng-parse, rng-valid, regexp, uri, xinclude, save, c14n, catalog, tree, **reader-ops**, **io-callback**, **reader-schema**, **reader-rng**

| API | Behavior |
|-----|----------|
| `reader-ops` | `xmlReaderForMemory` then a bounded op stream (max 200): Read/Next/Expand/MoveToFirstAttribute/ConstValue/… Optional `OPS\n---SPLIT---\nDOC`; else first 32 input bytes are ops. |
| `io-callback` | `xmlReadIO` or `xmlCreateIOParserCtxt` with custom read callback (short reads, occasional early EOF). |
| `reader-schema` | XSD on reader: `SCHEMA\n---SPLIT---\nINSTANCE` → `xmlTextReaderSetSchema` + Read (no-op clean if schemas disabled). |
| `reader-rng` | RelaxNG on reader: same split → `xmlTextReaderRelaxNGSetSchema` + Read (no-op clean if RNG disabled). |

```sh
./libxml2_all_apis --all < seed.xml
./libxml2_all_apis --api=xpath <<'EOF'
<?xml version="1.0"?><r><a/></r>
---SPLIT---
//*
EOF
echo '<r a="1"/>' | ./libxml2_all_apis --api=reader-ops
echo '<r/>' | ./libxml2_all_apis --api=io-callback
```

Dual-input marker: `\n---SPLIT---\n`.

## Persistent worker (resource oracles)

One-shot spawn hides leaks (process exit reclaims heap). For RSS/CPU/thread/FD
growth across cases:

```sh
./libxml2_all_apis --worker
# stdin protocol (binary-safe):
#   JOB <api> <opts_int> <chunk> <nbytes>\n
#   <nbytes raw bytes>
#   QUIT\n
# stdout per job:
#   RES ok=0|1 elapsed_ms=N rss_kb=N rss_delta_kb=N threads=N fds=N cpu_user_ms=N cpu_sys_ms=N
```

Parallel campaigns: **N separate `--worker` processes** (one measurement domain
each). Do not share one worker across threads without a lock. Prefer serial
workers when hunting slow leaks; use `XML_FUZZ_MEASURE=1` on
`resource_campaign` before multi-worker throughput runs.

Fingerprints still go to stderr; only the `RES` line is on stdout.

## Env vars (Rust)

- `XML_FUZZ_LIBXML2_HARNESS` → `libxml2_parse`
- `XML_FUZZ_LIBXML2_ALL` → `libxml2_all_apis`
- `XML_FUZZ_WORKERS` → isolated worker process count (resource campaign)
- `XML_FUZZ_MEASURE` → serial-vs-N contention probe
