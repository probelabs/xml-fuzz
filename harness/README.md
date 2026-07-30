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

## Env vars (Rust)

- `XML_FUZZ_LIBXML2_HARNESS` → `libxml2_parse`
- `XML_FUZZ_LIBXML2_ALL` → `libxml2_all_apis`
