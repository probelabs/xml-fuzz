#!/usr/bin/env bash
# Export corpus + generated seeds to corpus_export/{family}/ and refresh tools/xml-fuzz.dict.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export XML_FUZZ_EXPORT_DIR="${XML_FUZZ_EXPORT_DIR:-$ROOT/corpus_export}"
export XML_FUZZ_DICT="${XML_FUZZ_DICT:-$ROOT/tools/xml-fuzz.dict}"
export XML_FUZZ_EXPORT_GEN="${XML_FUZZ_EXPORT_GEN:-32}"

cargo run --example export_seeds

echo "corpus export ready under $XML_FUZZ_EXPORT_DIR"
echo "dictionary: $XML_FUZZ_DICT"
