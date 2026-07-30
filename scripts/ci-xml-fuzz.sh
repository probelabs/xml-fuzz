#!/usr/bin/env bash
# CI entrypoint for xml-fuzz: optional ASan harness rebuild, unit tests, short multi-API fuzz.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Workspace root (libxml2 tree) is parent of xml-fuzz.
WS="$(cd "$ROOT/.." && pwd)"
ASAN_BUILD="${LIBXML2_ASAN_BUILD:-$WS/.proof/native/libxml2-asan-build}"

echo "==> xml-fuzz CI (cwd=$ROOT)"

# 1) Rebuild harnesses when an ASan libxml2 build directory is present.
asan_present=0
if [[ -d "$ASAN_BUILD" ]]; then
  if compgen -G "$ASAN_BUILD/libxml2.so*" >/dev/null 2>&1 \
    || [[ -f "$ASAN_BUILD/libxml2.dylib" ]] \
    || [[ -f "$ASAN_BUILD/libxml2.a" ]]; then
    asan_present=1
  else
    # Directory exists; still attempt build (headers/config may be enough).
    asan_present=1
  fi
fi

if [[ "$asan_present" -eq 1 ]]; then
  echo "==> ASan build dir at $ASAN_BUILD — building harnesses"
  if [[ -f "$ROOT/harness/build_asan.sh" ]]; then
    if ! LIBXML2_ASAN_BUILD="$ASAN_BUILD" bash "$ROOT/harness/build_asan.sh"; then
      echo "WARN: harness ASan build failed; continuing with existing binaries if any"
    fi
  fi
else
  echo "==> No ASan build at $ASAN_BUILD — skipping harness rebuild"
fi

# 2) Unit + integration tests (includes proptest).
echo "==> cargo test"
cargo test

# 3) Short multi-API fuzz when harness binary is available.
HARNESS="${XML_FUZZ_LIBXML2_ALL:-$ROOT/harness/libxml2_all_apis}"
if [[ -f "$HARNESS" ]]; then
  echo "==> short fuzz_all_libxml2 via $HARNESS"
  export XML_FUZZ_LIBXML2_ALL="$HARNESS"
  export XML_FUZZ_ITERS="${XML_FUZZ_ITERS:-2}"
  cargo run --example fuzz_all_libxml2
else
  echo "==> harness not found at $HARNESS — skipping fuzz_all_libxml2"
fi

echo "==> xml-fuzz CI OK"
