#!/usr/bin/env bash
# Build libxml2 harnesses (parse + multi-API).
#
# Usage:
#   bash harness/build.sh              # ASan+UBSan (default, bug-finding)
#   XML_FUZZ_SANITIZE=0 bash harness/build.sh   # no sanitizer (throughput)
#   LIBXML2_BUILD=/path/to/lib  bash harness/build.sh
#
# Outputs:
#   harness/libxml2_parse[_fast]
#   harness/libxml2_all_apis[_fast]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$(cd "$(dirname "$0")" && pwd)"

SANITIZE="${XML_FUZZ_SANITIZE:-1}"
BUILD="${LIBXML2_BUILD:-${LIBXML2_ASAN_BUILD:-$ROOT/.proof/native/libxml2-asan-build}}"

if [[ ! -d "$BUILD" ]]; then
  echo "libxml2 build not found: $BUILD" >&2
  echo "Set LIBXML2_BUILD or LIBXML2_ASAN_BUILD to a configured/built tree." >&2
  exit 1
fi

CFLAGS=(-O2 -g -I"$ROOT/include" -I"$BUILD" -I"$BUILD/libxml")
LDFLAGS=(-L"$BUILD" -lxml2 -Wl,-rpath,"$BUILD")
SUFFIX=""

if [[ "$SANITIZE" == "1" || "$SANITIZE" == "asan" ]]; then
  CFLAGS+=(-O1 -fsanitize=address,undefined -fno-omit-frame-pointer)
  LDFLAGS+=(-fsanitize=address,undefined)
  SUFFIX=""
  echo "building WITH ASan+UBSan (slower, better for memory bugs)"
else
  SUFFIX="_fast"
  echo "building WITHOUT sanitizers (faster throughput campaigns)"
fi

cc "${CFLAGS[@]}" "$OUT/libxml2_parse.c" "${LDFLAGS[@]}" -o "$OUT/libxml2_parse${SUFFIX}"
cc "${CFLAGS[@]}" "$OUT/libxml2_all_apis.c" "${LDFLAGS[@]}" -o "$OUT/libxml2_all_apis${SUFFIX}"
chmod +x "$OUT/libxml2_parse${SUFFIX}" "$OUT/libxml2_all_apis${SUFFIX}"

# Convenience symlinks for default names when building fast-only
if [[ -n "$SUFFIX" ]]; then
  # Keep default names pointing at fast builds only if asan builds absent
  if [[ ! -x "$OUT/libxml2_all_apis" ]]; then
    ln -sfn "libxml2_all_apis${SUFFIX}" "$OUT/libxml2_all_apis"
    ln -sfn "libxml2_parse${SUFFIX}" "$OUT/libxml2_parse"
  fi
fi

echo "built:"
ls -la "$OUT"/libxml2_parse* "$OUT"/libxml2_all_apis* 2>/dev/null | sed 's/^/  /'
ldd "$OUT/libxml2_all_apis${SUFFIX}" | head -8
