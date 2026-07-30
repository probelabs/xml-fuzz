#!/usr/bin/env bash
# Build multi-API + single-parse harnesses against workspace ASan libxml2.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ASAN="${LIBXML2_ASAN_BUILD:-$ROOT/.proof/native/libxml2-asan-build}"
OUT="$(cd "$(dirname "$0")" && pwd)"
cc -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I"$ROOT/include" -I"$ASAN" -I"$ASAN/libxml" \
  "$OUT/libxml2_parse.c" \
  -L"$ASAN" -lxml2 -Wl,-rpath,"$ASAN" \
  -o "$OUT/libxml2_parse"
cc -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I"$ROOT/include" -I"$ASAN" -I"$ASAN/libxml" \
  "$OUT/libxml2_all_apis.c" \
  -L"$ASAN" -lxml2 -Wl,-rpath,"$ASAN" \
  -o "$OUT/libxml2_all_apis"
chmod +x "$OUT/libxml2_parse" "$OUT/libxml2_all_apis"
echo "built $OUT/libxml2_parse and $OUT/libxml2_all_apis against $ASAN"
ldd "$OUT/libxml2_all_apis" | head -8
