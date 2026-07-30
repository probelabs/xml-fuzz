#!/usr/bin/env bash
# Backward-compatible ASan build (calls build.sh with sanitizers on).
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
XML_FUZZ_SANITIZE=1 exec bash "$DIR/build.sh" "$@"
