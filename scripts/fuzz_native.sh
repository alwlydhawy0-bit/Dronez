#!/usr/bin/env bash
# Native-code fuzzing gate for the MAVLink / ROS2 parsers (Zero-Trust §9).
#
#   scripts/fuzz_native.sh                 # report status, exit 0 if honestly N/A
#   scripts/fuzz_native.sh --require-native  # exit non-zero unless it actually ran
#
# Why this script reports "no target" instead of passing
# ------------------------------------------------------
# Zero-Trust §9 makes fuzzing plus ASan/UBSan/MSan release-blocking *for native and
# embedded code*, because MAVLink and ROS2 parsers are the classic memory-safety
# attack surface: attacker-controlled bytes off an RF link, parsed in C, on a device
# that is flying.
#
# There is no native code in this repository. `src/ros2_bridge/mavlink_signer.py` is
# pure Python, opens no socket, and implements signing rather than wire parsing -- the
# C parsers it will eventually sit beside do not exist yet (CLAUDE.md §2.1 forbids
# them until the Milestone-0 gate closes).
#
# So this gate has no target, and that is the honest thing to report. A script that
# printed PASS here would attach a green fuzzing result to a release whose native
# attack surface had never been fuzzed -- which is worse than no script at all,
# because the gate would look satisfied.
#
# `scripts/fuzz_parsers.py` fuzzes the Python parsers that DO exist and are reachable,
# including the one binary parser (the 13-byte MAVLink2 signature block).

set -euo pipefail

REQUIRE_NATIVE=0
for arg in "$@"; do
  case "$arg" in
    --require-native) REQUIRE_NATIVE=1 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "Native-code fuzzing gate (Zero-Trust §9)"
echo "========================================================================"

# Find native sources. Extensions only -- a heuristic, but the repository is
# stdlib-Python by construction, so a false negative here would be a new build system
# nobody mentioned rather than a hidden .c file.
NATIVE_FILES="$(find src -type f \( \
  -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' \
  -o -name '*.h' -o -name '*.hpp' -o -name '*.rs' \
  \) 2>/dev/null | sort || true)"

BUILD_FILES="$(find . -maxdepth 2 -type f \( \
  -name 'CMakeLists.txt' -o -name 'Makefile' -o -name 'Cargo.toml' -o -name 'setup.py' \
  \) -not -path './node_modules/*' 2>/dev/null | sort || true)"

if [ -z "$NATIVE_FILES" ]; then
  echo "native sources found:     NONE"
  echo "build files:              ${BUILD_FILES:-none}"
  echo
  echo "STATUS: NO TARGET."
  echo
  echo "  There is no native code in this repository, so there is nothing to fuzz"
  echo "  under ASan/UBSan/MSan. This is NOT a pass: the gate has not been"
  echo "  satisfied, it has not been reached."
  echo
  echo "  What must exist before this gate can pass, per Zero-Trust §9 and §11.1:"
  echo "    1. libFuzzer/AFL++ harnesses for the MAVLink2 frame parser and the"
  echo "       ROS2 message deserializer, built with -fsanitize=address,undefined"
  echo "       and a separate MSan build."
  echo "    2. A seed corpus of real frames plus the crashing inputs from"
  echo "       scripts/fuzz_parsers.py --corpus."
  echo "    3. A current fuzzing report attached to the release artifact."
  echo "    4. Zero open ASan/UBSan/MSan findings."
  echo
  echo "  Tracked as TM-31. The Python-parser coverage that DOES exist:"
  echo "    python3 scripts/fuzz_parsers.py --iterations 200000"
  echo

  if [ "$REQUIRE_NATIVE" -eq 1 ]; then
    echo "RESULT: FAIL -- --require-native was set and no native target exists."
    exit 1
  fi
  echo "RESULT: N/A -- no native target. Run with --require-native in any CI job"
  echo "that claims to satisfy the Zero-Trust §9 gate."
  exit 0
fi

echo "native sources found:"
echo "$NATIVE_FILES" | sed 's/^/  /'
echo

# Native code exists, so the gate is live and the tooling must actually be present.
MISSING=""
command -v clang >/dev/null 2>&1 || MISSING="$MISSING clang"
command -v llvm-symbolizer >/dev/null 2>&1 || MISSING="$MISSING llvm-symbolizer"

if [ -n "$MISSING" ]; then
  echo "STATUS: BLOCKED -- native sources are present but the toolchain is not:"
  echo "  missing:$MISSING"
  echo
  echo "RESULT: FAIL -- native code cannot ship without a sanitizer build."
  exit 1
fi

echo "STATUS: native sources present and toolchain available, but no fuzz harness"
echo "        is wired up in this script yet."
echo
echo "RESULT: FAIL -- add the libFuzzer harnesses before this can pass."
exit 1
