#!/usr/bin/env bash
#
# mayhem/build.sh -- build two libFuzzer harnesses over bkcrack's ZIP CONTAINER PARSER
# (bkcrack/Zip.{hpp,cpp}, upstream's OWN, unmodified sources; we only compile them here), plus
# standalone reproducers, AND bkcrack's own homegrown test suite + CLI (built with the project's
# NORMAL flags) for mayhem/test.sh.
#
#   fuzz_zip         -- Zip{istream} + walk the central directory (Zip::begin()/end(), decoding
#                       every ExtraField block: AES / Info-Zip Unicode path / Zip64) + Zip::load()
#                       each entry's raw bytes (re-parses the local file header via Zip::seek()).
#                       The core untrusted-input parser surface.
#   fuzz_zip_decrypt -- Zip::decrypt() with a fixed default Keys{}: a SEPARATE code path that
#                       re-reads/rewrites the whole archive (LocalFileHeader::read at each
#                       encrypted entry, Zip64 extra-field substitution, the optional data
#                       descriptor variants, a second central-directory rewrite pass, the Zip64
#                       EOCD/locator/EOCD tail). Deliberately NOT the Biham-Kocher attack itself
#                       (Zreduction/Attack.cpp) -- that search is compute-bound by design and out
#                       of scope for fuzzing; decrypt() only XORs with whatever Keys it is given,
#                       so it never touches that search.
#
# bkcrack-core is built TWICE: once here with $SANITIZER_FLAGS (+ -fsanitize=fuzzer-no-link,
# unconditionally, even under an explicit empty --build-arg SANITIZER_FLAGS= build) so the fuzzed
# parser carries SanitizerCoverage, and once below with the project's NORMAL flags for the
# oracle. Both are ordinary, independent CMake build trees (mayhem-build/fuzz, mayhem-build/oracle)
# -- upstream's own build never runs at the repo root, so there is no make-clean/stash dance.
#
# bkcrack has ZERO third-party dependencies beyond libpthread (see src/bkcrack/CMakeLists.txt --
# only find_package(Threads)), so both builds are fully air-gapped by construction: nothing here
# ever reaches the network.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) -- must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# Always ensure the LIBRARY gets SanitizerCoverage instrumentation, regardless of the base image's
# default or an empty override -- otherwise Mayhem would see 0 edges from the parser despite the
# harness translation unit itself being instrumented via $LIB_FUZZING_ENGINE at the final link.
case "$SANITIZER_FLAGS" in
  *fuzzer-no-link*) ;;  # already present
  *) SANITIZER_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link" ;;
esac
# DWARF <= 3 (SPEC 6.2 item 10): clang-19's plain -g emits DWARF-5; be explicit.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE STANDALONE_FUZZ_MAIN MAYHEM_JOBS COVERAGE_FLAGS
cd "$SRC"

BUILD_ROOT="$SRC/mayhem-build"
mkdir -p "$BUILD_ROOT"

# ─────────────────────────────────────────────────────────────────────────────────────────────
# 1) Sanitized bkcrack-core (SanCov + ASan/UBSan + DWARF-3). Only the CORE library is needed --
#    the harnesses call into bkcrack/Zip.hpp directly, never through the CLI. BKCRACK_BUILD_TESTING
#    stays OFF here (the fuzz tree has no business building the CLI/tests -- see the oracle build
#    below for that).
# ─────────────────────────────────────────────────────────────────────────────────────────────
FUZZ_BUILD="$BUILD_ROOT/fuzz"
cmake -S "$SRC" -B "$FUZZ_BUILD" -G Ninja \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
  -DBKCRACK_BUILD_TESTING=OFF -DBKCRACK_BUILD_DOC=OFF -DBKCRACK_BUILD_COVERAGE=OFF
cmake --build "$FUZZ_BUILD" --target bkcrack-core -j"$MAYHEM_JOBS"

FUZZ_LIB="$(find "$FUZZ_BUILD" -maxdepth 3 -type f -name 'libbkcrack-core.a' | head -1)"
[ -n "$FUZZ_LIB" ] && [ -f "$FUZZ_LIB" ] || { echo "FATAL: libbkcrack-core.a not produced by the fuzz build" >&2; exit 1; }
FUZZ_INC="-I $SRC/include -I $FUZZ_BUILD/include"

# $STANDALONE_FUZZ_MAIN is a C file: compile it once as C (a C++ harness would otherwise mangle its
# LLVMFuzzerTestOneInput reference) and reuse it per target.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c -x c "$STANDALONE_FUZZ_MAIN" -o "$FUZZ_BUILD/standalone_main.o"

# build_harness <target-name> <harness .cpp>
build_harness() {
  local name="$1" src="$2"
  echo "=== building /mayhem/$name (fuzzer) ==="
  $CXX -std=c++20 $SANITIZER_FLAGS $DEBUG_FLAGS $FUZZ_INC $LIB_FUZZING_ENGINE \
      "$src" "$FUZZ_LIB" -lpthread -o "/mayhem/$name"
  echo "=== building /mayhem/$name-standalone (reproducer) ==="
  $CXX -std=c++20 $SANITIZER_FLAGS $DEBUG_FLAGS $FUZZ_INC \
      "$src" "$FUZZ_BUILD/standalone_main.o" "$FUZZ_LIB" -lpthread -o "/mayhem/$name-standalone"
}

build_harness fuzz_zip         "$SRC/mayhem/harnesses/fuzz_zip.cpp"
build_harness fuzz_zip_decrypt "$SRC/mayhem/harnesses/fuzz_zip_decrypt.cpp"

# Ship the per-target libFuzzer dictionaries the Mayhemfiles reference -- a referenced-but-absent
# dict makes libFuzzer exit 1 at 0 edges.
cp -f "$SRC/mayhem/fuzz_zip/fuzz_zip.dict"                 /mayhem/fuzz_zip.dict
cp -f "$SRC/mayhem/fuzz_zip_decrypt/fuzz_zip_decrypt.dict" /mayhem/fuzz_zip_decrypt.dict

# ─────────────────────────────────────────────────────────────────────────────────────────────
# 2) The ORACLE: a separate, CLEAN, NON-sanitized build of upstream's OWN homegrown test suite
#    (tests/runner/TestRunner.{hpp,cpp} -- NOT Catch2/gtest; see mayhem/test.sh's header comment)
#    plus the `bkcrack` CLI itself, built with the project's NORMAL flags so it stays an honest
#    functional oracle, not a triage artifact. BKCRACK_BUILD_TESTING=ON pulls in
#    tests/CMakeLists.txt, which registers one unittest-<name> executable per *.test.cpp file
#    (~16 of them) plus the CLI-driven ctest cases.
# ─────────────────────────────────────────────────────────────────────────────────────────────
ORACLE_BUILD="$BUILD_ROOT/oracle"
cmake -S "$SRC" -B "$ORACLE_BUILD" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
  -DBKCRACK_BUILD_TESTING=ON -DBKCRACK_BUILD_DOC=OFF -DBKCRACK_BUILD_COVERAGE=OFF
cmake --build "$ORACLE_BUILD" -j"$MAYHEM_JOBS"

# Sanity: the CLI binary and at least one unittest-* binary must exist, and both must be
# dynamically linked so verify-repo's LD_PRELOAD sabotage shim can actually neuter them -- a
# statically-linked test binary would survive sabotage and make mayhem/test.sh a
# reward-hackable oracle (SPEC 6.3). Plain clang/clang++ links dynamically by default; assert it
# so a toolchain change can't silently flip this.
CLI_BIN="$(find "$ORACLE_BUILD" -maxdepth 3 -type f -name bkcrack -perm -u+x | head -1)"
[ -n "$CLI_BIN" ] && [ -x "$CLI_BIN" ] || { echo "FATAL: the bkcrack CLI binary was not produced by the oracle build" >&2; exit 1; }
if ! file "$CLI_BIN" | grep -q 'dynamically linked'; then
  echo "FATAL: $CLI_BIN is not dynamically linked -- the sabotage check could not neuter it" >&2
  file "$CLI_BIN" >&2
  exit 1
fi

UNIT_BINS="$(find "$ORACLE_BUILD" -type f -name 'unittest-*' -perm -u+x)"
[ -n "$UNIT_BINS" ] || { echo "FATAL: no unittest-* binaries were produced by the oracle build" >&2; exit 1; }
while IFS= read -r bin; do
  [ -n "$bin" ] || continue
  if ! file "$bin" | grep -q 'dynamically linked'; then
    echo "FATAL: $bin is not dynamically linked -- the sabotage check could not neuter it" >&2
    file "$bin" >&2
    exit 1
  fi
done <<<"$UNIT_BINS"

echo "build.sh complete:"
ls -la /mayhem/fuzz_zip /mayhem/fuzz_zip_decrypt /mayhem/fuzz_zip-standalone /mayhem/fuzz_zip_decrypt-standalone
echo "CLI:    $CLI_BIN"
echo "unit test binaries:"
printf '%s\n' "$UNIT_BINS"
