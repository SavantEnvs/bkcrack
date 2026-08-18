#!/usr/bin/env bash
#
# mayhem/test.sh -- run bkcrack's own functional oracle, built by mayhem/build.sh with the
# project's NORMAL (non-sanitized) flags. Two independent legs, both unconditional (a missing
# binary/marker/value is a FAILURE, never a skip):
#
#   (A) bkcrack's OWN homegrown test suite (tests/runner/TestRunner.{hpp,cpp} -- NOT Catch2/gtest;
#       upstream rolled its own ~90-line CHECK()/CHECK_THROWS() framework). Each *.test.cpp file
#       under tests/bkcrack/ and tests/cli/ becomes its own `unittest-<name>` executable
#       (tests/CMakeLists.txt's bkcrack_add_unittest()). Every one is run DIRECTLY (never through
#       ctest) and we parse TestRunner's OWN summary line -- "Tests: N pass, M fail" (printed by
#       TestRunner::runAllTests() in tests/runner/TestRunner.cpp) -- NOT the process exit code.
#       This matters: ctest/meson judge a case purely by its child's exit code, and a binary that
#       is `_exit(0)`'d by the verify-repo sabotage shim before it prints a single character looks
#       like a passing test to an exit-code-only runner (proven empirically on pkgconf -- 32/32
#       "OK" under sabotage). Here, a neutered binary produces NO summary line at all, which we
#       treat as an unconditional FAIL for that binary -- sabotage cannot hide behind a clean exit
#       code either. We exclude unittest-testrunner-{pass,fail}: they test the TEST FRAMEWORK
#       itself, not bkcrack (and testrunner-fail is upstream's OWN deliberately-failing case --
#       ctest marks it WILL_FAIL -- so folding it into our pass/fail tally would be wrong either
#       way we count it).
#   (B) Direct KAT probes through the `bkcrack` CLI binary itself (also built by build.sh with
#       normal flags, also dynamically linked -- asserted there). Fixed archive fixtures ->
#       EXACT expected stdout lines, lifted by hand from a real build of this exact commit (see
#       the comment above each check_kat call): a `--version` string, and `-L` (list) rows for
#       three different container shapes (a plain+ZipCrypto real-world archive, a Zip64 archive,
#       and a Zip64+ZipCrypto archive) -- each `-L` row is only printed after Zip::Iterator has
#       actually decoded that entry's central directory record (name, encryption, compression,
#       crc32, sizes), so this exercises exactly the ZIP CONTAINER PARSER the fuzz harnesses
#       target, through the one binary a neutered library cannot fake: a no-op/exit(0) bkcrack
#       would print nothing, and every grep below would fail.
#
# Together (A)+(B) assert real computed VALUES through binaries the sabotage shim CAN neuter
# (both asserted dynamically linked by build.sh), not merely "the process exited 0" -- the
# anti-reward-hacking property SPEC 6.3 requires. This script only RUNS things; mayhem/build.sh
# already built every binary referenced here.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

ORACLE_BUILD="$SRC/mayhem-build/oracle"
if [ ! -d "$ORACLE_BUILD" ]; then
  echo "FATAL: $ORACLE_BUILD is missing -- mayhem/build.sh should have built the oracle" >&2
  emit_ctrf "bkcrack-oracle" 0 1
  exit $?
fi

total_all=0
passed_all=0
failed_all=0
nbins=0

# ── (A) bkcrack's own TestRunner-based unit suite ───────────────────────────────────────────
unit_bins="$(find "$ORACLE_BUILD" -type f -name 'unittest-*' -perm -u+x \
             | grep -vE '/unittest-testrunner-(pass|fail)$' | sort)"
if [ -z "$unit_bins" ]; then
  echo "FATAL: no unittest-* binaries found under $ORACLE_BUILD" >&2
  emit_ctrf "bkcrack-oracle" 0 1
  exit $?
fi
while IFS= read -r bin; do
  [ -n "$bin" ] || continue
  nbins=$((nbins + 1))
  out="$("$bin" 2>&1)"
  summary="$(printf '%s\n' "$out" | grep -E '^Tests: [0-9]+ pass, [0-9]+ fail' | tail -1)"
  if [ -z "$summary" ]; then
    echo "ORACLE FAIL: $(basename "$bin") produced no TestRunner summary line (neutered, crashed, or hung?)" >&2
    failed_all=$((failed_all + 1))
    total_all=$((total_all + 1))
    continue
  fi
  pass="$(printf '%s' "$summary" | grep -oE '[0-9]+ pass' | grep -oE '[0-9]+')"
  fail="$(printf '%s' "$summary" | grep -oE '[0-9]+ fail' | grep -oE '[0-9]+')"
  : "${pass:=0}" "${fail:=0}"
  case_total=$((pass + fail))
  if [ "$case_total" -eq 0 ]; then
    echo "ORACLE FAIL: $(basename "$bin") registered 0 test cases (empty suite is suspicious)" >&2
    failed_all=$((failed_all + 1))
    total_all=$((total_all + 1))
    continue
  fi
  total_all=$((total_all + case_total))
  passed_all=$((passed_all + pass))
  failed_all=$((failed_all + fail))
done <<<"$unit_bins"
echo "TestRunner suite: $nbins binaries, $total_all cases, $passed_all passed, $((total_all - passed_all)) failed"

# ── (B) direct KAT probes through the bkcrack CLI ───────────────────────────────────────────
CLI_BIN="$(find "$ORACLE_BUILD" -maxdepth 3 -type f -name bkcrack -perm -u+x | head -1)"
if [ -z "$CLI_BIN" ] || [ ! -x "$CLI_BIN" ]; then
  echo "ORACLE FAIL: the bkcrack CLI binary is missing -- mayhem/build.sh should have built it" >&2
  CLI_OUT_VERSION=""; CLI_OUT_SECRETS=""; CLI_OUT_ZIP64=""; CLI_OUT_ZIP64_ZC=""
  failed_all=$((failed_all + 4)); total_all=$((total_all + 4))
else
  CLI_OUT_VERSION="$("$CLI_BIN" --version 2>&1 || true)"
  CLI_OUT_SECRETS="$("$CLI_BIN" -L "$SRC/example/secrets.zip" 2>&1 || true)"
  CLI_OUT_ZIP64="$("$CLI_BIN" -L "$SRC/tests/bkcrack/data/zip64.zip" 2>&1 || true)"
  CLI_OUT_ZIP64_ZC="$("$CLI_BIN" -L "$SRC/tests/bkcrack/data/zip64-zipcrypto.zip" 2>&1 || true)"
fi

check_kat() {
  local desc="$1" haystack="$2" expected_line="$3"
  total_all=$((total_all + 1))
  if printf '%s\n' "$haystack" | grep -qxF "$expected_line"; then
    passed_all=$((passed_all + 1))
  else
    echo "ORACLE FAIL: $desc -- expected exact line not found: $expected_line" >&2
    failed_all=$((failed_all + 1))
  fi
}

# `bkcrack --version` on this exact commit (CMakeLists.txt: VERSION 1.8.1 / bkcrack_VERSION_DATE
# "2025-10-25"). If upstream bumps the version, this probe intentionally fails loudly (a sync
# re-verification issue) rather than silently degrading into a no-op check.
check_kat "bkcrack --version" "$CLI_OUT_VERSION" "bkcrack 1.8.1 - 2025-10-25"

# `bkcrack -L example/secrets.zip` -- real-world archive (ZipCrypto + Deflate/Store), the same
# fixture upstream's own ctest cli.attack/cli.list cases use. Only printed after the central
# directory has been walked and both entries decoded.
check_kat "bkcrack -L example/secrets.zip (entry 0)" "$CLI_OUT_SECRETS" \
  "    0 ZipCrypto  Deflate     7ca9f10a        54799        54700 advice.jpg"
check_kat "bkcrack -L example/secrets.zip (entry 1)" "$CLI_OUT_SECRETS" \
  "    1 ZipCrypto  Store       a99f1d0d         1265         1277 spiral.svg"

# `bkcrack -L tests/bkcrack/data/zip64.zip` -- exercises the ZIP64 extra-field decode path
# (ExtraField::Zip64) specifically, distinct from the plain-header path above.
check_kat "bkcrack -L zip64.zip (entry 0)" "$CLI_OUT_ZIP64" \
  "    0 None       Store       1ca08acd          208          208 store.txt"
check_kat "bkcrack -L zip64.zip (entry 1)" "$CLI_OUT_ZIP64" \
  "    1 None       Deflate     45e207a8          260           71 deflate.txt"

# `bkcrack -L tests/bkcrack/data/zip64-zipcrypto.zip` -- ZIP64 extra field AND traditional
# encryption flag decode together.
check_kat "bkcrack -L zip64-zipcrypto.zip (entry 0)" "$CLI_OUT_ZIP64_ZC" \
  "    0 ZipCrypto  Store       1ca08acd          208          220 store.txt"

echo "=== totals: $total_all cases, $passed_all passed, $failed_all failed ==="
emit_ctrf "bkcrack-testrunner+cli-kat" "$passed_all" "$failed_all"
