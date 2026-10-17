#!/usr/bin/env bash
# ==============================================================================
# Automated Test Suite for scripts/agent_deploy_wrapper.sh
# Validates least-privilege security invariants, parameter bounds,
# metacharacter rejection, and updater script delegation.
# ==============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
WRAPPER="${ROOT_DIR}/scripts/agent_deploy_wrapper.sh"

if [[ ! -f "$WRAPPER" ]]; then
    echo "ERROR: Wrapper script not found at $WRAPPER" >&2
    exit 1
fi

TEST_TMP="$(mktemp -d -t primecloud-wrapper-test.XXXXXX)"
trap 'rm -rf "${TEST_TMP}"' EXIT

PASSED_COUNT=0
FAILED_COUNT=0

assert_eq() {
    local expected="$1"
    local actual="$2"
    local message="$3"
    if [[ "$expected" != "$actual" ]]; then
        echo "  [FAIL] $message: expected '$expected', got '$actual'" >&2
        FAILED_COUNT=$((FAILED_COUNT + 1))
        return 1
    else
        echo "  [PASS] $message"
        PASSED_COUNT=$((PASSED_COUNT + 1))
        return 0
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local message="$3"
    if [[ "$haystack" != *"$needle"* ]]; then
        echo "  [FAIL] $message: output did not contain '$needle'" >&2
        echo "  Output was: $haystack" >&2
        FAILED_COUNT=$((FAILED_COUNT + 1))
        return 1
    else
        echo "  [PASS] $message"
        PASSED_COUNT=$((PASSED_COUNT + 1))
        return 0
    fi
}

echo "=============================================================================="
echo "RUNNING AGENT_DEPLOY_WRAPPER.SH AUTOMATED TEST SUITE"
echo "=============================================================================="

# Test 1: Missing arguments
echo "Test 1: Missing arguments validation"
set +e
output=$(bash "$WRAPPER" 2>&1)
code=$?
set -e
assert_eq 1 "$code" "Zero arguments returns exit code 1"
assert_contains "$output" "Both release tag and SHA-256 checksum are required" "Error notes missing args"

set +e
output=$(bash "$WRAPPER" "v0.4.0" 2>&1)
code=$?
set -e
assert_eq 1 "$code" "One argument returns exit code 1"
assert_contains "$output" "Both release tag and SHA-256 checksum are required" "Error notes missing checksum"

# Test 2: Too many arguments
echo "Test 2: Too many arguments rejection"
set +e
output=$(bash "$WRAPPER" "v0.4.0" "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" "extra_arg" 2>&1)
code=$?
set -e
assert_eq 1 "$code" "Three arguments returns exit code 1"
assert_contains "$output" "Too many arguments provided" "Error notes too many args"

# Test 3: Invalid tag format
echo "Test 3: Invalid tag format rejection"
set +e
output=$(bash "$WRAPPER" "0.4.0" "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" 2>&1)
code=$?
set -e
assert_eq 1 "$code" "Missing 'v' prefix returns exit code 1"
assert_contains "$output" "does not follow SemVer release tag format" "Error reports invalid tag format"

set +e
output=$(bash "$WRAPPER" "v0.4.0;rm -rf" "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" 2>&1)
code=$?
set -e
assert_eq 1 "$code" "Metacharacters in tag returns exit code 1"
assert_contains "$output" "Tag contains forbidden characters" "Error reports metacharacter rejection"

# Test 4: Invalid checksum format
echo "Test 4: Invalid checksum format rejection"
set +e
output=$(bash "$WRAPPER" "v0.4.0" "not_a_hex_checksum" 2>&1)
code=$?
set -e
assert_eq 1 "$code" "Non-hex checksum returns exit code 1"
assert_contains "$output" "Checksum contains non-hexadecimal characters" "Error reports non-hex"

set +e
output=$(bash "$WRAPPER" "v0.4.0" "0123456789abcdef" 2>&1)
code=$?
set -e
assert_eq 1 "$code" "Short checksum returns exit code 1"
assert_contains "$output" "Checksum must be exactly 64 hexadecimal characters" "Error reports length issue"

# Test 5: Missing target updater script
echo "Test 5: Missing target updater script handling"
NONEXISTENT_DIR="${TEST_TMP}/nonexistent"
set +e
output=$(PRIMECLOUD_ENV="test" PRIMECLOUD_BOOTSTRAP_DIR="$NONEXISTENT_DIR" bash "$WRAPPER" "v0.4.0" "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" 2>&1)
code=$?
set -e
assert_eq 1 "$code" "Missing target updater script returns exit code 1"
assert_contains "$output" "Target updater script not found" "Error notes missing updater"

# Test 6: Successful delegation to updater script
echo "Test 6: Successful delegation with valid arguments"
MOCK_BOOTSTRAP="${TEST_TMP}/bootstrap"
mkdir -p "$MOCK_BOOTSTRAP"
cat << 'EOF' > "${MOCK_BOOTSTRAP}/update-agent.sh"
#!/usr/bin/env bash
echo "MOCK_UPDATER_INVOKED: args='$*'"
exit 0
EOF
chmod 0755 "${MOCK_BOOTSTRAP}/update-agent.sh"

VALID_TAG="v0.4.0"
VALID_SHA="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

set +e
output=$(PRIMECLOUD_ENV="test" PRIMECLOUD_BOOTSTRAP_DIR="$MOCK_BOOTSTRAP" bash "$WRAPPER" "$VALID_TAG" "$VALID_SHA" 2>&1)
code=$?
set -e
assert_eq 0 "$code" "Valid delegation returns exit code 0"
assert_contains "$output" "MOCK_UPDATER_INVOKED: args='v0.4.0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'" "Delegates exact tag and checksum"

# Test 7: Dry-run delegation
echo "Test 7: Dry-run delegation"
set +e
output=$(PRIMECLOUD_ENV="test" PRIMECLOUD_BOOTSTRAP_DIR="$MOCK_BOOTSTRAP" bash "$WRAPPER" --dry-run "$VALID_TAG" "$VALID_SHA" 2>&1)
code=$?
set -e
assert_eq 0 "$code" "Dry-run delegation returns exit code 0"
assert_contains "$output" "MOCK_UPDATER_INVOKED: args='--dry-run v0.4.0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'" "Passes --dry-run flag to updater"

# Test 8: Pre-staged candidate archive auto-detection and passing to updater
echo "Test 8: Pre-staged candidate archive auto-detection and passing to updater"
T8_ARCHIVE="/tmp/primecloud-agent-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.tar.gz"
echo "mock tarball content" > "$T8_ARCHIVE"
T8_REAL_SHA="$(sha256sum "$T8_ARCHIVE" | awk '{print $1}')"
T8_NAMED_ARCHIVE="/tmp/primecloud-agent-${T8_REAL_SHA}.tar.gz"
mv "$T8_ARCHIVE" "$T8_NAMED_ARCHIVE"

set +e
output=$(PRIMECLOUD_ENV="test" PRIMECLOUD_BOOTSTRAP_DIR="$MOCK_BOOTSTRAP" bash "$WRAPPER" "$VALID_TAG" "$T8_REAL_SHA" 2>&1)
code=$?
set -e
rm -f "$T8_NAMED_ARCHIVE"
assert_eq 0 "$code" "Staged archive detection returns exit code 0"
assert_contains "$output" "Validated candidate staged archive: ${T8_NAMED_ARCHIVE}" "Logs candidate validation"
assert_contains "$output" "MOCK_UPDATER_INVOKED: args='--staged-archive ${T8_NAMED_ARCHIVE} v0.4.0 ${T8_REAL_SHA}'" "Passes --staged-archive to updater"

# Test 9: Pre-staged candidate archive SHA-256 mismatch rejection
echo "Test 9: Pre-staged candidate archive SHA-256 mismatch rejection"
T9_ARCHIVE="/tmp/primecloud-agent-${VALID_SHA}.tar.gz"
echo "corrupted content with wrong sha" > "$T9_ARCHIVE"

set +e
output=$(PRIMECLOUD_ENV="test" PRIMECLOUD_BOOTSTRAP_DIR="$MOCK_BOOTSTRAP" bash "$WRAPPER" "$VALID_TAG" "$VALID_SHA" 2>&1)
code=$?
set -e
rm -f "$T9_ARCHIVE"
assert_eq 1 "$code" "Corrupted candidate archive returns exit code 1"
assert_contains "$output" "Candidate archive SHA-256 does not match expected checksum" "Reports checksum mismatch"

# Test 10: Branch deployment tag rejection when pre-staged archive is missing
echo "Test 10: Branch deployment tag rejection when pre-staged archive is missing"
BRANCH_TAG="v0.4.4-main.1234567"
NONEXISTENT_SHA="abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
set +e
output=$(PRIMECLOUD_ENV="test" PRIMECLOUD_BOOTSTRAP_DIR="$MOCK_BOOTSTRAP" bash "$WRAPPER" "$BRANCH_TAG" "$NONEXISTENT_SHA" 2>&1)
code=$?
set -e
assert_eq 1 "$code" "Branch deployment without staged archive returns exit code 1"
assert_contains "$output" "requires a pre-staged candidate archive" "Reports branch deployment requires staged archive"

# Test 11: Explicit --staged-archive argument delegation
echo "Test 11: Explicit --staged-archive argument delegation"
T11_ARCHIVE="${TEST_TMP}/candidate.tar.gz"
echo "custom candidate content" > "$T11_ARCHIVE"
T11_SHA="$(sha256sum "$T11_ARCHIVE" | awk '{print $1}')"

set +e
output=$(PRIMECLOUD_ENV="test" PRIMECLOUD_BOOTSTRAP_DIR="$MOCK_BOOTSTRAP" bash "$WRAPPER" --staged-archive "$T11_ARCHIVE" "$VALID_TAG" "$T11_SHA" 2>&1)
code=$?
set -e
assert_eq 0 "$code" "Explicit --staged-archive flag returns exit code 0"
assert_contains "$output" "MOCK_UPDATER_INVOKED: args='--staged-archive ${T11_ARCHIVE} v0.4.0 ${T11_SHA}'" "Passes explicit archive path"

echo "=============================================================================="
echo "TEST RESULTS SUMMARY: ${PASSED_COUNT} passed, ${FAILED_COUNT} failed"
echo "=============================================================================="

if [[ $FAILED_COUNT -ne 0 ]]; then
    exit 1
fi
exit 0
