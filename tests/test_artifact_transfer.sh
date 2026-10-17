#!/usr/bin/env bash
# ==============================================================================
# Isolated Test Suite for Artifact Transfer Logic in deploy.yml
# Validates host-key pinning, pre-flight capacity check, transfer integrity,
# post-transfer checksum verification, and fail-closed security invariants.
# ==============================================================================
set -euo pipefail
IFS=$'\n\t'

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

TEST_TMP="$(mktemp -d -t primecloud-transfer-test.XXXXXX)"
trap 'rm -rf "${TEST_TMP}"' EXIT

# Helper function simulating the transfer step logic from deploy.yml
execute_transfer_step() {
    local deploy_host="$1"
    local deploy_user="$2"
    local tag="$3"
    local checksum="$4"
    local mock_remote_dir="$5"
    local simulated_avail_kb="$6"
    local corrupt_transfer="${7:-false}"

    local known_hosts_file="${TEST_TMP}/known_hosts"
    local id_deploy_file="${TEST_TMP}/id_deploy"

    # Step logic identical to deploy.yml
    local DEPLOY_HOST_CLEAN="$(printf '%s' "${deploy_host}" | tr -d '\r[:space:]')"
    local DEPLOY_USER_CLEAN="$(printf '%s' "${deploy_user}" | tr -d '\r[:space:]')"
    local TAG_CLEAN="$(printf '%s' "${tag}" | tr -d '\r[:space:]')"
    local CHECKSUM_CLEAN="$(printf '%s' "${checksum}" | tr -d '\r[:space:]' | tr '[:upper:]' '[:lower:]')"

    # 1. Pinned host key verification
    if ! ssh-keygen -F "${DEPLOY_HOST_CLEAN}" -f "${known_hosts_file}" >/dev/null 2>&1; then
        echo "::error::Verified host key entry for target host '${DEPLOY_HOST_CLEAN}' not found in known_hosts!" >&2
        return 1
    fi

    # 2. Pre-flight remote capacity verification
    local AVAIL_KB="${simulated_avail_kb}"
    if [[ -z "${AVAIL_KB}" || "${AVAIL_KB}" -lt 51200 ]]; then
        echo "::error::Target host filesystem (/tmp) has insufficient free space (Available: ${AVAIL_KB:-0} KB, minimum required: 51200 KB). Aborting deployment." >&2
        return 1
    fi

    # 3. Transfer candidate asset
    local staged_remote="${mock_remote_dir}/primecloud-agent-${CHECKSUM_CLEAN}.tar.gz"
    local local_asset="${TEST_TMP}/primecloud-agent-linux-amd64.tar.gz"

    if [[ "${corrupt_transfer}" == "true" ]]; then
        echo "corrupted-payload-data" > "${staged_remote}"
    else
        cp -f "${local_asset}" "${staged_remote}"
    fi
    chmod 0644 "${staged_remote}"

    # 4. Post-transfer remote checksum verification
    local REMOTE_SHA=$(sha256sum "${staged_remote}" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
    if [[ "${REMOTE_SHA}" != "${CHECKSUM_CLEAN}" ]]; then
        echo "::error::Remote candidate asset checksum mismatch! Expected: ${CHECKSUM_CLEAN}, got: ${REMOTE_SHA}" >&2
        rm -f "${staged_remote}"
        return 1
    fi

    echo "Verified remote asset SHA-256 matches build checksum: ${REMOTE_SHA}"
    return 0
}

echo "=============================================================================="
echo "RUNNING ARTIFACT TRANSFER LOCAL TEST SUITE"
echo "=============================================================================="

# Create mock asset and valid checksum
MOCK_ASSET="${TEST_TMP}/primecloud-agent-linux-amd64.tar.gz"
echo "primecloud-binary-archive-mock-content-v0.4.4" > "$MOCK_ASSET"
VALID_SHA=$(sha256sum "$MOCK_ASSET" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')

# Setup known_hosts with valid dummy host key
KNOWN_HOSTS="${TEST_TMP}/known_hosts"
ssh-keygen -q -t ed25519 -N "" -f "${TEST_TMP}/dummy_host_key"
DUMMY_PUB=$(cat "${TEST_TMP}/dummy_host_key.pub")
echo "167.86.73.226 ${DUMMY_PUB}" > "$KNOWN_HOSTS"

REMOTE_TMP="${TEST_TMP}/remote_tmp"
mkdir -p "$REMOTE_TMP"

# Test 1: Successful transfer when capacity is sufficient and host key is verified
echo "Test 1: Successful transfer with sufficient capacity and pinned host"
set +e
output=$(execute_transfer_step "167.86.73.226" "deploy" "v0.4.4-main.1234567" "$VALID_SHA" "$REMOTE_TMP" 1048576 2>&1)
code=$?
set -e
assert_eq 0 "$code" "Transfer succeeds with exit code 0"
assert_contains "$output" "Verified remote asset SHA-256 matches build checksum" "Logs verified remote checksum"
STAGED_FILE="${REMOTE_TMP}/primecloud-agent-${VALID_SHA}.tar.gz"
if [[ -f "$STAGED_FILE" ]]; then
    PASSED_COUNT=$((PASSED_COUNT + 1))
    echo "  [PASS] Staged remote file exists"
else
    FAILED_COUNT=$((FAILED_COUNT + 1))
    echo "  [FAIL] Staged remote file missing" >&2
fi
rm -f "$STAGED_FILE"

# Test 2: Unverified host key fail-closed
echo "Test 2: Rejection of unverified host key"
set +e
output=$(execute_transfer_step "192.168.1.99" "deploy" "v0.4.4-main.1234567" "$VALID_SHA" "$REMOTE_TMP" 1048576 2>&1)
code=$?
set -e
assert_eq 1 "$code" "Unverified host returns exit code 1"
assert_contains "$output" "not found in known_hosts" "Reports unverified host key"

# Test 3: Insufficient capacity (disk full) fail-closed
echo "Test 3: Insufficient capacity rejection (simulated disk full)"
set +e
output=$(execute_transfer_step "167.86.73.226" "deploy" "v0.4.4-main.1234567" "$VALID_SHA" "$REMOTE_TMP" 0 2>&1)
code=$?
set -e
assert_eq 1 "$code" "Disk full rejection returns exit code 1"
assert_contains "$output" "insufficient free space" "Reports insufficient capacity"
assert_contains "$output" "Available: 0 KB" "Reports exact available KB"

# Test 4: Capacity just below 50MB threshold rejected
echo "Test 4: Capacity below threshold (<51200 KB) rejection"
set +e
output=$(execute_transfer_step "167.86.73.226" "deploy" "v0.4.4-main.1234567" "$VALID_SHA" "$REMOTE_TMP" 40960 2>&1)
code=$?
set -e
assert_eq 1 "$code" "Sub-threshold capacity returns exit code 1"
assert_contains "$output" "minimum required: 51200 KB" "Reports threshold requirement"

# Test 5: Post-transfer corruption detection fail-closed
echo "Test 5: Checksum mismatch fail-closed on corrupt transfer"
set +e
output=$(execute_transfer_step "167.86.73.226" "deploy" "v0.4.4-main.1234567" "$VALID_SHA" "$REMOTE_TMP" 1048576 true 2>&1)
code=$?
set -e
assert_eq 1 "$code" "Corrupted transfer returns exit code 1"
assert_contains "$output" "Remote candidate asset checksum mismatch" "Reports checksum mismatch"
if [[ ! -f "$STAGED_FILE" ]]; then
    PASSED_COUNT=$((PASSED_COUNT + 1))
    echo "  [PASS] Corrupted candidate asset was purged"
else
    FAILED_COUNT=$((FAILED_COUNT + 1))
    echo "  [FAIL] Corrupted candidate asset was not cleaned up" >&2
fi

echo "=============================================================================="
echo "TEST RESULTS SUMMARY: ${PASSED_COUNT} passed, ${FAILED_COUNT} failed"
echo "=============================================================================="

if [[ $FAILED_COUNT -ne 0 ]]; then
    exit 1
fi
exit 0
