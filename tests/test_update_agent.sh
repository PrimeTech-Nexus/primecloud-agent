#!/usr/bin/env bash
# ==============================================================================
# Automated Test Suite for scripts/update-agent.sh
# Validates fail-closed semantics, cryptographic checksum verification,
# archive security, atomic swap, systemd verification, rollback, and locking.
# ==============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
UPDATER="${ROOT_DIR}/scripts/update-agent.sh"

if [[ ! -f "$UPDATER" ]]; then
    echo "ERROR: Updater script not found at $UPDATER" >&2
    exit 1
fi

TEST_TMP="$(mktemp -d -t primecloud-updater-test.XXXXXX)"
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

# Helper to create a mock agent binary that outputs valid --version
create_mock_agent_binary() {
    local target_path="$1"
    local version="$2"
    local commit="$3"

    cat << EOF > "$target_path"
#!/usr/bin/env bash
if [[ "\$*" == *"--version"* || "\$*" == *"-v"* ]]; then
    echo "primecloud-agent ${version} (commit: ${commit})"
    exit 0
fi
echo "Mock agent running..."
exit 0
EOF
    chmod 0755 "$target_path"
}

# Helper to create a release tarball
create_release_tarball() {
    local tarball_path="$1"
    local version="$2"
    local commit="$3"
    local tmp_build="$(mktemp -d -t agent-build.XXXXXX)"

    create_mock_agent_binary "${tmp_build}/primecloud-agent" "$version" "$commit"
    tar -czf "$tarball_path" -C "$tmp_build" primecloud-agent
    rm -rf "$tmp_build"
}

# Helper to create a mock curl that copies local tarball
create_mock_curl() {
    local mock_curl_path="$1"
    local source_tarball="$2"

    cat << EOF > "$mock_curl_path"
#!/usr/bin/env bash
set -eu
output_file=""
while [[ \$# -gt 0 ]]; do
    case "\$1" in
        -o)
            output_file="\$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

if [[ -n "\$output_file" ]]; then
    cp -f "${source_tarball}" "\$output_file"
    exit 0
fi
echo "Mock curl: No output file specified" >&2
exit 1
EOF
    chmod 0755 "$mock_curl_path"
}

# Helper to create a mock systemctl
create_mock_systemctl() {
    local mock_systemctl_path="$1"
    local restart_behavior="${2:-success}" # success | fail_first | always_fail
    local health_state="${3:-active}"      # active | failed | inactive
    local state_dir="${4:-${TEST_TMP}/systemctl_state}"
    mkdir -p "$state_dir"

    cat << EOF > "$mock_systemctl_path"
#!/usr/bin/env bash
state_dir="${state_dir}"
restart_behavior="${restart_behavior}"
health_state="${health_state}"

action="\$1"
shift || true
service="\$*"

case "\$action" in
    restart)
        count=\$(cat "\${state_dir}/restarts" 2>/dev/null || echo "0")
        count=\$((count + 1))
        echo "\$count" > "\${state_dir}/restarts"

        if [[ "\$restart_behavior" == "always_fail" ]]; then
            echo "Mock systemctl: restart failed" >&2
            exit 1
        elif [[ "\$restart_behavior" == "fail_first" && \$count -eq 1 ]]; then
            echo "Mock systemctl: first restart failed" >&2
            exit 1
        fi
        exit 0
        ;;
    is-active)
        restarts=\$(cat "\${state_dir}/restarts" 2>/dev/null || echo "0")
        rollback_marker=\$(cat "\${state_dir}/rollback_healthy" 2>/dev/null || echo "false")
        if [[ "\$rollback_marker" == "true" ]]; then
            echo "active"
            exit 0
        fi
        echo "\$health_state"
        if [[ "\$health_state" == "active" ]]; then
            exit 0
        else
            exit 1
        fi
        ;;
    show)
        # Handle show -p SubState --value or show -p MainPID --value
        prop=""
        while [[ \$# -gt 0 ]]; do
            case "\$1" in
                -p)
                    prop="\$2"
                    shift 2
                    ;;
                *)
                    shift
                    ;;
            esac
        done
        if [[ "\$prop" == "SubState" ]]; then
            if [[ "\$health_state" == "active" ]]; then
                echo "running"
            else
                echo "failed"
            fi
        elif [[ "\$prop" == "MainPID" ]]; then
            echo "1"
        fi
        exit 0
        ;;
    *)
        exit 0
        ;;
esac
EOF
    chmod 0755 "$mock_systemctl_path"
}

echo "=============================================================================="
echo "RUNNING UPDATE-AGENT.SH AUTOMATED TEST SUITE"
echo "=============================================================================="

# Test 1: Missing arguments
echo "Test 1: Missing arguments validation"
set +e
output=$(bash "$UPDATER" 2>&1)
code=$?
set -e
assert_eq 2 "$code" "Missing args returns exit code 2"
assert_contains "$output" "ERROR: Release tag is required." "Error message notes missing tag"

# Test 2: Invalid tag formats
echo "Test 2: Invalid tag formats"
set +e
output=$(bash "$UPDATER" 0.4.0 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" 2>&1)
code=$?
set -e
assert_eq 2 "$code" "Missing 'v' prefix in tag returns exit code 2"
assert_contains "$output" "Invalid release tag format" "Error indicates invalid tag format"

set +e
output=$(bash "$UPDATER" "v0.4.0/../../evil" "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" 2>&1)
code=$?
set -e
assert_eq 2 "$code" "Path traversal in tag returns exit code 2"

# Test 3: Invalid checksum format
echo "Test 3: Invalid checksum format"
set +e
output=$(bash "$UPDATER" v0.4.0 "invalid-checksum" 2>&1)
code=$?
set -e
assert_eq 2 "$code" "Non-hex checksum returns exit code 2"
assert_contains "$output" "Invalid SHA-256 checksum format" "Error notes checksum format issue"

# Test 4: Invalid repository format
echo "Test 4: Invalid repository format"
set +e
output=$(bash "$UPDATER" --repo "https://evil.com/repo" v0.4.0 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" 2>&1)
code=$?
set -e
assert_eq 2 "$code" "Malformed repo URL returns exit code 2"

# Test 5: Help flag
echo "Test 5: Help flag"
set +e
output=$(bash "$UPDATER" --help 2>&1)
code=$?
set -e
assert_eq 0 "$code" "--help returns exit code 0"
assert_contains "$output" "Usage: update-agent.sh" "Help message displays usage"

# Test 6: Checksum mismatch fail-closed
echo "Test 6: Checksum mismatch fail-closed"
T6_DIR="${TEST_TMP}/t6"
mkdir -p "$T6_DIR"
TARBALL_T6="${T6_DIR}/asset.tar.gz"
create_release_tarball "$TARBALL_T6" "v0.4.0" "deadbeef1234"
MOCK_CURL_T6="${T6_DIR}/mock_curl"
create_mock_curl "$MOCK_CURL_T6" "$TARBALL_T6"

WRONG_CHECKSUM="1111111111111111111111111111111111111111111111111111111111111111"
set +e
output=$(CURL_CMD="$MOCK_CURL_T6" \
    PRIMECLOUD_AGENT_BIN="${T6_DIR}/primecloud-agent" \
    PRIMECLOUD_UPDATE_LOCK="${T6_DIR}/lock" \
    PRIMECLOUD_TARGET_ARCH="amd64" \
    bash "$UPDATER" --dry-run v0.4.0 "$WRONG_CHECKSUM" 2>&1)
code=$?
set -e
assert_eq 5 "$code" "Checksum mismatch returns exit code 5"
assert_contains "$output" "Cryptographic SHA-256 checksum mismatch" "Error reports checksum mismatch"

# Test 7: Malicious archive traversal
echo "Test 7: Malicious archive traversal detection"
T7_DIR="${TEST_TMP}/t7"
mkdir -p "$T7_DIR"
EVIL_TARBALL_T7="${T7_DIR}/evil.tar.gz"
BUILD_T7="${T7_DIR}/build"
mkdir -p "$BUILD_T7"
echo "evil" > "${BUILD_T7}/evil.txt"
# Create archive with path traversal entry
(cd "$BUILD_T7" && tar -czf "$EVIL_TARBALL_T7" evil.txt)
# Rename entry inside tar or construct traversal
# Modern tar forbids creating ../, so create tar with unexpected entry 'evil.txt'
EVIL_SHA=$(sha256sum "$EVIL_TARBALL_T7" | awk '{print $1}')
MOCK_CURL_T7="${T7_DIR}/mock_curl"
create_mock_curl "$MOCK_CURL_T7" "$EVIL_TARBALL_T7"

set +e
output=$(CURL_CMD="$MOCK_CURL_T7" \
    PRIMECLOUD_AGENT_BIN="${T7_DIR}/primecloud-agent" \
    PRIMECLOUD_UPDATE_LOCK="${T7_DIR}/lock" \
    PRIMECLOUD_TARGET_ARCH="amd64" \
    bash "$UPDATER" --dry-run v0.4.0 "$EVIL_SHA" 2>&1)
code=$?
set -e
assert_eq 6 "$code" "Unexpected archive contents returns exit code 6"
assert_contains "$output" "Unexpected archive content" "Error reports unexpected archive content"

# Test 8: Dry-run mode execution
echo "Test 8: Dry-run mode execution"
T8_DIR="${TEST_TMP}/t8"
mkdir -p "$T8_DIR"
TARBALL_T8="${T8_DIR}/asset.tar.gz"
create_release_tarball "$TARBALL_T8" "v0.4.0" "feedbeef5678"
T8_SHA=$(sha256sum "$TARBALL_T8" | awk '{print $1}')
MOCK_CURL_T8="${T8_DIR}/mock_curl"
create_mock_curl "$MOCK_CURL_T8" "$TARBALL_T8"
BIN_T8="${T8_DIR}/primecloud-agent"

set +e
output=$(CURL_CMD="$MOCK_CURL_T8" \
    PRIMECLOUD_AGENT_BIN="$BIN_T8" \
    PRIMECLOUD_UPDATE_LOCK="${T8_DIR}/lock" \
    PRIMECLOUD_TARGET_ARCH="amd64" \
    bash "$UPDATER" --dry-run v0.4.0 "$T8_SHA" 2>&1)
code=$?
set -e
assert_eq 0 "$code" "Dry-run returns exit code 0"
assert_contains "$output" "[DRY-RUN] Simulation successful" "Dry-run confirms simulation"
if [[ ! -f "$BIN_T8" ]]; then
    echo "  [PASS] Dry-run did not create or modify target binary"
    PASSED_COUNT=$((PASSED_COUNT + 1))
else
    echo "  [FAIL] Dry-run unexpectedly created target binary" >&2
    FAILED_COUNT=$((FAILED_COUNT + 1))
fi

# Test 9: Lock contention
echo "Test 9: Lock contention"
T9_DIR="${TEST_TMP}/t9"
mkdir -p "$T9_DIR"
LOCK_T9="${T9_DIR}/update.lock"
TARBALL_T9="${T9_DIR}/asset.tar.gz"
create_release_tarball "$TARBALL_T9" "v0.4.0" "abcd1234"
T9_SHA=$(sha256sum "$TARBALL_T9" | awk '{print $1}')
MOCK_CURL_T9="${T9_DIR}/mock_curl"
create_mock_curl "$MOCK_CURL_T9" "$TARBALL_T9"

# Acquire lock before running update
if command -v flock >/dev/null 2>&1; then
    (
        exec 200>"$LOCK_T9"
        flock -x 200
        sleep 3
    ) &
    BG_LOCK_PID=$!
    sleep 0.5
else
    mkdir "${LOCK_T9}.dir"
    BG_LOCK_PID=""
fi

set +e
output=$(CURL_CMD="$MOCK_CURL_T9" \
    PRIMECLOUD_AGENT_BIN="${T9_DIR}/primecloud-agent" \
    PRIMECLOUD_UPDATE_LOCK="$LOCK_T9" \
    PRIMECLOUD_TARGET_ARCH="amd64" \
    bash "$UPDATER" --dry-run v0.4.0 "$T9_SHA" 2>&1)
code=$?
set -e
if [[ -n "$BG_LOCK_PID" ]]; then
    kill -9 $BG_LOCK_PID 2>/dev/null || true
    wait $BG_LOCK_PID 2>/dev/null || true
else
    rmdir "${LOCK_T9}.dir" 2>/dev/null || true
fi

assert_eq 3 "$code" "Lock contention returns exit code 3"
assert_contains "$output" "Another update is currently in progress" "Error reports lock contention"

# Test 10: Successful host update
echo "Test 10: Successful host update"
T10_DIR="${TEST_TMP}/t10"
mkdir -p "$T10_DIR"
BIN_T10="${T10_DIR}/primecloud-agent"
create_mock_agent_binary "$BIN_T10" "v0.3.0" "oldcommit1111"

TARBALL_T10="${T10_DIR}/asset.tar.gz"
create_release_tarball "$TARBALL_T10" "v0.4.0" "newcommit2222"
T10_SHA=$(sha256sum "$TARBALL_T10" | awk '{print $1}')
MOCK_CURL_T10="${T10_DIR}/mock_curl"
create_mock_curl "$MOCK_CURL_T10" "$TARBALL_T10"
MOCK_SYSTEMCTL_T10="${T10_DIR}/mock_systemctl"
create_mock_systemctl "$MOCK_SYSTEMCTL_T10" "success" "active" "${T10_DIR}/sys_state"

set +e
output=$(CURL_CMD="$MOCK_CURL_T10" \
    SYSTEMCTL_CMD="$MOCK_SYSTEMCTL_T10" \
    PRIMECLOUD_AGENT_BIN="$BIN_T10" \
    PRIMECLOUD_UPDATE_LOCK="${T10_DIR}/lock" \
    PRIMECLOUD_TARGET_ARCH="amd64" \
    PRIMECLOUD_HEALTH_TIMEOUT=5 \
    PRIMECLOUD_HEALTH_INTERVAL=1 \
    bash "$UPDATER" v0.4.0 "$T10_SHA" 2>&1)
code=$?
set -e
assert_eq 0 "$code" "Successful update returns exit code 0"
assert_contains "$output" "PrimeCloud Agent successfully updated to v0.4.0" "Success message logged"

# Verify installed binary version
INSTALLED_VER=$("$BIN_T10" --version)
assert_contains "$INSTALLED_VER" "v0.4.0" "Installed binary is now v0.4.0"

# Verify backup binary exists and has old version
if [[ -f "${BIN_T10}.bak" ]]; then
    BACKUP_VER=$("${BIN_T10}.bak" --version)
    assert_contains "$BACKUP_VER" "v0.3.0" "Backup binary was retained with v0.3.0"
else
    echo "  [FAIL] Backup binary ${BIN_T10}.bak was not found" >&2
    FAILED_COUNT=$((FAILED_COUNT + 1))
fi

# Test 11: Service restart failure triggers rollback
echo "Test 11: Service restart failure triggers rollback"
T11_DIR="${TEST_TMP}/t11"
mkdir -p "$T11_DIR"
BIN_T11="${T11_DIR}/primecloud-agent"
create_mock_agent_binary "$BIN_T11" "v0.3.0" "oldcommit1111"

TARBALL_T11="${T11_DIR}/asset.tar.gz"
create_release_tarball "$TARBALL_T11" "v0.4.0" "newcommit2222"
T11_SHA=$(sha256sum "$TARBALL_T11" | awk '{print $1}')
MOCK_CURL_T11="${T11_DIR}/mock_curl"
create_mock_curl "$MOCK_CURL_T11" "$TARBALL_T11"
MOCK_SYSTEMCTL_T11="${T11_DIR}/mock_systemctl"
# Fails first restart (new version), succeeds on rollback restart
create_mock_systemctl "$MOCK_SYSTEMCTL_T11" "fail_first" "active" "${T11_DIR}/sys_state"

set +e
output=$(CURL_CMD="$MOCK_CURL_T11" \
    SYSTEMCTL_CMD="$MOCK_SYSTEMCTL_T11" \
    PRIMECLOUD_AGENT_BIN="$BIN_T11" \
    PRIMECLOUD_UPDATE_LOCK="${T11_DIR}/lock" \
    PRIMECLOUD_TARGET_ARCH="amd64" \
    PRIMECLOUD_HEALTH_TIMEOUT=5 \
    PRIMECLOUD_HEALTH_INTERVAL=1 \
    bash "$UPDATER" v0.4.0 "$T11_SHA" 2>&1)
code=$?
set -e
assert_eq 1 "$code" "Restart failure with successful rollback returns exit code 1"
assert_contains "$output" "Service successfully rolled back to previous version and is active" "Rollback success reported"

# Verify restored binary is old version
RESTORED_VER=$("$BIN_T11" --version)
assert_contains "$RESTORED_VER" "v0.3.0" "Installed binary restored to v0.3.0"

# Test 12: Health check failure triggers rollback
echo "Test 12: Health check failure triggers rollback"
T12_DIR="${TEST_TMP}/t12"
mkdir -p "$T12_DIR"
BIN_T12="${T12_DIR}/primecloud-agent"
create_mock_agent_binary "$BIN_T12" "v0.3.0" "oldcommit1111"

TARBALL_T12="${T12_DIR}/asset.tar.gz"
create_release_tarball "$TARBALL_T12" "v0.4.0" "newcommit2222"
T12_SHA=$(sha256sum "$TARBALL_T12" | awk '{print $1}')
MOCK_CURL_T12="${T12_DIR}/mock_curl"
create_mock_curl "$MOCK_CURL_T12" "$TARBALL_T12"
MOCK_SYSTEMCTL_T12="${T12_DIR}/mock_systemctl"
# Mock systemctl restart succeeds, but is-active returns 'failed' initially.
# On rollback, state dir marks rollback healthy.
STATE_T12="${T12_DIR}/sys_state"
create_mock_systemctl "$MOCK_SYSTEMCTL_T12" "success" "failed" "$STATE_T12"

# Wrap mock systemctl to set rollback_healthy=true on 2nd restart
cat << EOF > "${T12_DIR}/mock_systemctl_wrapper"
#!/usr/bin/env bash
state_dir="${STATE_T12}"
if [[ "\$1" == "restart" ]]; then
    count=\$(cat "\${state_dir}/restarts" 2>/dev/null || echo "0")
    if [[ \$count -ge 1 ]]; then
        echo "true" > "\${state_dir}/rollback_healthy"
    fi
fi
exec "${MOCK_SYSTEMCTL_T12}" "\$@"
EOF
chmod 0755 "${T12_DIR}/mock_systemctl_wrapper"

set +e
output=$(CURL_CMD="$MOCK_CURL_T12" \
    SYSTEMCTL_CMD="${T12_DIR}/mock_systemctl_wrapper" \
    PRIMECLOUD_AGENT_BIN="$BIN_T12" \
    PRIMECLOUD_UPDATE_LOCK="${T12_DIR}/lock" \
    PRIMECLOUD_TARGET_ARCH="amd64" \
    PRIMECLOUD_HEALTH_TIMEOUT=3 \
    PRIMECLOUD_HEALTH_INTERVAL=1 \
    bash "$UPDATER" v0.4.0 "$T12_SHA" 2>&1)
code=$?
set -e
assert_eq 1 "$code" "Health check failure with successful rollback returns exit code 1"
assert_contains "$output" "Service successfully rolled back" "Rollback reported"
RESTORED_VER_T12=$("$BIN_T12" --version)
assert_contains "$RESTORED_VER_T12" "v0.3.0" "Binary restored to v0.3.0 after health check failure"

# Test 13: Critical rollback failure
echo "Test 13: Critical rollback failure"
T13_DIR="${TEST_TMP}/t13"
mkdir -p "$T13_DIR"
BIN_T13="${T13_DIR}/primecloud-agent"
create_mock_agent_binary "$BIN_T13" "v0.3.0" "oldcommit1111"

TARBALL_T13="${T13_DIR}/asset.tar.gz"
create_release_tarball "$TARBALL_T13" "v0.4.0" "newcommit2222"
T13_SHA=$(sha256sum "$TARBALL_T13" | awk '{print $1}')
MOCK_CURL_T13="${T13_DIR}/mock_curl"
create_mock_curl "$MOCK_CURL_T13" "$TARBALL_T13"
MOCK_SYSTEMCTL_T13="${T13_DIR}/mock_systemctl"
create_mock_systemctl "$MOCK_SYSTEMCTL_T13" "always_fail" "failed" "${T13_DIR}/sys_state"

set +e
output=$(CURL_CMD="$MOCK_CURL_T13" \
    SYSTEMCTL_CMD="$MOCK_SYSTEMCTL_T13" \
    PRIMECLOUD_AGENT_BIN="$BIN_T13" \
    PRIMECLOUD_UPDATE_LOCK="${T13_DIR}/lock" \
    PRIMECLOUD_TARGET_ARCH="amd64" \
    PRIMECLOUD_HEALTH_TIMEOUT=2 \
    PRIMECLOUD_HEALTH_INTERVAL=1 \
    bash "$UPDATER" v0.4.0 "$T13_SHA" 2>&1)
code=$?
set -e
assert_eq 8 "$code" "Critical rollback failure returns exit code 8"
assert_contains "$output" "[CRITICAL] Rollback service restart failed" "Critical failure logged"

# Test 14: Download failure fail-closed
echo "Test 14: Download failure fail-closed"
T14_DIR="${TEST_TMP}/t14"
mkdir -p "$T14_DIR"
MOCK_CURL_T14="${T14_DIR}/mock_curl_fail"
cat << 'EOF' > "$MOCK_CURL_T14"
#!/usr/bin/env bash
echo "curl: (22) The requested URL returned error: 404 Not Found" >&2
exit 22
EOF
chmod 0755 "$MOCK_CURL_T14"

set +e
output=$(CURL_CMD="$MOCK_CURL_T14" \
    PRIMECLOUD_AGENT_BIN="${T14_DIR}/primecloud-agent" \
    PRIMECLOUD_UPDATE_LOCK="${T14_DIR}/lock" \
    PRIMECLOUD_TARGET_ARCH="amd64" \
    bash "$UPDATER" --dry-run v0.4.0 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" 2>&1)
code=$?
set -e
assert_eq 4 "$code" "Download failure returns exit code 4"
assert_contains "$output" "Failed to download release asset" "Error reports download failure"

# Test 15: Version mismatch rejection
echo "Test 15: Version mismatch rejection"
T15_DIR="${TEST_TMP}/t15"
mkdir -p "$T15_DIR"
TARBALL_T15="${T15_DIR}/asset.tar.gz"
# Packaged binary reports v0.3.0, but caller requests v0.4.0
create_release_tarball "$TARBALL_T15" "v0.3.0" "oldcommit3333"
T15_SHA=$(sha256sum "$TARBALL_T15" | awk '{print $1}')
MOCK_CURL_T15="${T15_DIR}/mock_curl"
create_mock_curl "$MOCK_CURL_T15" "$TARBALL_T15"

set +e
output=$(CURL_CMD="$MOCK_CURL_T15" \
    PRIMECLOUD_AGENT_BIN="${T15_DIR}/primecloud-agent" \
    PRIMECLOUD_UPDATE_LOCK="${T15_DIR}/lock" \
    PRIMECLOUD_TARGET_ARCH="amd64" \
    bash "$UPDATER" --dry-run v0.4.0 "$T15_SHA" 2>&1)
code=$?
set -e
assert_eq 7 "$code" "Version mismatch returns exit code 7"
assert_contains "$output" "Version mismatch! Extracted binary reported" "Error reports version mismatch"

# Test 16: Duplicate archive entries rejection
echo "Test 16: Duplicate archive entries rejection"
T16_DIR="${TEST_TMP}/t16"
mkdir -p "$T16_DIR"
BUILD_T16="${T16_DIR}/build"
mkdir -p "$BUILD_T16"
create_mock_agent_binary "${BUILD_T16}/primecloud-agent" "v0.4.0" "hash1234"
# Create tar with duplicate entry
(cd "$BUILD_T16" && tar -cf "${T16_DIR}/dup.tar" primecloud-agent && tar -rf "${T16_DIR}/dup.tar" primecloud-agent && gzip -c "${T16_DIR}/dup.tar" > "${T16_DIR}/dup.tar.gz")
T16_SHA=$(sha256sum "${T16_DIR}/dup.tar.gz" | awk '{print $1}')
MOCK_CURL_T16="${T16_DIR}/mock_curl"
create_mock_curl "$MOCK_CURL_T16" "${T16_DIR}/dup.tar.gz"

set +e
output=$(CURL_CMD="$MOCK_CURL_T16" \
    PRIMECLOUD_AGENT_BIN="${T16_DIR}/primecloud-agent" \
    PRIMECLOUD_UPDATE_LOCK="${T16_DIR}/lock" \
    PRIMECLOUD_TARGET_ARCH="amd64" \
    bash "$UPDATER" --dry-run v0.4.0 "$T16_SHA" 2>&1)
code=$?
set -e
assert_eq 6 "$code" "Duplicate entries in archive returns exit code 6"
assert_contains "$output" "Expected exactly 1 file" "Error reports duplicate entry rejection"

# Test 17: Backup preservation after rollback
echo "Test 17: Backup preservation verified after rollback"
T17_DIR="${TEST_TMP}/t17"
mkdir -p "$T17_DIR"
BIN_T17="${T17_DIR}/primecloud-agent"
create_mock_agent_binary "$BIN_T17" "v0.3.0" "oldcommit1111"
TARBALL_T17="${T17_DIR}/asset.tar.gz"
create_release_tarball "$TARBALL_T17" "v0.4.0" "newcommit2222"
T17_SHA=$(sha256sum "$TARBALL_T17" | awk '{print $1}')
MOCK_CURL_T17="${T17_DIR}/mock_curl"
create_mock_curl "$MOCK_CURL_T17" "$TARBALL_T17"
MOCK_SYSTEMCTL_T17="${T17_DIR}/mock_systemctl"
create_mock_systemctl "$MOCK_SYSTEMCTL_T17" "fail_first" "active" "${T17_DIR}/sys_state"

set +e
output=$(CURL_CMD="$MOCK_CURL_T17" \
    SYSTEMCTL_CMD="$MOCK_SYSTEMCTL_T17" \
    PRIMECLOUD_AGENT_BIN="$BIN_T17" \
    PRIMECLOUD_UPDATE_LOCK="${T17_DIR}/lock" \
    PRIMECLOUD_TARGET_ARCH="amd64" \
    PRIMECLOUD_HEALTH_TIMEOUT=3 \
    PRIMECLOUD_HEALTH_INTERVAL=1 \
    bash "$UPDATER" v0.4.0 "$T17_SHA" 2>&1)
code=$?
set -e
assert_eq 1 "$code" "Rollback returns exit code 1"
if [[ -f "${BIN_T17}.bak" ]]; then
    echo "  [PASS] Backup file was retained after rollback"
    PASSED_COUNT=$((PASSED_COUNT + 1))
else
    echo "  [FAIL] Backup file ${BIN_T17}.bak was destroyed by rollback" >&2
    FAILED_COUNT=$((FAILED_COUNT + 1))
fi

echo "=============================================================================="
echo "TEST RESULTS SUMMARY: ${PASSED_COUNT} passed, ${FAILED_COUNT} failed"
echo "=============================================================================="

if [[ $FAILED_COUNT -ne 0 ]]; then
    exit 1
fi
exit 0
