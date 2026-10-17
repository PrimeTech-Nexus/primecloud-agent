#!/usr/bin/env bash
# ==============================================================================
# PrimeCloud Node Agent Host Update Script
# Component: Host Binary Lifecycle Management
# Target: Linux hosts running primecloud-agent under systemd
# Mode: Fail-closed, atomic replacement, checksum-verified, rollback-capable
# ==============================================================================
set -euo pipefail
IFS=$'\n\t'

# Default configuration
DEFAULT_REPO="PrimeTech-Nexus/primecloud-agent"
REPO="${PRIMECLOUD_AGENT_REPO:-$DEFAULT_REPO}"
BIN_PATH="${PRIMECLOUD_AGENT_BIN:-/usr/local/bin/primecloud-agent}"
SERVICE_NAME="${PRIMECLOUD_AGENT_SERVICE:-primecloud-agent.service}"
LOCK_FILE="${PRIMECLOUD_UPDATE_LOCK:-/run/lock/primecloud-agent-update.lock}"
TIMEOUT_SECONDS="${PRIMECLOUD_HEALTH_TIMEOUT:-30}"
POLL_INTERVAL="${PRIMECLOUD_HEALTH_INTERVAL:-2}"
TARGET_ARCH="${PRIMECLOUD_TARGET_ARCH:-}"
DRY_RUN=false

# Command overrides for testing / environments
CURL_CMD="${CURL_CMD:-curl}"
TAR_CMD="${TAR_CMD:-tar}"
SHA256SUM_CMD="${SHA256SUM_CMD:-sha256sum}"
SYSTEMCTL_CMD="${SYSTEMCTL_CMD:-systemctl}"
JOURNALCTL_CMD="${JOURNALCTL_CMD:-journalctl}"

# Global tracking variables for cleanup and rollback
TMP_DIR=""
STAGE_BIN=""
STAGED_ARCHIVE=""
LOCK_HELD=false
LOCK_FD=200
cleanup() {
    local exit_code=$?
    if [[ -n "${TMP_DIR:-}" && -d "${TMP_DIR:-}" ]]; then
        rm -rf "${TMP_DIR}" 2>/dev/null || true
    fi
    if [[ -n "${STAGE_BIN:-}" && -f "${STAGE_BIN:-}" ]]; then
        rm -f "${STAGE_BIN}" 2>/dev/null || true
    fi
    if [[ -n "${STAGED_ARCHIVE:-}" && -f "${STAGED_ARCHIVE:-}" ]]; then
        rm -f "${STAGED_ARCHIVE}" 2>/dev/null || true
    fi
    if [[ "${LOCK_HELD}" == "true" ]]; then
        if command -v flock >/dev/null 2>&1; then
            flock -u ${LOCK_FD} 2>/dev/null || true
            eval "exec ${LOCK_FD}>&-" 2>/dev/null || true
        fi
        if [[ -n "${LOCK_DIR_PATH:-}" && -d "${LOCK_DIR_PATH:-}" ]]; then
            rmdir "${LOCK_DIR_PATH}" 2>/dev/null || true
        fi
    fi
    exit ${exit_code}
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
    cat << 'EOF'
Usage: update-agent.sh [OPTIONS] <TAG> <SHA256_CHECKSUM>
       update-agent.sh [OPTIONS] --tag <TAG> --checksum <SHA256_CHECKSUM>

Safely updates the PrimeCloud Agent binary on a Linux host managed by systemd.

Arguments:
  <TAG>                     Release tag to install (e.g. v0.4.0)
  <SHA256_CHECKSUM>         Expected SHA-256 hex checksum of the release tarball

Options:
  -t, --tag <tag>           Release tag to install
  -c, --checksum <sha256>   Expected SHA-256 checksum (64 hex characters)
  --repo <owner/repo>       GitHub repository (default: PrimeTech-Nexus/primecloud-agent)
  --bin-path <path>         Path to installed binary (default: /usr/local/bin/primecloud-agent)
  --service <name>          Systemd service name (default: primecloud-agent.service)
  --lock-file <path>        Lockfile path (default: /run/lock/primecloud-agent-update.lock)
  --arch <amd64|arm64>      Target architecture override (default: auto-detected)
  --timeout <seconds>       Health check timeout in seconds (default: 30)
  -n, --dry-run             Validate and download without mutating host binary or restarting service
  -h, --help                Show this help message
EOF
}

TAG=""
CHECKSUM=""

# Parse options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--tag)
            [[ $# -lt 2 ]] && { echo "ERROR: --tag requires an argument." >&2; exit 2; }
            TAG="$2"
            shift 2
            ;;
        -c|--checksum)
            [[ $# -lt 2 ]] && { echo "ERROR: --checksum requires an argument." >&2; exit 2; }
            CHECKSUM="$2"
            shift 2
            ;;
        --repo)
            [[ $# -lt 2 ]] && { echo "ERROR: --repo requires an argument." >&2; exit 2; }
            REPO="$2"
            shift 2
            ;;
        --bin-path)
            [[ $# -lt 2 ]] && { echo "ERROR: --bin-path requires an argument." >&2; exit 2; }
            BIN_PATH="$2"
            shift 2
            ;;
        --service)
            [[ $# -lt 2 ]] && { echo "ERROR: --service requires an argument." >&2; exit 2; }
            SERVICE_NAME="$2"
            shift 2
            ;;
        --lock-file)
            [[ $# -lt 2 ]] && { echo "ERROR: --lock-file requires an argument." >&2; exit 2; }
            LOCK_FILE="$2"
            shift 2
            ;;
        --arch)
            [[ $# -lt 2 ]] && { echo "ERROR: --arch requires an argument." >&2; exit 2; }
            TARGET_ARCH="$2"
            shift 2
            ;;
        --timeout)
            [[ $# -lt 2 ]] && { echo "ERROR: --timeout requires an argument." >&2; exit 2; }
            TIMEOUT_SECONDS="$2"
            shift 2
            ;;
        -n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo "ERROR: Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            if [[ -z "$TAG" ]]; then
                TAG="$1"
            elif [[ -z "$CHECKSUM" ]]; then
                CHECKSUM="$1"
            else
                echo "ERROR: Unexpected positional argument: $1" >&2
                usage >&2
                exit 2
            fi
            shift
            ;;
    esac
done

# Validate required inputs
if [[ -z "$TAG" ]]; then
    echo "ERROR: Release tag is required." >&2
    usage >&2
    exit 2
fi

if [[ -z "$CHECKSUM" ]]; then
    echo "ERROR: Expected SHA-256 checksum is required." >&2
    usage >&2
    exit 2
fi

# Strict tag format validation: Must start with 'v', contain valid SemVer, alphanumeric, dots, hyphens
if [[ ! "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "ERROR: Invalid release tag format: '$TAG'. Must follow SemVer (e.g. v0.4.0, v1.0.0-rc.1)." >&2
    exit 2
fi

# Strict checksum format validation: exactly 64 hexadecimal characters
if [[ ! "$CHECKSUM" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "ERROR: Invalid SHA-256 checksum format: '$CHECKSUM'. Must be 64 hexadecimal characters." >&2
    exit 2
fi

# Strict repository format validation: owner/repo
if [[ ! "$REPO" =~ ^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$ ]]; then
    echo "ERROR: Invalid repository format: '$REPO'. Must be 'owner/repo'." >&2
    exit 2
fi

# Validate target binary directory
TARGET_DIR="$(dirname "$BIN_PATH")"
if [[ ! -d "$TARGET_DIR" ]]; then
    echo "ERROR: Target binary directory does not exist: $TARGET_DIR" >&2
    exit 2
fi

# Validate timeout is a positive integer
if [[ ! "$TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
    echo "ERROR: Invalid timeout: '$TIMEOUT_SECONDS'. Must be a positive integer." >&2
    exit 2
fi

# Validate required tool availability
for tool_cmd in "$CURL_CMD" "$TAR_CMD" "$SHA256SUM_CMD"; do
    if ! command -v "$tool_cmd" >/dev/null 2>&1; then
        echo "ERROR: Required tool '$tool_cmd' not found in PATH." >&2
        exit 2
    fi
done

if [[ "$DRY_RUN" != "true" ]]; then
    for tool_cmd in "$SYSTEMCTL_CMD"; do
        if ! command -v "$tool_cmd" >/dev/null 2>&1; then
            echo "ERROR: Required systemd tool '$tool_cmd' not found in PATH." >&2
            exit 2
        fi
    done
    if [[ ! -w "$TARGET_DIR" ]]; then
        echo "ERROR: Target directory '$TARGET_DIR' is not writable. Root or sudo privileges required." >&2
        exit 1
    fi
fi

# Acquire exclusive update lock to prevent concurrent executions
LOCK_PARENT="$(dirname "$LOCK_FILE")"
mkdir -p "$LOCK_PARENT" 2>/dev/null || true

if command -v flock >/dev/null 2>&1; then
    eval "exec ${LOCK_FD}>\"\$LOCK_FILE\""
    if ! flock -n ${LOCK_FD}; then
        echo "ERROR: Another update is currently in progress (lock held: $LOCK_FILE)." >&2
        exit 3
    fi
    LOCK_HELD=true
else
    LOCK_DIR_PATH="${LOCK_FILE}.dir"
    if ! mkdir "$LOCK_DIR_PATH" 2>/dev/null; then
        echo "ERROR: Another update is currently in progress (lock directory: $LOCK_DIR_PATH)." >&2
        exit 3
    fi
    LOCK_HELD=true
fi

# Resolve architecture
if [[ -z "$TARGET_ARCH" ]]; then
    UNAME_M="$(uname -m)"
    case "$UNAME_M" in
        x86_64|amd64)
            TARGET_ARCH="amd64"
            ;;
        aarch64|arm64)
            TARGET_ARCH="arm64"
            ;;
        *)
            echo "ERROR: Unsupported system architecture: $UNAME_M. Supported architectures: x86_64, aarch64." >&2
            exit 2
            ;;
    esac
else
    case "$TARGET_ARCH" in
        amd64|arm64)
            ;;
        x86_64)
            TARGET_ARCH="amd64"
            ;;
        aarch64)
            TARGET_ARCH="arm64"
            ;;
        *)
            echo "ERROR: Unsupported target architecture: $TARGET_ARCH. Must be 'amd64' or 'arm64'." >&2
            exit 2
            ;;
    esac
fi

ASSET_NAME="primecloud-agent-linux-${TARGET_ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET_NAME}"

# Create secure isolated temporary directory
TMP_DIR="$(mktemp -d -t primecloud-agent-update.XXXXXX)"
chmod 0700 "$TMP_DIR"
ARCHIVE_PATH="${TMP_DIR}/${ASSET_NAME}"

# Acquire candidate archive: check pre-staged asset first, fallback to HTTPS release download
STAGED_ARCHIVE="/tmp/primecloud-agent-${CHECKSUM}.tar.gz"
if [[ -f "$STAGED_ARCHIVE" ]]; then
    echo "==> Found locally staged candidate asset at ${STAGED_ARCHIVE}"
    cp -f "$STAGED_ARCHIVE" "$ARCHIVE_PATH"
else
    echo "==> Downloading release asset from ${DOWNLOAD_URL}..."
    if ! "$CURL_CMD" -fsSL --proto '=https' --tlsv1.2 --max-time 120 --retry 3 --retry-delay 2 -o "$ARCHIVE_PATH" "$DOWNLOAD_URL"; then
        echo "ERROR: Failed to download release asset from ${DOWNLOAD_URL}" >&2
        exit 4
    fi
fi

# Verify SHA-256 checksum
echo "==> Verifying SHA-256 checksum..."
ACTUAL_SHA="$("$SHA256SUM_CMD" "$ARCHIVE_PATH" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')"
EXPECTED_SHA="$(echo "$CHECKSUM" | tr '[:upper:]' '[:lower:]')"

if [[ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]]; then
    echo "ERROR: Cryptographic SHA-256 checksum mismatch!" >&2
    echo "  Expected: ${EXPECTED_SHA}" >&2
    echo "  Actual:   ${ACTUAL_SHA}" >&2
    rm -f "$ARCHIVE_PATH"
    exit 5
fi
echo "==> Checksum verified successfully: ${ACTUAL_SHA}"

# Inspect archive entries before extraction
echo "==> Inspecting archive contents for path safety..."
ARCHIVE_ENTRIES="$("$TAR_CMD" -tzf "$ARCHIVE_PATH")"
if [[ -z "$ARCHIVE_ENTRIES" ]]; then
    echo "ERROR: Release archive is empty." >&2
    exit 6
fi

ENTRY_COUNT=$(echo "$ARCHIVE_ENTRIES" | grep -c .) || true
if [[ "$ENTRY_COUNT" -ne 1 ]]; then
    echo "ERROR: Malicious or invalid archive detected! Expected exactly 1 file, found ${ENTRY_COUNT} entries." >&2
    exit 6
fi

while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    # Reject absolute paths
    if [[ "$entry" == /* || "$entry" == \\* ]]; then
        echo "ERROR: Malicious archive detected! Absolute path entry: $entry" >&2
        exit 6
    fi
    # Reject directory traversal
    if [[ "$entry" == *".."* ]]; then
        echo "ERROR: Malicious archive detected! Path traversal entry: $entry" >&2
        exit 6
    fi
    # Must only contain primecloud-agent
    clean_entry="${entry#./}"
    if [[ "$clean_entry" != "primecloud-agent" ]]; then
        echo "ERROR: Unexpected archive content: $entry (only 'primecloud-agent' is allowed)." >&2
        exit 6
    fi
done <<< "$ARCHIVE_ENTRIES"

# Extract binary
echo "==> Extracting binary from archive..."
"$TAR_CMD" -xzf "$ARCHIVE_PATH" --no-same-owner -C "$TMP_DIR"
EXTRACTED_BIN="${TMP_DIR}/primecloud-agent"

if [[ -L "$EXTRACTED_BIN" || ! -f "$EXTRACTED_BIN" ]]; then
    echo "ERROR: Extracted file is a symlink or irregular file: ${EXTRACTED_BIN}" >&2
    exit 6
fi
chmod 0755 "$EXTRACTED_BIN"

# Pre-execution sanity verification: execute --version
echo "==> Testing extracted binary execution (--version)..."
if ! EXTRACTED_VER="$("$EXTRACTED_BIN" --version 2>&1)"; then
    echo "ERROR: Extracted binary failed pre-execution check: $EXTRACTED_VER" >&2
    exit 7
fi

if [[ "$EXTRACTED_VER" != *"$TAG"* ]]; then
    echo "ERROR: Version mismatch! Extracted binary reported '${EXTRACTED_VER}', expected tag '${TAG}'." >&2
    exit 7
fi
echo "==> Extracted binary verified: $EXTRACTED_VER"

# If Dry-Run, exit cleanly before making any host mutations
if [[ "$DRY_RUN" == "true" ]]; then
    echo "==> [DRY-RUN] Pre-execution verification passed."
    echo "==> [DRY-RUN] Target binary path: ${BIN_PATH}"
    echo "==> [DRY-RUN] Backup target:       ${BIN_PATH}.bak"
    echo "==> [DRY-RUN] Systemd service:     ${SERVICE_NAME}"
    echo "==> [DRY-RUN] Simulation successful. No files were modified and no services were restarted."
    exit 0
fi

# Stage new binary on the SAME filesystem as the target binary for atomic rename
STAGE_BIN="${TARGET_DIR}/.primecloud-agent.new.$RANDOM$$"
BACKUP_BIN="${BIN_PATH}.bak"

echo "==> Staging binary to ${STAGE_BIN}..."
cp -f "$EXTRACTED_BIN" "$STAGE_BIN"

# If current binary exists, preserve ownership and permissions
if [[ -f "$BIN_PATH" ]]; then
    chown --reference="$BIN_PATH" "$STAGE_BIN" 2>/dev/null || true
    chmod --reference="$BIN_PATH" "$STAGE_BIN" 2>/dev/null || chmod 0755 "$STAGE_BIN"
    echo "==> Backing up installed binary to ${BACKUP_BIN}..."
    cp -fp "$BIN_PATH" "$BACKUP_BIN"
else
    chmod 0755 "$STAGE_BIN"
fi

# Atomic replacement
echo "==> Atomically replacing ${BIN_PATH}..."
mv -f "$STAGE_BIN" "$BIN_PATH"

# Restart systemd service and verify health
NEED_ROLLBACK=false
echo "==> Restarting ${SERVICE_NAME}..."
if ! "$SYSTEMCTL_CMD" restart "$SERVICE_NAME"; then
    echo "ERROR: Failed to restart ${SERVICE_NAME}!" >&2
    NEED_ROLLBACK=true
else
    echo "==> Verifying service health (timeout: ${TIMEOUT_SECONDS}s, poll: ${POLL_INTERVAL}s)..."
    ELAPSED=0
    HEALTHY=false
    while [[ $ELAPSED -lt $TIMEOUT_SECONDS ]]; do
        ACTIVE_STATE="$("$SYSTEMCTL_CMD" is-active "$SERVICE_NAME" 2>/dev/null || true)"
        SUB_STATE="$("$SYSTEMCTL_CMD" show -p SubState --value "$SERVICE_NAME" 2>/dev/null || true)"

        if [[ "$ACTIVE_STATE" == "active" && "$SUB_STATE" == "running" ]]; then
            MAIN_PID="$("$SYSTEMCTL_CMD" show -p MainPID --value "$SERVICE_NAME" 2>/dev/null || true)"
            if [[ -n "$MAIN_PID" && "$MAIN_PID" =~ ^[0-9]+$ && "$MAIN_PID" -gt 0 ]]; then
                if kill -0 "$MAIN_PID" 2>/dev/null || [[ -d "/proc/$MAIN_PID" ]] || [[ "${OSTYPE:-}" == "msys"* ]]; then
                    HEALTHY=true
                    break
                fi
            fi
        fi

        if [[ "$ACTIVE_STATE" == "failed" ]]; then
            echo "ERROR: ${SERVICE_NAME} entered failed state!" >&2
            break
        fi

        sleep "$POLL_INTERVAL"
        ELAPSED=$((ELAPSED + POLL_INTERVAL))
    done

    if [[ "$HEALTHY" != "true" ]]; then
        echo "ERROR: ${SERVICE_NAME} failed health verification within ${TIMEOUT_SECONDS}s!" >&2
        if command -v "$JOURNALCTL_CMD" >/dev/null 2>&1; then
            echo "==> Diagnostic journal entries for ${SERVICE_NAME}:" >&2
            "$JOURNALCTL_CMD" -u "$SERVICE_NAME" -n 20 --no-pager 2>/dev/null || true
        fi
        NEED_ROLLBACK=true
    fi
fi

# Rollback procedure if needed
if [[ "$NEED_ROLLBACK" == "true" ]]; then
    echo "==> [ROLLBACK] Initiating automated rollback..." >&2
    if [[ -f "$BACKUP_BIN" ]]; then
        cp -fp "$BACKUP_BIN" "$BIN_PATH"
        echo "==> [ROLLBACK] Restored previous binary from ${BACKUP_BIN} (backup preserved)." >&2
        echo "==> [ROLLBACK] Restarting ${SERVICE_NAME} with restored binary..." >&2
        if "$SYSTEMCTL_CMD" restart "$SERVICE_NAME" 2>/dev/null; then
            sleep 2
            ROLLBACK_STATE="$("$SYSTEMCTL_CMD" is-active "$SERVICE_NAME" 2>/dev/null || true)"
            if [[ "$ROLLBACK_STATE" == "active" ]]; then
                echo "==> [ROLLBACK SUCCESS] Service successfully rolled back to previous version and is active." >&2
                exit 1
            fi
        fi
        echo "==> [CRITICAL] Rollback service restart failed! Manual intervention required." >&2
        exit 8
    else
        echo "==> [ROLLBACK] No backup binary found at ${BACKUP_BIN} (fresh install failure). Unlinking failed binary..." >&2
        rm -f "$BIN_PATH" 2>/dev/null || true
        echo "==> [CRITICAL] Initial installation failed and no previous binary exists!" >&2
        exit 8
    fi
fi

echo "==> [SUCCESS] PrimeCloud Agent successfully updated to ${TAG}."
exit 0
