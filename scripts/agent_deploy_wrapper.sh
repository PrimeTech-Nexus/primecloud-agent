#!/usr/bin/env bash
# ==============================================================================
# PrimeCloud Agent Production Deployment Least-Privilege Entry Point Wrapper
# Component: Infrastructure / Secure Agent Deployment Entry Point
# Host Target: pc-node-001 | Installed Path: /opt/primecloud-bootstrap/agent_deploy_wrapper.sh
# Permissions: chmod 750 / chown root:root
# Mode: Strictly validated, argument-locked, root-delegated execution
# ==============================================================================
set -euo pipefail
IFS=$'\n\t'

DRY_RUN=false
TAG=""
CHECKSUM=""
STAGED_ARCHIVE=""

# 1. Parse and validate arguments (accepts [--dry-run] [--staged-archive <PATH>] <TAG> <CHECKSUM>)
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run|-n)
            DRY_RUN=true
            shift
            ;;
        -a|--archive|--staged-archive)
            [[ $# -lt 2 ]] && { echo "==> [SECURITY REJECTION] --staged-archive requires an argument." >&2; exit 1; }
            STAGED_ARCHIVE="$2"
            shift 2
            ;;
        -*)
            echo "==> [SECURITY REJECTION] Unknown flag or option: '$1'" >&2
            echo "    Usage: $0 [--dry-run] [--staged-archive <PATH>] <TAG> <SHA256_CHECKSUM>" >&2
            exit 1
            ;;
        *)
            if [[ -z "$TAG" ]]; then
                TAG="$1"
            elif [[ -z "$CHECKSUM" ]]; then
                CHECKSUM="$1"
            else
                echo "==> [SECURITY REJECTION] Too many arguments provided." >&2
                echo "    Usage: $0 [--dry-run] [--staged-archive <PATH>] <TAG> <SHA256_CHECKSUM>" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

if [[ -z "$TAG" || -z "$CHECKSUM" ]]; then
    echo "==> [SECURITY REJECTION] Both release tag and SHA-256 checksum are required." >&2
    echo "    Usage: $0 [--dry-run] [--staged-archive <PATH>] <TAG> <SHA256_CHECKSUM>" >&2
    exit 1
fi

# 2. Reject shell metacharacters and control characters immediately
if [[ ! "$TAG" =~ ^[a-zA-Z0-9.-]+$ ]]; then
    echo "==> [SECURITY REJECTION] Tag contains forbidden characters or shell metacharacters: '$TAG'" >&2
    exit 1
fi

if [[ ! "$CHECKSUM" =~ ^[0-9a-fA-F]+$ ]]; then
    echo "==> [SECURITY REJECTION] Checksum contains non-hexadecimal characters." >&2
    exit 1
fi

# 3. Strict SemVer tag format validation: must start with 'v'
if [[ ! "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "==> [SECURITY REJECTION] Tag '$TAG' does not follow SemVer release tag format (e.g. v0.4.0)." >&2
    exit 1
fi

# 4. Strict SHA-256 length validation: exactly 64 hexadecimal characters
if [[ ! "$CHECKSUM" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "==> [SECURITY REJECTION] Checksum must be exactly 64 hexadecimal characters." >&2
    exit 1
fi

# 5. Fixed path resolution for update script
BOOTSTRAP_DIR="${PRIMECLOUD_BOOTSTRAP_DIR:-/opt/primecloud-bootstrap}"
UPDATER_SCRIPT="${BOOTSTRAP_DIR}/update-agent.sh"

# Preflight check on target update script
if [[ ! -f "${UPDATER_SCRIPT}" ]]; then
    echo "==> [FATAL] Target updater script not found at: ${UPDATER_SCRIPT}" >&2
    exit 1
fi

if [[ ! -x "${UPDATER_SCRIPT}" ]]; then
    echo "==> [FATAL] Target updater script is not executable: ${UPDATER_SCRIPT}" >&2
    exit 1
fi

# In production mode, verify root ownership
if [[ "${PRIMECLOUD_ENV:-}" != "test" ]]; then
    SCRIPT_OWNER="$(stat -c '%u' "${UPDATER_SCRIPT}" 2>/dev/null || stat -f '%u' "${UPDATER_SCRIPT}" 2>/dev/null || echo "unknown")"
    if [[ "${SCRIPT_OWNER}" != "0" ]]; then
        echo "==> [FATAL SECURITY ERROR] Target updater script is not root-owned (UID ${SCRIPT_OWNER})!" >&2
        exit 1
    fi
fi

# 6. Candidate archive resolution and integrity pre-check
CHECKSUM_LOWER="$(printf '%s' "$CHECKSUM" | tr '[:upper:]' '[:lower:]')"
SHA256SUM_BIN="${SHA256SUM_CMD:-sha256sum}"

if [[ -z "$STAGED_ARCHIVE" ]]; then
    if [[ -f "/tmp/primecloud-agent-${CHECKSUM_LOWER}.tar.gz" ]]; then
        STAGED_ARCHIVE="/tmp/primecloud-agent-${CHECKSUM_LOWER}.tar.gz"
    elif [[ -f "/tmp/primecloud-agent-${CHECKSUM}.tar.gz" ]]; then
        STAGED_ARCHIVE="/tmp/primecloud-agent-${CHECKSUM}.tar.gz"
    fi
fi

EXTRA_ARGS=()
if [[ "$DRY_RUN" == "true" ]]; then
    EXTRA_ARGS+=("--dry-run")
fi

if [[ -n "$STAGED_ARCHIVE" ]]; then
    if [[ ! -f "$STAGED_ARCHIVE" || ! -s "$STAGED_ARCHIVE" ]]; then
        echo "==> [SECURITY REJECTION] Candidate archive is missing, empty, or not a regular file: ${STAGED_ARCHIVE}" >&2
        exit 1
    fi
    if command -v "$SHA256SUM_BIN" >/dev/null 2>&1; then
        ACTUAL_SHA="$("$SHA256SUM_BIN" "$STAGED_ARCHIVE" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')"
        if [[ "$ACTUAL_SHA" != "$CHECKSUM_LOWER" ]]; then
            echo "==> [SECURITY REJECTION] Candidate archive SHA-256 does not match expected checksum!" >&2
            echo "    Expected: ${CHECKSUM_LOWER}" >&2
            echo "    Actual:   ${ACTUAL_SHA}" >&2
            exit 1
        fi
    fi
    EXTRA_ARGS+=("--staged-archive" "$STAGED_ARCHIVE")
    echo "==> [ENTRYPOINT] Validated candidate staged archive: ${STAGED_ARCHIVE}"
elif [[ "$TAG" =~ -main\. || "$TAG" =~ -ci\. || "$TAG" =~ -dev\. ]]; then
    echo "==> [SECURITY REJECTION] Branch deployment '${TAG}' requires a pre-staged candidate archive at /tmp/primecloud-agent-${CHECKSUM_LOWER}.tar.gz, but none was found!" >&2
    exit 1
fi

echo "==> [ENTRYPOINT] Validated release tag: ${TAG}"
echo "==> [ENTRYPOINT] Validated SHA-256 checksum: ${CHECKSUM_LOWER}"
echo "==> [ENTRYPOINT] Executing ${UPDATER_SCRIPT}..."

exec "${UPDATER_SCRIPT}" "${EXTRA_ARGS[@]}" "${TAG}" "${CHECKSUM}"
