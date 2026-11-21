#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../system/sources.lock
source "$ROOT/system/sources.lock"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

require_sha() {
    local name="$1" value="$2"
    [[ "$value" =~ ^[0-9a-f]{40}$ ]] || fail "$name is not a full commit SHA."
}

verify_git_ref() {
    local name="$1" repository="$2" ref="$3" workdir actual
    workdir="$(mktemp -d)"
    trap 'rm -rf "$workdir"' RETURN
    git init -q "$workdir"
    git -C "$workdir" fetch -q --depth=1 "$repository" "$ref" ||
        fail "$name locked commit cannot be fetched."
    actual="$(git -C "$workdir" rev-parse FETCH_HEAD)"
    [[ "$actual" = "$ref" ]] || fail "$name resolved to $actual instead of $ref."
}

require_sha PWNAGOTCHI_REF "$PWNAGOTCHI_REF"
require_sha PWNGRID_REF "$PWNGRID_REF"
require_sha BJORN_REF "$BJORN_REF"
require_sha ROUTERKEYGEN_REF "$ROUTERKEYGEN_REF"
require_sha SECLISTS_REF "$SECLISTS_REF"
require_sha RESPONDER_REF "$RESPONDER_REF"
require_sha JOHN_REF "$JOHN_REF"
[[ "$WAVESHARE35C_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
    fail "WAVESHARE35C_ARCHIVE_SHA256 is not a SHA-256 digest."

if [[ "${1:-}" = "--offline" ]]; then
    echo "Source lock syntax is valid."
    exit 0
fi

verify_git_ref "Pwnagotchi" "$PWNAGOTCHI_REPOSITORY" "$PWNAGOTCHI_REF"
verify_git_ref "pwngrid" "$PWNGRID_REPOSITORY" "$PWNGRID_REF"
verify_git_ref "Bjorn" "$BJORN_REPOSITORY" "$BJORN_REF"
verify_git_ref "routerkeygen" "$ROUTERKEYGEN_REPOSITORY" "$ROUTERKEYGEN_REF"
verify_git_ref "SecLists" "$SECLISTS_REPOSITORY" "$SECLISTS_REF"
verify_git_ref "Responder" "$RESPONDER_REPOSITORY" "$RESPONDER_REF"
verify_git_ref "John" "$JOHN_REPOSITORY" "$JOHN_REF"

archive_sha="$(curl --fail --location --silent --show-error "$WAVESHARE35C_ARCHIVE_URL" | sha256sum | awk '{print $1}')"
[[ "$archive_sha" = "$WAVESHARE35C_ARCHIVE_SHA256" ]] ||
    fail "Waveshare archive checksum changed."

echo "All locked external sources are reachable and match their expected revisions."
