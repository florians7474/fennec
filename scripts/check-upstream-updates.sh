#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../system/sources.lock
source "$ROOT/system/sources.lock"

changed=0
check_upstream() {
    local name="$1" repository="$2" tracking_ref="$3" locked_ref="$4" current_ref
    current_ref="$(git ls-remote "$repository" "refs/heads/$tracking_ref" | awk 'NR == 1 {print $1}')"
    if [[ -z "$current_ref" ]]; then
        echo "$name: unable to read upstream $tracking_ref" >&2
        changed=1
        return
    fi
    if [[ "$current_ref" = "$locked_ref" ]]; then
        echo "$name: locked at $locked_ref"
    else
        echo "$name: update available ($locked_ref -> $current_ref)"
        changed=1
    fi
}

check_upstream "Pwnagotchi" "$PWNAGOTCHI_REPOSITORY" "$PWNAGOTCHI_TRACKING_REF" "$PWNAGOTCHI_REF"
check_upstream "pwngrid" "$PWNGRID_REPOSITORY" "$PWNGRID_TRACKING_REF" "$PWNGRID_REF"
check_upstream "Bjorn" "$BJORN_REPOSITORY" "$BJORN_TRACKING_REF" "$BJORN_REF"
check_upstream "routerkeygen" "$ROUTERKEYGEN_REPOSITORY" "$ROUTERKEYGEN_TRACKING_REF" "$ROUTERKEYGEN_REF"
check_upstream "SecLists" "$SECLISTS_REPOSITORY" "$SECLISTS_TRACKING_REF" "$SECLISTS_REF"
check_upstream "Responder" "$RESPONDER_REPOSITORY" "$RESPONDER_TRACKING_REF" "$RESPONDER_REF"
check_upstream "John" "$JOHN_REPOSITORY" "$JOHN_TRACKING_REF" "$JOHN_REF"

if (( changed )); then
    exit 10
fi
