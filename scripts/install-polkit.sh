#!/usr/bin/env bash
# Install the abracadabra polkit action policy (requires root).
# Usage: sudo scripts/install-polkit.sh
set -euo pipefail

DEST_DIR="/usr/share/polkit-1/actions"
DEST="${DEST_DIR}/dev.abracadabra.policy"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${SCRIPT_DIR}/../packaging/linux/dev.abracadabra.policy"

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: must run as root. Try: sudo $0" >&2
  exit 1
fi

if [[ ! -f "${SRC}" ]]; then
  echo "error: policy not found at ${SRC}" >&2
  exit 1
fi

mkdir -p "${DEST_DIR}"

if [[ -f "${DEST}" ]] && cmp -s "${SRC}" "${DEST}"; then
  echo "ok: ${DEST} already up to date (identical)"
  exit 0
fi

install -m 0644 "${SRC}" "${DEST}"
echo "ok: installed ${DEST}"
echo "verify: pkaction --action-id dev.abracadabra.reveal --verbose"
