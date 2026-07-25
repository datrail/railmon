#!/usr/bin/env bash
# Download a pinned AgentSight release binary into bin/agentsight.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${AGENTSIGHT_VERSION:-v0.2.65}"
REPO="${AGENTSIGHT_REPO:-eunomia-bpf/agentsight}"
ASSET="${AGENTSIGHT_ASSET:-agentsight}"
OUT_DIR="${ROOT}/bin"
OUT="${OUT_DIR}/agentsight"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"

mkdir -p "${OUT_DIR}"

if [[ -x "${OUT}" ]]; then
  # Reuse existing binary unless FORCE=1
  if [[ "${FORCE:-0}" != "1" ]]; then
    echo "agentsight already present at ${OUT} (set FORCE=1 to re-download)"
    exit 0
  fi
fi

TMP="$(mktemp)"
trap 'rm -f "${TMP}"' EXIT

echo "Downloading ${URL}"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL -o "${TMP}" "${URL}"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "${TMP}" "${URL}"
else
  echo "error: need curl or wget to download agentsight" >&2
  exit 1
fi

chmod +x "${TMP}"
# Basic sanity: ELF executable
if ! file "${TMP}" | grep -qi 'ELF'; then
  echo "error: downloaded file is not an ELF binary" >&2
  exit 1
fi

mv "${TMP}" "${OUT}"
trap - EXIT
echo "Installed ${OUT} (${VERSION})"
"${OUT}" --version || true
