#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ -f "$root/SHA256SUMS" ]]; then
  if ! (cd "$root" && sha256sum --check --strict --quiet SHA256SUMS); then
    echo 'FAIL: File checksum mismatch. Download and extract the package again.' >&2
    exit 1
  fi
  echo 'PASS: Package checksums'
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo 'FAIL: Python 3 was not found. Install python3 on Ubuntu 24.04 and retry.' >&2
  exit 1
fi
exec python3 -B "$root/deploy/preflight.py" "$@"
