#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
python=python3
# Use the installed venv for server-side checks. The external client only
# needs the standard library, curl and a local sing-box executable.
if (( $# == 0 )); then set -- local; fi
if [[ "$1" == local && "${2:-}" != --help && "${2:-}" != -h ]]; then
  python=/opt/hy2-lite/current/.venv/bin/python
fi
if ! command -v "$python" >/dev/null 2>&1; then
  echo 'FAIL: Python was not found. Finish the VPS installation or install Python 3 on the external device.' >&2
  exit 1
fi
PYTHONPATH="$root" exec "$python" -B "$root/deploy/verify_install.py" "$@"
