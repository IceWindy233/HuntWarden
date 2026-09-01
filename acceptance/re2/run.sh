#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
matrix_tmp=$(mktemp -d)
cleanup() { rm -rf -- "$matrix_tmp"; }
trap cleanup EXIT

python3 -m venv "$matrix_tmp/venv"
"$matrix_tmp/venv/bin/python" -m pip install --quiet --disable-pip-version-check google-re2==1.1.20251105
"$matrix_tmp/venv/bin/python" "$project_root/acceptance/re2/verify.py" "$project_root/host-helper/huntwarden_helper.py"

docker build --quiet -f "$project_root/acceptance/re2/Dockerfile" -t huntwarden-re2-matrix:ubuntu22 "$project_root" >/dev/null
docker run --rm huntwarden-re2-matrix:ubuntu22
