#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "$0")/../.." && pwd)
state_dir="${project_dir}/acceptance/real-world/.state"
compose_file="${project_dir}/acceptance/real-world/docker-compose.yml"

mkdir -p "${state_dir}"
chmod 700 "${state_dir}"
if [[ ! -f "${state_dir}/operator_ed25519" ]]; then
  ssh-keygen -q -t ed25519 -N '' -f "${state_dir}/operator_ed25519"
fi
if [[ ! -f "${state_dir}/unknown_ed25519" ]]; then
  ssh-keygen -q -t ed25519 -N '' -f "${state_dir}/unknown_ed25519"
fi

cleanup() {
  docker compose -f "${compose_file}" down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker compose -f "${compose_file}" up -d --build

known_hosts="${state_dir}/known_hosts"
: > "${known_hosts}"
line=""
for _ in $(seq 1 60); do
  if line=$(ssh-keyscan -p 2299 -t ed25519 127.0.0.1 2>/dev/null) && [[ -n "${line}" ]]; then
    printf '%s\n' "${line}" >> "${known_hosts}"
    fingerprint=$(printf '%s\n' "${line}" | ssh-keygen -lf - -E sha256 | awk '{print $2}')
    printf '# %s port=2299\n' "${fingerprint}" >> "${known_hosts}"
    break
  fi
  sleep 1
done
if [[ -z "${line}" ]]; then
  printf 'Real-world acceptance SSH target did not become ready\n' >&2
  exit 1
fi
chmod 600 "${known_hosts}"

cd "${project_dir}"
HUNTWARDEN_REAL_WORLD_TESTS=1 npx vitest run tests/acceptance/real-world.test.ts --testTimeout=180000 --hookTimeout=180000
