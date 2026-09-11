#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
compose_file="$project_root/acceptance/load/docker-compose.yml"
process_count="${HUNTWARDEN_LOAD_PROCESS_COUNT:-1000}"
file_count="${HUNTWARDEN_LOAD_FILE_COUNT:-100000}"
log_count="${HUNTWARDEN_LOAD_LOG_COUNT:-100000}"
result_path="${HUNTWARDEN_LOAD_RESULT:-$project_root/acceptance/load/result-${process_count}p-${file_count}f-${log_count}l.json}"
control_result_path="${HUNTWARDEN_LOAD_CONTROL_RESULT:-$project_root/acceptance/load/control-result-${process_count}p.json}"
state_dir="$project_root/acceptance/load/.state"

mkdir -p "$state_dir"
chmod 700 "$state_dir"
if [[ ! -f "$state_dir/operator_ed25519" ]]; then
  ssh-keygen -q -t ed25519 -N '' -f "$state_dir/operator_ed25519"
fi

if (( process_count > 2000 )) && [[ "${HUNTWARDEN_LOAD_CONFIRM:-}" != "I_HAVE_A_DISPOSABLE_8GB_DOCKER_ENV" ]]; then
  echo "超过 2000 个进程需要设置 HUNTWARDEN_LOAD_CONFIRM=I_HAVE_A_DISPOSABLE_8GB_DOCKER_ENV" >&2
  exit 64
fi

cleanup() {
  docker compose -f "$compose_file" down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker compose -f "$compose_file" up -d --build
for _ in $(seq 1 120); do
  status="$(docker inspect --format '{{.State.Health.Status}}' huntwarden-load-target 2>/dev/null || true)"
  if [[ "$status" == "healthy" ]]; then break; fi
  if [[ "$status" == "unhealthy" ]]; then
    docker logs huntwarden-load-target >&2
    exit 1
  fi
  sleep 2
done
if [[ "$(docker inspect --format '{{.State.Health.Status}}' huntwarden-load-target 2>/dev/null || true)" != "healthy" ]]; then
  docker logs huntwarden-load-target >&2
  echo "负载容器未就绪" >&2
  exit 1
fi
python3 "$project_root/acceptance/load/verify.py" \
  --process-count "$process_count" \
  --file-count "$file_count" \
  --log-count "$log_count" \
  --output "$result_path"

known_hosts="$state_dir/known_hosts"
: > "$known_hosts"
line=""
for _ in $(seq 1 60); do
  if line=$(ssh-keyscan -p 2300 -t ed25519 127.0.0.1 2>/dev/null) && [[ -n "$line" ]]; then
    printf '%s\n' "$line" >> "$known_hosts"
    fingerprint=$(printf '%s\n' "$line" | ssh-keygen -lf - -E sha256 | awk '{print $2}')
    printf '# %s port=2300\n' "$fingerprint" >> "$known_hosts"
    break
  fi
  sleep 1
done
if [[ -z "$line" ]]; then
  echo "负载控制端 SSH 目标未就绪" >&2
  exit 1
fi
chmod 600 "$known_hosts"

cd "$project_root"
HUNTWARDEN_CONTROL_LOAD_TESTS=1 \
HUNTWARDEN_LOAD_PROCESS_COUNT="$process_count" \
HUNTWARDEN_LOAD_CONTROL_RESULT="$control_result_path" \
npx vitest run tests/acceptance/control-plane-load.test.ts --testTimeout=900000 --hookTimeout=120000
