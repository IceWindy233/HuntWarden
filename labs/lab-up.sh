#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "$0")/.." && pwd)
state_dir="$project_dir/labs/.lab-state"
common_dir="$project_dir/labs/common"
mkdir -p "$state_dir" "$common_dir"
chmod 700 "$state_dir"

if [[ ! -f "$state_dir/id_ed25519" ]]; then
  ssh-keygen -q -t ed25519 -N '' -f "$state_dir/id_ed25519"
fi
if [[ ! -f "$state_dir/unknown_ed25519" ]]; then
  ssh-keygen -q -t ed25519 -N '' -f "$state_dir/unknown_ed25519"
fi
cp "$state_dir/id_ed25519.pub" "$common_dir/lab_authorized_key.pub"
cp "$state_dir/unknown_ed25519.pub" "$common_dir/unknown_authorized_key.pub"

"$project_dir/java/build-probe.sh" jar
docker compose -f "$project_dir/labs/docker-compose.yml" up -d --build

known_hosts="$state_dir/known_hosts"
: > "$known_hosts"
for port in 2222 2223 2224 2225 2226; do
  line=""
  for _ in $(seq 1 30); do
    if line=$(ssh-keyscan -p "$port" -t ed25519 127.0.0.1 2>/dev/null) && [[ -n "$line" ]]; then
      printf '%s\n' "$line" >> "$known_hosts"
      fingerprint=$(printf '%s\n' "$line" | ssh-keygen -lf - -E sha256 | awk '{print $2}')
      printf '# %s port=%s\n' "$fingerprint" "$port" >> "$known_hosts"
      break
    fi
    sleep 1
  done
  if [[ -z "$line" ]]; then
    printf 'Lab SSH port %s did not become ready\n' "$port" >&2
    exit 1
  fi
done
chmod 600 "$known_hosts"

wait_http() {
  local name="$1"
  local url="$2"
  for _ in $(seq 1 60); do
    if curl -fsS "$url" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  printf '%s did not become ready: %s\n' "$name" "$url" >&2
  return 1
}

wait_http "Lab-Web" "http://127.0.0.1:8080/"
wait_http "Lab-Tomcat" "http://127.0.0.1:8081/lab/"

# SSH 和 HTTP 就绪不代表 Lab-Linux-IR 的可疑客户端已经连上假 C2。此前直接开跑测试，
# `relate process connects` 偶发看不到 46666 连接，测试红灯却不是回归。46666 = 0xB64A。
wait_lab_ir_c2() {
  for _ in $(seq 1 60); do
    if docker compose -f "$project_dir/labs/docker-compose.yml" exec -T lab-linux-ir \
      awk '$3 ~ /:B64A$/ && $4 == "01" { found = 1 } END { exit !found }' /proc/net/tcp >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  printf 'Lab-Linux-IR 的假 C2 连接未建立：/proc/net/tcp 中没有远端端口 46666 的 ESTABLISHED 连接\n' >&2
  return 1
}

wait_lab_ir_c2
printf 'Lab ready. Identity: %s\nKnown hosts: %s\n' "$state_dir/id_ed25519" "$known_hosts"
