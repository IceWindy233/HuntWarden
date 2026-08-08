#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "$0")/.." && pwd)
state_dir="$project_dir/labs/.lab-state"
mkdir -p "$state_dir"
chmod 700 "$state_dir"

if [[ ! -f "$state_dir/id_ed25519" ]]; then
  ssh-keygen -q -t ed25519 -N '' -f "$state_dir/id_ed25519"
fi
if [[ ! -f "$state_dir/unknown_ed25519" ]]; then
  ssh-keygen -q -t ed25519 -N '' -f "$state_dir/unknown_ed25519"
fi
cp "$state_dir/id_ed25519.pub" "$project_dir/labs/common/lab_authorized_key.pub"
cp "$state_dir/unknown_ed25519.pub" "$project_dir/labs/common/unknown_authorized_key.pub"

"$project_dir/java/build-probe.sh" jar
docker compose -f "$project_dir/labs/docker-compose.yml" up -d --build

known_hosts="$state_dir/known_hosts"
: > "$known_hosts"
for port in 2222 2223 2224; do
  for _ in $(seq 1 30); do
    if line=$(ssh-keyscan -p "$port" -t ed25519 127.0.0.1 2>/dev/null) && [[ -n "$line" ]]; then
      printf '%s\n' "$line" >> "$known_hosts"
      fingerprint=$(printf '%s\n' "$line" | ssh-keygen -lf - -E sha256 | awk '{print $2}')
      printf '# %s port=%s\n' "$fingerprint" "$port" >> "$known_hosts"
      break
    fi
    sleep 1
  done
done
chmod 600 "$known_hosts"
printf 'Lab ready. Identity: %s\nKnown hosts: %s\n' "$state_dir/id_ed25519" "$known_hosts"
