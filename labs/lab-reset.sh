#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "$0")/.." && pwd)
compose_file="$project_dir/labs/docker-compose.yml"

docker compose -f "$compose_file" down --remove-orphans
exec bash "$project_dir/labs/lab-up.sh"
