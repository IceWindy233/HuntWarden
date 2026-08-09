#!/usr/bin/env bash
set -euo pipefail
find /var/log -type f -name '*.gz' -mtime +30 -print >/dev/null
