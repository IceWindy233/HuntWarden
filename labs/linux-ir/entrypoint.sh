#!/usr/bin/env bash
set -euo pipefail

ssh-keygen -A
service cron start
python3 /opt/huntwarden-lab/listener.py &
python3 /tmp/.update &
/tmp/.cache-worker 3600 &
deleted_pid=$!
rm -f /tmp/.cache-worker
printf '%s\n' "$deleted_pid" > /run/huntwarden-deleted-process.pid
exec /usr/sbin/sshd -D -e
