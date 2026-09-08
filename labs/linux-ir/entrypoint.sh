#!/usr/bin/env bash
set -euo pipefail

ssh-keygen -A
touch -- /tmp/.update /usr/bin/yes /etc/cron.d/huntwarden-ir /etc/ld.so.preload /opt/huntwarden-lab/libpreload.so
log_time=$(LC_ALL=C date '+%b %e %H:%M:%S')
printf '%s lab-linux-ir sshd[120]: Accepted publickey for iruser from 192.0.2.45 port 43210 ssh2\n%s lab-linux-ir sudo: iruser : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/id\n%s lab-linux-ir sshd[120]: Failed publickey for invalid user admin from 198.51.100.22 port 50000 ssh2\n' \
  "${log_time}" "${log_time}" "${log_time}" > /var/log/auth.log
printf '%s lab-linux-ir system-health[321]: scan completed token=lab-secret-value\n' "${log_time}" > /var/log/syslog
service cron start
python3 /opt/huntwarden-lab/listener.py &
python3 /tmp/.update &
/tmp/.cache-worker 3600 &
deleted_pid=$!
# Bash may return from the background launch before the child has opened its
# executable. Wait for /proc to expose the executable so unlinking the fixture
# cannot race the dynamic loader.
for _ in $(seq 1 100); do
  if [[ "$(readlink "/proc/${deleted_pid}/exe" 2>/dev/null || true)" == "/tmp/.cache-worker" ]]; then
    break
  fi
  sleep 0.01
done
if [[ "$(readlink "/proc/${deleted_pid}/exe" 2>/dev/null || true)" != "/tmp/.cache-worker" ]]; then
  echo "deleted executable fixture did not start" >&2
  exit 1
fi
rm -f /tmp/.cache-worker
printf '%s\n' "$deleted_pid" > /run/huntwarden-deleted-process.pid
exec /usr/sbin/sshd -D -e
