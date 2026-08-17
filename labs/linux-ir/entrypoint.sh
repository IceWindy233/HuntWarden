#!/usr/bin/env bash
set -euo pipefail

ssh-keygen -A
touch -- /tmp/.update /usr/bin/yes /etc/cron.d/huntwarden-ir /etc/ld.so.preload /opt/huntwarden-lab/libpreload.so
log_time=$(LC_ALL=C date '+%b %e %H:%M:%S')
printf '%s lab-linux-ir sshd[120]: Accepted publickey for iruser from 192.0.2.45 port 43210 ssh2\n%s lab-linux-ir sudo: iruser : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/id\n%s lab-linux-ir sshd[120]: Failed publickey for invalid user admin from 198.51.100.22 port 50000 ssh2\n' \
  "${log_time}" "${log_time}" "${log_time}" > /var/log/auth.log
service cron start
python3 /opt/huntwarden-lab/listener.py &
python3 /tmp/.update &
/tmp/.cache-worker 3600 &
deleted_pid=$!
rm -f /tmp/.cache-worker
printf '%s\n' "$deleted_pid" > /run/huntwarden-deleted-process.pid
exec /usr/sbin/sshd -D -e
