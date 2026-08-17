#!/usr/bin/env bash
set -euo pipefail

# Keep time-window fixtures relative to every container start. Image-layer
# mtimes and fixed log dates otherwise age out of the 168-hour scan window.
find /var/www/html /srv/alternate-app -xdev -type f -exec touch -- {} +
touch -- /tmp/lab-upload.php
log_time=$(LC_ALL=C date -u '+%d/%b/%Y:%H:%M:%S +0000')
printf '192.0.2.44 - - [%s] "POST /uploads/lab-upload.php HTTP/1.1" 200 42 "-" "HuntWarden-Lab"\n192.0.2.44 - - [%s] "GET /uploads/lab-upload.php?cmd=id HTTP/1.1" 200 42 "-" "HuntWarden-Lab"\n' \
  "${log_time}" "${log_time}" > /var/log/nginx/access.log

ssh-keygen -A
nginx
exec /usr/sbin/sshd -D -e
