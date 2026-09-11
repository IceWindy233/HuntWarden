#!/usr/bin/env bash
set -euo pipefail

# Keep time-window fixtures relative to every container start. Image-layer
# mtimes and fixed log dates otherwise age out of the 168-hour scan window.
find /var/www/html /srv/alternate-app /srv/apache-app -xdev -type f -exec touch -- {} +
# 模拟攻击者回改时间戳或长期驻留文件。自主候选发现必须仍能枚举该文件。
touch -d '2010-01-02T03:04:05Z' -- /var/www/html/old-webshell.php
touch -- /tmp/lab-upload.php
log_time=$(LC_ALL=C date -u '+%d/%b/%Y:%H:%M:%S +0000')
printf '192.0.2.44 - - [%s] "POST /uploads/lab-upload.php HTTP/1.1" 200 42 "-" "HuntWarden-Lab"\n192.0.2.44 - - [%s] "GET /lab-webshell.php?cmd=id HTTP/1.1" 200 42 "-" "HuntWarden-Lab"\n' \
  "${log_time}" "${log_time}" > /var/log/nginx/access.log

ssh-keygen -A
nginx
apache2ctl start
php_fpm_binary="$(command -v php-fpm || find /usr/sbin -maxdepth 1 -type f -name 'php-fpm*' | sort | head -n 1)"
if [[ -n "${php_fpm_binary}" ]]; then
  "${php_fpm_binary}" -D
fi
exec /usr/sbin/sshd -D -e
