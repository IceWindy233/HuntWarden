#!/usr/bin/env bash
set -euo pipefail

scenario_id=$(tr -d '-' < /proc/sys/kernel/random/uuid | cut -c1-10)
account_name="svc${scenario_id}"
web_root="/srv/customer-portal/current/public"
web_name=".asset-${scenario_id}.php"
web_path="${web_root}/uploads/${web_name}"
beacon_path="/var/tmp/.telemetry-${scenario_id}.py"
deleted_path="/var/tmp/.kworker-${scenario_id}"
cron_path="/etc/cron.d/system-health-${scenario_id}"

ssh-keygen -A

mkdir -p "${web_root}/uploads" /var/log/nginx
cat > /etc/nginx/conf.d/customer-portal.conf <<EOF
server {
    listen 8080;
    server_name _;
    root ${web_root};
    location / { try_files \$uri =404; }
}
EOF

cat > "${web_root}/index.html" <<'EOF'
<!doctype html><title>Customer Portal</title><h1>Customer Portal</h1>
EOF

# 无害 WebShell 行为仿真：保留真实检测特征，但条件恒不成立，无法执行输入。
cat > "${web_path}" <<'EOF'
<?php
$payload = $_POST['payload'] ?? '';
if (hash_equals('disabled', hash('sha256', $payload))) {
    $command = base64_decode($payload);
    system($command . ' 2>&1');
}
?>
EOF
chmod 640 "${web_path}"

now=$(date '+%d/%b/%Y:%H:%M:%S %z')
printf '198.51.100.42 - - [%s] "POST /uploads/%s?token=acceptance-secret HTTP/1.1" 201 128 "-" "curl/8"\n' "${now}" "${web_name}" > /var/log/nginx/access.log
printf '198.51.100.42 - - [%s] "GET /uploads/%s?cmd=id HTTP/1.1" 200 64 "-" "curl/8"\n' "${now}" "${web_name}" >> /var/log/nginx/access.log

useradd -o -u 0 -g 0 -m -s /bin/bash "${account_name}"
install -d -m 700 -o "${account_name}" -g root "/home/${account_name}/.ssh"
install -m 600 -o "${account_name}" -g root /opt/huntwarden-acceptance/unknown_ed25519.pub "/home/${account_name}/.ssh/authorized_keys"

printf '*/7 * * * * root /usr/bin/python3 %s >/dev/null 2>&1\n' "${beacon_path}" > "${cron_path}"
chmod 644 "${cron_path}"
printf '17 3 * * * root /usr/bin/find /var/backups -type f -mtime +14 -delete\n' > /etc/cron.d/backup-retention
chmod 644 /etc/cron.d/backup-retention

cp /opt/huntwarden-acceptance/beacon.py "${beacon_path}"
chmod 755 "${beacon_path}"
python3 /opt/huntwarden-acceptance/listener.py &
python3 "${beacon_path}" &

cp /bin/sleep "${deleted_path}"
chmod 755 "${deleted_path}"
"${deleted_path}" 3600 &
deleted_pid=$!
rm -f "${deleted_path}"

auth_time=$(date '+%b %e %H:%M:%S')
printf '%s real-world-target sshd[731]: Accepted publickey for %s from 198.51.100.42 port 48122 ssh2\n' "${auth_time}" "${account_name}" > /var/log/auth.log
printf '%s real-world-target sudo: %s : TTY=pts/2 ; PWD=/var/tmp ; USER=root ; COMMAND=/usr/bin/id\n' "${auth_time}" "${account_name}" >> /var/log/auth.log

python3 - "${scenario_id}" "${account_name}" "${web_root}" "${web_path}" "${beacon_path}" "${deleted_path}" "${cron_path}" "${deleted_pid}" <<'PY'
import json
import sys

keys = ["scenarioId", "account", "webRoot", "webPath", "beaconPath", "deletedPath", "cronPath", "deletedPid"]
values = sys.argv[1:]
payload = dict(zip(keys, values, strict=True))
payload["deletedPid"] = int(payload["deletedPid"])
with open("/run/huntwarden-acceptance.json", "w", encoding="utf-8") as handle:
    json.dump(payload, handle, sort_keys=True)
PY

service cron start
nginx
exec /usr/sbin/sshd -D -e
