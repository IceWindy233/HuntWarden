#!/usr/bin/env bash
set -euo pipefail
ssh-keygen -A
/usr/sbin/sshd
catalina.sh start
for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8080/lab/ >/dev/null 2>&1; then break; fi
  sleep 1
done
# Harmless diskless-class simulation: the already-loaded filter only adds a marker header.
find /usr/local/tomcat/webapps/lab/WEB-INF/classes -name 'DynamicMarkerFilter.class' -delete
exec tail -F /usr/local/tomcat/logs/catalina.out
