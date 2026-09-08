#!/usr/bin/env bash
set -euo pipefail

process_count="${HUNTWARDEN_LOAD_PROCESS_COUNT:-1000}"
file_count="${HUNTWARDEN_LOAD_FILE_COUNT:-100000}"
log_count="${HUNTWARDEN_LOAD_LOG_COUNT:-100000}"
if [[ ! "$process_count" =~ ^[0-9]+$ ]] || (( process_count < 1 || process_count > 10000 )); then
  echo "HUNTWARDEN_LOAD_PROCESS_COUNT 必须为 1..10000" >&2
  exit 64
fi
if [[ ! "$file_count" =~ ^[0-9]+$ ]] || (( file_count < 1 || file_count > 100000 )); then
  echo "HUNTWARDEN_LOAD_FILE_COUNT 必须为 1..100000" >&2
  exit 64
fi
if [[ ! "$log_count" =~ ^[0-9]+$ ]] || (( log_count < 10000 || log_count > 1000000 )); then
  echo "HUNTWARDEN_LOAD_LOG_COUNT 必须为 10000..1000000" >&2
  exit 64
fi

rm -rf /load/files
mkdir -p /load/files /run
python3 - "$file_count" <<'PY'
import os
import pathlib
import sys

count = int(sys.argv[1])
root = pathlib.Path("/load/files")
for index in range(count):
    directory = root / f"d{index // 1000:03d}"
    if index % 1000 == 0:
        directory.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(directory / f"f{index:06d}.dat", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o640)
    os.close(descriptor)
(root / "fixture-count").write_text(str(count), encoding="ascii")
PY
python3 - "$log_count" <<'PY'
import datetime as dt
import gzip
import os
import pathlib
import sys

count = int(sys.argv[1])
root = pathlib.Path("/var/log")
active = min(2500, count)
rotated_one = min(7500, count - active)
remaining = count - active - rotated_one
counts = [active, rotated_one]
for index in range(18):
    share = remaining // (18 - index)
    counts.append(share)
    remaining -= share

now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
sequence = 0
for rotation, amount in enumerate(counts):
    path = root / ("syslog" if rotation == 0 else f"syslog.{rotation}.gz")
    moment = now - dt.timedelta(minutes=rotation)
    stream_context = path.open("wt", encoding="utf-8") if rotation == 0 else gzip.open(path, "wt", encoding="utf-8")
    with stream_context as stream:
        for local_index in range(amount):
            marker = ""
            if rotation == 0 and local_index == amount - 1:
                marker = " HUNTWARDEN_ACTIVE_SENTINEL"
            if rotation == 1 and local_index == amount - 1:
                marker = " HUNTWARDEN_ROTATED_SENTINEL"
            stream.write(f"{moment.isoformat().replace('+00:00', 'Z')} loadhost loadgen: event={sequence:06d}{marker}\n")
            sequence += 1
    timestamp = now.timestamp() - rotation
    os.utime(path, (timestamp, timestamp))
(pathlib.Path("/run/huntwarden-load-logs.ready")).write_text(str(sequence), encoding="ascii")
PY
printf '%s\n' "$file_count" > /run/huntwarden-load-files.ready
ssh-keygen -A
/usr/sbin/sshd
# 单独放置一个首屏可达的临时目录执行体；其 PID 早于大批量进程夹具，
# 控制端必须在后续进程 Cursor 页完成前建立 Lead 并保全原始映像。
cp /bin/sleep /var/tmp/.huntwarden-load-beacon
chmod 755 /var/tmp/.huntwarden-load-beacon
/var/tmp/.huntwarden-load-beacon 3600 &
exec /usr/local/bin/huntwarden-process-fixture "$process_count"
