FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server sudo python3 ca-certificates cron gcc libc6-dev libcap2-bin && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash secagent && useradd -m -s /bin/bash iruser && mkdir -p /run/sshd /home/secagent/.ssh /home/iruser/.ssh /usr/local/libexec /var/lib/huntwarden/actions /opt/huntwarden-lab && chmod 700 /home/secagent/.ssh /home/iruser/.ssh /var/lib/huntwarden/actions
COPY labs/common/lab_authorized_key.pub /home/secagent/.ssh/authorized_keys
COPY labs/common/unknown_authorized_key.pub /home/iruser/.ssh/authorized_keys
COPY host-helper/huntwarden_helper.py /usr/local/libexec/huntwarden-helper
COPY labs/linux-ir/entrypoint.sh /opt/huntwarden-lab/entrypoint.sh
COPY labs/linux-ir/listener.py /opt/huntwarden-lab/listener.py
COPY labs/linux-ir/suspicious_client.py /tmp/.update
COPY labs/linux-ir/preload.c /opt/huntwarden-lab/preload.c
COPY labs/linux-ir/suspicious.cron /etc/cron.d/huntwarden-ir
COPY labs/linux-ir/normal-maintenance.sh /usr/local/sbin/huntwarden-normal-maintenance
RUN gcc -shared -fPIC -o /opt/huntwarden-lab/libpreload.so /opt/huntwarden-lab/preload.c && printf '/opt/huntwarden-lab/libpreload.so\n' > /etc/ld.so.preload && cp /bin/sleep /tmp/.cache-worker && printf '\0' >> /usr/bin/yes && chown -R secagent:secagent /home/secagent/.ssh && chown -R iruser:iruser /home/iruser && chmod 600 /home/secagent/.ssh/authorized_keys /home/iruser/.ssh/authorized_keys && chmod 755 /usr/local/libexec/huntwarden-helper /opt/huntwarden-lab/entrypoint.sh /opt/huntwarden-lab/listener.py /tmp/.update /usr/local/sbin/huntwarden-normal-maintenance && chmod 644 /etc/cron.d/huntwarden-ir && chown root:root /usr/local/libexec/huntwarden-helper /opt/huntwarden-lab/libpreload.so && printf 'secagent ALL=(root) NOPASSWD: /usr/local/libexec/huntwarden-helper *\n' > /etc/sudoers.d/huntwarden && chmod 440 /etc/sudoers.d/huntwarden && printf 'Aug  9 10:00:00 lab-linux-ir sshd[120]: Accepted publickey for iruser from 192.0.2.45 port 43210 ssh2\nAug  9 10:02:00 lab-linux-ir sudo: iruser : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/id\nAug  9 10:03:00 lab-linux-ir sshd[120]: Failed publickey for invalid user admin from 198.51.100.22 port 50000 ssh2\n' > /var/log/auth.log
ENTRYPOINT ["/opt/huntwarden-lab/entrypoint.sh"]
