FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server sudo python3 ca-certificates cron && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash secagent && useradd -m -s /bin/bash persistuser && mkdir -p /run/sshd /home/secagent/.ssh /home/persistuser/.ssh /usr/local/libexec /var/lib/huntwarden/actions /opt/huntwarden-lab /etc/systemd/system/multi-user.target.wants && chmod 700 /home/secagent/.ssh /home/persistuser/.ssh /var/lib/huntwarden/actions
COPY labs/common/lab_authorized_key.pub /home/secagent/.ssh/authorized_keys
COPY labs/common/unknown_authorized_key.pub /home/persistuser/.ssh/authorized_keys
COPY host-helper/huntwarden_helper.py /usr/local/libexec/huntwarden-helper
COPY labs/persistence/listener.py /opt/huntwarden-lab/listener.py
COPY labs/persistence/huntwarden-lab.service /etc/systemd/system/huntwarden-lab.service
COPY labs/persistence/normal-maintenance.service /etc/systemd/system/normal-maintenance.service
COPY labs/persistence/huntwarden-lab.cron /etc/cron.d/huntwarden-lab
COPY labs/persistence/normal-maintenance.cron /etc/cron.d/normal-maintenance
COPY labs/persistence/persistuser.bashrc /home/persistuser/.bashrc
RUN ln -s /etc/systemd/system/huntwarden-lab.service /etc/systemd/system/multi-user.target.wants/huntwarden-lab.service && chown -R secagent:secagent /home/secagent/.ssh && chown -R persistuser:persistuser /home/persistuser && chmod 600 /home/secagent/.ssh/authorized_keys /home/persistuser/.ssh/authorized_keys && chmod 644 /etc/cron.d/huntwarden-lab /etc/cron.d/normal-maintenance /etc/systemd/system/*.service && chmod 755 /usr/local/libexec/huntwarden-helper /opt/huntwarden-lab/listener.py && chown root:root /usr/local/libexec/huntwarden-helper /opt/huntwarden-lab/listener.py && printf 'secagent ALL=(root) NOPASSWD: /usr/local/libexec/huntwarden-helper *\n' > /etc/sudoers.d/huntwarden && chmod 440 /etc/sudoers.d/huntwarden
CMD ["/bin/bash", "-lc", "ssh-keygen -A && python3 /opt/huntwarden-lab/listener.py & exec /usr/sbin/sshd -D -e"]
