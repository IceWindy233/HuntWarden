FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates cron iproute2 nginx openssh-server procps python3 sudo yara \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash secagent \
    && mkdir -p /run/sshd /home/secagent/.ssh /usr/local/libexec \
      /var/lib/huntwarden/actions /opt/huntwarden/rules /opt/huntwarden-acceptance \
    && chmod 700 /home/secagent/.ssh /var/lib/huntwarden/actions

COPY acceptance/real-world/.state/operator_ed25519.pub /home/secagent/.ssh/authorized_keys
COPY acceptance/real-world/.state/unknown_ed25519.pub /opt/huntwarden-acceptance/unknown_ed25519.pub
COPY acceptance/real-world/entrypoint.sh /opt/huntwarden-acceptance/entrypoint.sh
COPY acceptance/real-world/listener.py /opt/huntwarden-acceptance/listener.py
COPY acceptance/real-world/beacon.py /opt/huntwarden-acceptance/beacon.py
COPY host-helper/huntwarden_helper.py /usr/local/libexec/huntwarden-helper
COPY rules/yara/webshell.yar /opt/huntwarden/rules/webshell.yar

RUN chown -R secagent:secagent /home/secagent/.ssh \
    && chmod 600 /home/secagent/.ssh/authorized_keys \
    && chmod 755 /usr/local/libexec/huntwarden-helper \
      /opt/huntwarden-acceptance/entrypoint.sh \
      /opt/huntwarden-acceptance/listener.py \
      /opt/huntwarden-acceptance/beacon.py \
    && chown root:root /usr/local/libexec/huntwarden-helper \
    && printf 'secagent ALL=(root) NOPASSWD: /usr/local/libexec/huntwarden-helper *\n' > /etc/sudoers.d/huntwarden \
    && chmod 440 /etc/sudoers.d/huntwarden

ENTRYPOINT ["/opt/huntwarden-acceptance/entrypoint.sh"]
