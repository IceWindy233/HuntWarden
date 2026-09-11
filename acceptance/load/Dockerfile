FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates gcc libc6-dev openssh-server python3 procps sudo \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash secagent \
    && mkdir -p /run/sshd /home/secagent/.ssh /var/lib/huntwarden/actions \
    && chmod 700 /home/secagent/.ssh /var/lib/huntwarden/actions
COPY acceptance/load/.state/operator_ed25519.pub /home/secagent/.ssh/authorized_keys
COPY host-helper/huntwarden_helper.py /usr/local/libexec/huntwarden-helper
COPY acceptance/load/process-fixture.c /tmp/process-fixture.c
COPY acceptance/load/entrypoint.sh /usr/local/bin/huntwarden-load-entrypoint
RUN gcc -O2 -Wall -Wextra -o /usr/local/bin/huntwarden-process-fixture /tmp/process-fixture.c \
    && rm /tmp/process-fixture.c \
    && chown -R secagent:secagent /home/secagent/.ssh \
    && chmod 600 /home/secagent/.ssh/authorized_keys \
    && chmod 755 /usr/local/libexec/huntwarden-helper /usr/local/bin/huntwarden-load-entrypoint /usr/local/bin/huntwarden-process-fixture \
    && chown root:root /usr/local/libexec/huntwarden-helper \
    && printf 'secagent ALL=(root) NOPASSWD: /usr/local/libexec/huntwarden-helper *\n' > /etc/sudoers.d/huntwarden \
    && chmod 440 /etc/sudoers.d/huntwarden
ENTRYPOINT ["/usr/local/bin/huntwarden-load-entrypoint"]
