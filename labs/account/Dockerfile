FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server sudo python3 yara ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash secagent && useradd -o -u 0 -g 0 -m -s /bin/bash labroot && mkdir -p /run/sshd /home/secagent/.ssh /home/labroot/.ssh /usr/local/libexec /opt/huntwarden/rules /var/lib/huntwarden/actions && chmod 700 /home/secagent/.ssh /home/labroot/.ssh /var/lib/huntwarden/actions
COPY labs/common/lab_authorized_key.pub /home/secagent/.ssh/authorized_keys
COPY labs/common/unknown_authorized_key.pub /home/labroot/.ssh/authorized_keys
COPY host-helper/huntwarden_helper.py /usr/local/libexec/huntwarden-helper
COPY rules/yara/webshell.yar /opt/huntwarden/rules/webshell.yar
RUN chown -R secagent:secagent /home/secagent/.ssh && chown -R labroot:root /home/labroot/.ssh && chmod 600 /home/secagent/.ssh/authorized_keys /home/labroot/.ssh/authorized_keys && chmod 755 /usr/local/libexec/huntwarden-helper && chown root:root /usr/local/libexec/huntwarden-helper && printf 'secagent ALL=(root) NOPASSWD: /usr/local/libexec/huntwarden-helper *\n' > /etc/sudoers.d/huntwarden && chmod 440 /etc/sudoers.d/huntwarden
RUN mkdir -p /etc/polkit-1/rules.d && printf 'permit nopass labroot as root cmd /usr/bin/id\n' > /etc/doas.conf && printf 'polkit.addRule(function(action, subject) { return polkit.Result.NOT_HANDLED; });\n' > /etc/polkit-1/rules.d/49-huntwarden-lab.rules
CMD ["/bin/bash", "-lc", "ssh-keygen -A && exec /usr/sbin/sshd -D -e"]
