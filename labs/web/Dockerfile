FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server sudo python3 yara nginx ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash secagent && mkdir -p /run/sshd /home/secagent/.ssh /usr/local/libexec /opt/huntwarden/rules /var/lib/huntwarden/actions && chmod 700 /home/secagent/.ssh /var/lib/huntwarden/actions
COPY labs/common/lab_authorized_key.pub /home/secagent/.ssh/authorized_keys
COPY host-helper/huntwarden_helper.py /usr/local/libexec/huntwarden-helper
COPY rules/yara/webshell.yar /opt/huntwarden/rules/webshell.yar
COPY labs/web/fixtures/ /var/www/html/
COPY labs/web/alternate-app/ /srv/alternate-app/
COPY labs/web/huntwarden-lab.conf /etc/nginx/conf.d/huntwarden-lab.conf
RUN chown -R secagent:secagent /home/secagent/.ssh && chmod 600 /home/secagent/.ssh/authorized_keys && chmod 755 /usr/local/libexec/huntwarden-helper && chown root:root /usr/local/libexec/huntwarden-helper && printf 'secagent ALL=(root) NOPASSWD: /usr/local/libexec/huntwarden-helper *\n' > /etc/sudoers.d/huntwarden && chmod 440 /etc/sudoers.d/huntwarden && printf '192.0.2.44 - - [09/Aug/2026:10:20:00 +0000] "POST /uploads/lab-upload.php HTTP/1.1" 200 42 "-" "HuntWarden-Lab"\n192.0.2.44 - - [09/Aug/2026:10:20:03 +0000] "GET /uploads/lab-upload.php?cmd=id HTTP/1.1" 200 42 "-" "HuntWarden-Lab"\n' > /var/log/nginx/access.log
CMD ["/bin/bash", "-lc", "ssh-keygen -A && nginx && exec /usr/sbin/sshd -D -e"]
