FROM tomcat:9.0-jdk17-temurin-jammy
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server sudo python3 yara ca-certificates procps passwd curl && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash secagent && mkdir -p /run/sshd /home/secagent/.ssh /usr/local/libexec /opt/huntwarden/rules /var/lib/huntwarden/actions /tmp/labclasses /usr/local/tomcat/webapps/lab/WEB-INF/classes /usr/local/tomcat/webapps/lab/WEB-INF && chmod 700 /home/secagent/.ssh /var/lib/huntwarden/actions
COPY labs/common/lab_authorized_key.pub /home/secagent/.ssh/authorized_keys
COPY host-helper/huntwarden_helper.py /usr/local/libexec/huntwarden-helper
COPY rules/yara/webshell.yar /opt/huntwarden/rules/webshell.yar
COPY java/tomcat-probe/build/libs/huntwarden-tomcat-probe.jar /opt/huntwarden/huntwarden-tomcat-probe.jar
COPY labs/tomcat/src/ /tmp/labsrc/
COPY labs/tomcat/web.xml /usr/local/tomcat/webapps/lab/WEB-INF/web.xml
COPY labs/tomcat/index.html /usr/local/tomcat/webapps/lab/index.html
RUN javac -cp /usr/local/tomcat/lib/servlet-api.jar -d /usr/local/tomcat/webapps/lab/WEB-INF/classes /tmp/labsrc/*.java && chown -R secagent:secagent /home/secagent/.ssh && chmod 600 /home/secagent/.ssh/authorized_keys && chmod 755 /usr/local/libexec/huntwarden-helper && chown root:root /usr/local/libexec/huntwarden-helper /opt/huntwarden/huntwarden-tomcat-probe.jar && printf 'secagent ALL=(root) NOPASSWD: /usr/local/libexec/huntwarden-helper *\n' > /etc/sudoers.d/huntwarden && chmod 440 /etc/sudoers.d/huntwarden
COPY labs/tomcat/entrypoint.sh /usr/local/bin/huntwarden-lab-entrypoint
RUN chmod 755 /usr/local/bin/huntwarden-lab-entrypoint
CMD ["/usr/local/bin/huntwarden-lab-entrypoint"]
