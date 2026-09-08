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
RUN set -eux; \
    spring_version=5.3.39; \
    spring_lib=/usr/local/tomcat/webapps/lab/WEB-INF/lib; \
    mkdir -p "$spring_lib"; \
    for spec in \
      spring-aop:aa706e4f749982c0bae5fa637433c44c24f0fff5d16dc41deea6d30c3dfa7c85 \
      spring-beans:b6697a5d8facb81aa75e5a46d959d4256da9ce3b40d33f3b5bbd42a8b1ed5722 \
      spring-context:9e644fc33bece9a9cb82538167a1b9640ae7b7d80252e893d89b8926a2f81633 \
      spring-core:3a1ddcf05420a9181bd9cacb6062a3edc493e14d555961ad50e1a6360eb1e75f \
      spring-expression:d5337774d889fcdc9c08b0c8b8aaa1018d4c95b9b441db0118f7ae4d328f2810 \
      spring-jcl:adbe656fc622e2457fefa09529d4b7c1126a3c4ff1c9306907764fcc93f1b725 \
      spring-web:444f243b936119b5488029f2d9399a3980855c60b493b9e2811464c6433a2b71 \
      spring-webmvc:1ad8a2ba468c07024ba63cb7681bb30a2ecf8d91124f00fdb4a3d184131b87ed; do \
      artifact="${spec%%:*}"; \
      expected="${spec#*:}"; \
      target="$spring_lib/$artifact-$spring_version.jar"; \
      curl -fsSL "https://repo.maven.apache.org/maven2/org/springframework/$artifact/$spring_version/$artifact-$spring_version.jar" -o "$target"; \
      echo "$expected  $target" | sha256sum -c -; \
    done; \
    javac -cp "/usr/local/tomcat/lib/servlet-api.jar:/usr/local/tomcat/lib/websocket-api.jar:$spring_lib/*" -d /usr/local/tomcat/webapps/lab/WEB-INF/classes /tmp/labsrc/*.java; \
    chown -R secagent:secagent /home/secagent/.ssh; \
    chmod 600 /home/secagent/.ssh/authorized_keys; \
    chmod 755 /usr/local/libexec/huntwarden-helper; \
    chown root:root /usr/local/libexec/huntwarden-helper /opt/huntwarden/huntwarden-tomcat-probe.jar; \
    printf 'secagent ALL=(root) NOPASSWD: /usr/local/libexec/huntwarden-helper *\n' > /etc/sudoers.d/huntwarden; \
    chmod 440 /etc/sudoers.d/huntwarden
COPY labs/tomcat/entrypoint.sh /usr/local/bin/huntwarden-lab-entrypoint
RUN chmod 755 /usr/local/bin/huntwarden-lab-entrypoint
CMD ["/usr/local/bin/huntwarden-lab-entrypoint"]
