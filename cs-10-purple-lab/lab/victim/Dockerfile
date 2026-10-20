# LAB ONLY: intentionally weak SSH victim (known passwords, root login). Runs on the internal labnet only.
ARG UBUNTU_IMAGE=ubuntu:24.04
FROM ${UBUNTU_IMAGE}
ARG APT_PROXY=
ARG LAB_USER_PASSWORD=labpass-not-a-secret
ARG LAB_ROOT_PASSWORD=rootpass-not-a-secret
ENV DEBIAN_FRONTEND=noninteractive
# Optional build secret `ca` + build arg APT_PROXY: lets apt work behind a TLS-inspecting proxy.
# Neither is needed in a normal environment, and nothing is left in the image.
RUN --mount=type=secret,id=ca,required=false \
    if [ -n "$APT_PROXY" ] && [ -s /run/secrets/ca ]; then \
      install -m 0644 /run/secrets/ca /tmp/apt-ca.crt; \
      printf 'Acquire::http::Proxy "%s";\nAcquire::https::Proxy "%s";\nAcquire::https::CaInfo "/tmp/apt-ca.crt";\n' \
        "$APT_PROXY" "$APT_PROXY" > /etc/apt/apt.conf.d/99proxy; \
      sed -i 's|http://|https://|g' /etc/apt/sources.list.d/ubuntu.sources; \
    fi \
 && apt-get update \
 && apt-get install -y --no-install-recommends openssh-server rsyslog cron sudo iproute2 procps passwd bsdutils \
 && rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/99proxy /tmp/apt-ca.crt
# containers have no audit loginuid; do not let pam_loginuid refuse logins
RUN sed -i 's/^\(session\s*required\s*pam_loginuid.so\)/session optional pam_loginuid.so # \1/' /etc/pam.d/sshd \
 && useradd -m -s /bin/bash labuser \
 && echo "labuser:${LAB_USER_PASSWORD}" | chpasswd \
 && echo "root:${LAB_ROOT_PASSWORD}" | chpasswd \
 && mkdir -p /logs /run/sshd
COPY rsyslog.conf /etc/rsyslog.conf
COPY sshd_config /etc/ssh/sshd_config
COPY audit-shell /usr/local/bin/audit-shell
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/audit-shell /usr/local/bin/entrypoint.sh
EXPOSE 22
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=10 \
    CMD ss -ltn | grep -q ':22 '
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
