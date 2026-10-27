# FRR routers with sshd and lldpd (Ubuntu 24.04, FRR 8.4.x) so lldpmap can log in over SSH
# and read LLDP neighbours. The lab password is a build argument from the environment.
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:24.04
FROM ${UBUNTU_IMAGE}

ARG LAB_SSH_PASSWORD
ARG LAB_SSH_USER=netops
ARG APT_PROXY=
RUN test -n "$LAB_SSH_PASSWORD" || (echo "set LAB_SSH_PASSWORD to build" >&2; exit 1)
RUN if [ -n "$APT_PROXY" ]; then echo "Acquire::http::Proxy \"$APT_PROXY\";" > /etc/apt/apt.conf.d/99proxy; fi \
 && apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      frr openssh-server lldpd iproute2 iputils-ping \
 && rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/99proxy \
 && useradd -m -s /bin/bash -G frrvty,_lldpd "$LAB_SSH_USER" \
 && echo "$LAB_SSH_USER:$LAB_SSH_PASSWORD" | chpasswd \
 && mkdir -p /run/sshd

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
