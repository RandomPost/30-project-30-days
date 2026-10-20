# Low-interaction SSH honeypot. Runs as an unprivileged user and needs no capabilities.
# Run it read-only with all capabilities dropped (see docker-compose.yml).
ARG BASE_IMAGE=python:3.13-slim
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system --gid 10001 sshpot \
 && useradd --system --uid 10001 --gid 10001 --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin sshpot

WORKDIR /app
COPY pyproject.toml ./
COPY sshpot ./sshpot
# An optional build secret `ca` (a CA bundle) lets the build run behind a TLS-inspecting
# proxy without baking the certificate into the image.
RUN --mount=type=secret,id=ca,required=false \
    if [ -f /run/secrets/ca ]; then export PIP_CERT=/run/secrets/ca; fi \
 && pip install . \
 && install -d -o 10001 -g 10001 -m 0700 /data

USER 10001:10001
ENV SSHPOT_PORT=2222 \
    SSHPOT_QUIET_LOOPBACK=1

VOLUME ["/data"]
EXPOSE 2222
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["sshpot", "healthcheck"]

ENTRYPOINT ["sshpot"]
CMD ["serve", "--log", "/data/sshpot.jsonl", "--host-key", "/data/ssh_host_key"]
