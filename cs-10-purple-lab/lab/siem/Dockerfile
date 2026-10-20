# LAB: CS-08 mini SIEM + purplelab (for `purplelab coverage`). Build context is the repo root.
ARG PYTHON_IMAGE=python:3.13-slim
FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY cs-08-minisiem ./cs-08-minisiem
COPY cs-10-purple-lab ./cs-10-purple-lab
# Optional build secret `ca` (CA bundle) for TLS-inspecting proxies; proxy via the standard HTTPS_PROXY build arg.
ARG HTTPS_PROXY=
RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then export PIP_CERT=/run/secrets/ca; fi \
 && if [ -z "$HTTPS_PROXY" ]; then unset HTTPS_PROXY https_proxy; fi \
 && pip install ./cs-08-minisiem ./cs-10-purple-lab
RUN mkdir -p /data /logs /rules /reports
VOLUME ["/data"]
ENTRYPOINT ["minisiem", "schedule", "--db", "/data/siem.db", "--logs", "/logs", "--rules", "/rules", "--interval", "5"]
