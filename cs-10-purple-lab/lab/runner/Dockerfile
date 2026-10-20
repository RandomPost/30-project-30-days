# LAB ONLY: benign adversary-emulation runner. Refuses to run unless PURPLELAB_LAB=1 and targets are allowlisted private hosts.
ARG PYTHON_IMAGE=python:3.13-slim
FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY cs-10-purple-lab ./cs-10-purple-lab
ARG HTTPS_PROXY=
RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then export PIP_CERT=/run/secrets/ca; fi \
 && if [ -z "$HTTPS_PROXY" ]; then unset HTTPS_PROXY https_proxy; fi \
 && pip install ./cs-10-purple-lab
ENV PURPLELAB_LAB=1 PURPLELAB_ALLOWED_HOSTS=target,victim
ENTRYPOINT ["purplelab", "emulate"]
CMD ["--web", "http://target", "--ssh", "victim:22", "--user", "labuser", "--password", "labpass-not-a-secret", \
     "--root-password", "rootpass-not-a-secret", "--log", "/logs/emulation.jsonl", "--allow", "target,victim", "--pause", "1.5"]
