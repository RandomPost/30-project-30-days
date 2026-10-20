#!/usr/bin/env bash
# Purple-team lab driver (LAB ONLY).  ./run-lab.sh [up|down]   (default: up)
#   up   : build, start victim+target+siem, run the attack profile, wait for the SIEM, write the coverage report
#   down : stop everything and remove volumes (logs, SIEM db)
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME=purplelab
dc() { docker compose "$@"; }

# Behind a TLS-inspecting proxy (sandbox): route builds through it. Not needed in a normal environment.
CA=/root/.ccr/ca-bundle.crt
if [ -n "${HTTPS_PROXY:-}" ] && [ -f "$CA" ]; then
  export LAB_CA="$CA" APT_PROXY="$HTTPS_PROXY" BUILD_NETWORK=host
  export UBUNTU_IMAGE="${UBUNTU_IMAGE:-mirror.gcr.io/library/ubuntu:24.04}"
  export PYTHON_IMAGE="${PYTHON_IMAGE:-mirror.gcr.io/library/python:3.13-slim}"
  export NGINX_IMAGE="${NGINX_IMAGE:-mirror.gcr.io/library/nginx:alpine}"
fi

case "${1:-up}" in
  down)
    dc --profile attack down -v --remove-orphans
    ;;
  up)
    mkdir -p reports
    dc build
    dc up -d --wait victim target siem
    echo "== attack =="
    dc --profile attack run --rm runner
    echo "== waiting for the SIEM to tick =="
    sleep 12
    dc exec -T siem purplelab coverage --db /data/siem.db --emulation /logs/emulation.jsonl \
      --rules /rules --md /reports/coverage.md --json /reports/coverage.json
    echo "report: $PWD/reports/coverage.md (and coverage.json)"
    ;;
  *) echo "usage: $0 [up|down]" >&2; exit 2 ;;
esac
