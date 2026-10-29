#!/bin/sh
# Bring the BGP lab up or down. Run from anywhere. DESIGN=a|b picks the policy design.
cd "$(dirname "$0")/.."
CLAB=${CLAB:-containerlab}
# Behind the sandbox proxy Docker Hub is rate limited; mirror.gcr.io has the same images.
if [ -n "${HTTPS_PROXY:-}" ]; then
  export FRR_IMAGE=${FRR_IMAGE:-mirror.gcr.io/frrouting/frr:v8.4.1}
  export PY_IMAGE=${PY_IMAGE:-mirror.gcr.io/library/python:3.13-slim}
fi
case "${1:-up}" in
  up)   $CLAB deploy -t bgp-lab.clab.yml --reconfigure ;;
  down) $CLAB destroy -t bgp-lab.clab.yml --cleanup ;;
esac
