#!/bin/sh
# Build the FRR image with sshd and lldpd and bring up the NE-04 lab with it (or tear it down).
#   export LAB_SSH_PASSWORD=...   # any throwaway value; needed to build the image
#   scripts/lab.sh up | down
set -e
cd "$(dirname "$0")/.."
LAB=../ne-04-ospf-lab
IMAGE=lldpmap-frr:lab
CLAB=${CLAB:-containerlab}

case "${1:-up}" in
  up)
    : "${LAB_SSH_PASSWORD:?export LAB_SSH_PASSWORD first (any throwaway value)}"
    set --
    # Behind a TLS-inspecting sandbox proxy, apt and the mirrored base image differ.
    if [ -n "${HTTPS_PROXY:-}" ]; then
      set -- --network host --build-arg UBUNTU_IMAGE=mirror.gcr.io/library/ubuntu:24.04
      [ -n "${HTTP_PROXY:-}" ] && set -- "$@" --build-arg "APT_PROXY=$HTTP_PROXY"
    fi
    docker build -q "$@" --build-arg LAB_SSH_PASSWORD -t "$IMAGE" lab
    make -C "$LAB" up CLAB="$CLAB" FRR_IMAGE="$IMAGE" ${HOST_IMAGE:+HOST_IMAGE="$HOST_IMAGE"}
    ;;
  down)
    make -C "$LAB" down CLAB="$CLAB"
    ;;
esac
