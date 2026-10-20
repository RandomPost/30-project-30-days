#!/usr/bin/env bash
# Build the image, run it hardened, prove the hardening holds, then run a scripted
# attacker through it and summarize the resulting log.
#
#   scripts/verify-hardening.sh
#
# Env: PORT (default 2222), BASE_IMAGE (build arg), BUILD_CA (CA bundle file, for builds
# behind a TLS-inspecting proxy), BUILD_ARGS (extra docker build args, e.g.
# --network=host), RUN_NET (docker run network args, default publishes
# 127.0.0.1:$PORT). DOCKER_HOST is honored as usual.
set -euo pipefail

cd "$(dirname "$0")/.."
PORT="${PORT:-2222}"
NAME="sshpot-verify-$$"
VOL="sshpot-verify-data-$$"
RUN_NET="${RUN_NET:--p 127.0.0.1:${PORT}:2222}"
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok:   $*"; }

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; docker volume rm "$VOL" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# shellcheck disable=SC2086
DOCKER_BUILDKIT=1 docker build ${BUILD_ARGS:-} ${BUILD_CA:+--secret id=ca,src=$BUILD_CA} ${BASE_IMAGE:+--build-arg BASE_IMAGE=$BASE_IMAGE} -t sshpot:verify . >/dev/null
ok "image built"

# shellcheck disable=SC2086
docker run -d --name "$NAME" $RUN_NET \
    --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --pids-limit 128 --memory 256m --user 10001:10001 \
    --tmpfs /tmp:size=16m,noexec,nosuid,nodev -v "$VOL":/data \
    -e SSHPOT_QUIET_LOOPBACK=0 -e SSHPOT_PORT="$PORT" \
    sshpot:verify serve --log /data/sshpot.jsonl --host-key /data/ssh_host_key >/dev/null
for _ in $(seq 1 30); do
    docker exec "$NAME" sshpot healthcheck 2>/dev/null && break
    sleep 0.5
done
docker exec "$NAME" sshpot healthcheck || fail "honeypot did not start"; ok "honeypot answers with an SSH banner"

insp() { docker inspect -f "$1" "$NAME"; }
[ "$(insp '{{.HostConfig.ReadonlyRootfs}}')" = true ] || fail "root fs is not read-only"; ok "read-only root filesystem"
[ "$(insp '{{.HostConfig.CapDrop}}')" = "[ALL]" ] || fail "capabilities not dropped"; ok "capabilities dropped (ALL)"
insp '{{.HostConfig.SecurityOpt}}' | grep -q no-new-privileges || fail "no-new-privileges missing"; ok "no-new-privileges"
[ "$(insp '{{.Config.User}}')" = "10001:10001" ] || fail "not running as 10001"; ok "non-root user 10001"

[ "$(docker exec "$NAME" id -u)" = 10001 ] || fail "process uid is not 10001"
capeff="$(docker exec "$NAME" sh -c "grep CapEff /proc/self/status | awk '{print \$2}'")"
[ "$capeff" = 0000000000000000 ] || fail "effective capabilities not empty: $capeff"; ok "effective capability set is empty"
docker exec "$NAME" sh -c 'touch /app/x 2>/dev/null' && fail "could write to /app" || ok "cannot write to /app"
docker exec "$NAME" sh -c 'touch /etc/x 2>/dev/null' && fail "could write to /etc" || ok "cannot write to /etc"
docker exec "$NAME" sh -c 'touch /data/x' || fail "cannot write to /data"; ok "can write to /data only"
docker exec "$NAME" sh -c 'touch /tmp/x && echo "#!/bin/sh" > /tmp/x && chmod +x /tmp/x && /tmp/x' 2>/dev/null && fail "could execute from /tmp" || ok "cannot execute from /tmp (noexec)"

# attack it over real SSH from the host (needs the sshpot package installed here)
sshpot simulate --port "$PORT" >/tmp/sshpot-sim.json || fail "simulated attack failed"
ok "scripted attacker finished: $(cat /tmp/sshpot-sim.json)"
sleep 1
docker exec "$NAME" cat /data/sshpot.jsonl > /tmp/sshpot-verify.jsonl
grep -q '"event":"command"' /tmp/sshpot-verify.jsonl || fail "no commands in the log"
ok "log written inside the container ($(wc -l < /tmp/sshpot-verify.jsonl) events)"
[ "$(docker exec "$NAME" ls /data | grep -c ssh_host_key)" -ge 1 ] || fail "host key not persisted"; ok "host key persisted to /data"
sshpot analyze /tmp/sshpot-verify.jsonl --top 5
echo "All hardening checks passed."
