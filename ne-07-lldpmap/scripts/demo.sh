#!/bin/sh
# Crawl the NE-04 lab from r1, break the r1-r3 link, crawl again, diff the two runs.
# Needs the lab up (scripts/lab.sh up) and LLDPMAP_USER / LLDPMAP_PASSWORD set.
cd "$(dirname "$0")/.."
OUT=${OUT:-runs}
mkdir -p "$OUT"
SEED=${SEED:-clab-ospf-r1}
TPL='clab-ospf-{name}'
run() { printf '\n$ %s\n' "$*"; "$@"; rc=$?; echo "(exit $rc)"; return 0; }

run python3 -m lldpmap crawl "$SEED" --name-template "$TPL" -o "$OUT/before.json" --html "$OUT/before.html"
grep -q '"crawled": true' "$OUT/before.json" || { echo "crawl found nothing; is the lab up?" >&2; exit 1; }

printf '\n$ docker exec clab-ospf-r1 ip link set eth2 down   # pull the r1-r3 cable\n'
docker exec clab-ospf-r1 ip link set eth2 down
sleep 6   # lldpd drops a neighbour as soon as the link goes down; wait for the dust to settle

run python3 -m lldpmap crawl "$SEED" --name-template "$TPL" -o "$OUT/after.json" --html "$OUT/after.html"
run python3 -m lldpmap diff "$OUT/before.json" "$OUT/after.json" --html "$OUT/diff.html"

printf '\n$ docker exec clab-ospf-r1 ip link set eth2 up   # cable back\n'
docker exec clab-ospf-r1 ip link set eth2 up
