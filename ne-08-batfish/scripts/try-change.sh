#!/bin/sh
# Apply a proposed change (a patch from changes/) to a scratch copy of the network
# and run the policy suite against it. The real files are not touched.
#   scripts/try-change.sh changes/bad-guest-acl-reordered.patch
set -e
here=$(cd "$(dirname "$0")/.." && pwd)
patch_file=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
work=$(mktemp -d)
mkdir -p "$work/ne-08-batfish/network" "$work/ne-05-netgen/data"
cp -r "$here/network/overlay" "$work/ne-08-batfish/network/"
cp "$here/../ne-05-netgen/data/sites.yml" "$work/ne-05-netgen/data/"
patch -s -p1 -d "$work" < "$patch_file"
echo "== applying $(basename "$patch_file") and running the policy suite"
cd "$here"
NETCHECK_SOURCE="$work/ne-05-netgen/data/sites.yml" \
NETCHECK_OVERLAY="$work/ne-08-batfish/network/overlay" \
  python3 -m pytest -q tests/test_policies.py 
