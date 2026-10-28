#!/bin/sh
# Run the policy suite on the current network and on every proposed change.
cd "$(dirname "$0")/.."
echo "### current network"; python3 -m pytest -q tests/ 2>&1 | tail -3
for c in changes/*.patch; do
  echo; echo "### $c"
  grep '^[+-][^+-]' "$c" | sed 's/^/    /'
  scripts/try-change.sh "$c" 2>&1 | grep -E "^(E  +[A-Za-z]|FAILED|[0-9]+ (passed|failed))" | cut -c1-220
done
