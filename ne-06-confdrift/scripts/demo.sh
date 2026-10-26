#!/bin/sh
# Demonstrate: manual change on a lab router -> drift report -> git diff of the backup.
# Needs the lab up (scripts/lab.sh up) and CONFDRIFT_USER / CONFDRIFT_PASSWORD set.
cd "$(dirname "$0")/.."
export PYTHONUNBUFFERED=1
rm -rf backups
python3 -m confdrift drift >/dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "lab not reachable or already drifted: run scripts/lab.sh up and check CONFDRIFT_* first" >&2
  exit 1
fi
say() { printf '\n$ %s\n' "$*"; }
run() { say "$*"; "$@"; echo "(exit $?)"; }

run python3 -m confdrift drift
run python3 -m confdrift backup

# Someone logs in to r1 and "just quickly" changes the cost of the r1-r3 link.
say "ssh netops@r1: interface eth2 / ip ospf cost 100"
python3 - <<'PY'
import os
from netmiko import ConnectHandler
with ConnectHandler(device_type="linux", host="clab-ospf-r1",
                    username=os.environ["CONFDRIFT_USER"],
                    password=os.environ["CONFDRIFT_PASSWORD"]) as c:
    c.send_command("vtysh -c 'configure terminal' -c 'interface eth2' -c 'ip ospf cost 100'")
PY

run python3 -m confdrift drift
run python3 -m confdrift backup
say "git -C backups log --stat"
git -C backups log --stat --format='commit %h%n    %s%n%b'
say "git -C backups diff HEAD~1 HEAD"
git -C backups diff HEAD~1 HEAD

# Put it back, and the drift disappears.
python3 - <<'PY'
import os
from netmiko import ConnectHandler
with ConnectHandler(device_type="linux", host="clab-ospf-r1",
                    username=os.environ["CONFDRIFT_USER"],
                    password=os.environ["CONFDRIFT_PASSWORD"]) as c:
    c.send_command("vtysh -c 'configure terminal' -c 'interface eth2' -c 'ip ospf cost 10'")
PY
say "(change reverted on r1)"
run python3 -m confdrift drift
run python3 -m confdrift backup
run python3 -m confdrift log r1
