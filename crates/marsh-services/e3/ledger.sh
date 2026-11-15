#!/usr/bin/env bash
# A ledger that cannot be written must refuse new objects and leave none behind
# (the agent could not remember them after a restart); it recovers when writes work.
source "$(dirname "$0")/lib.sh"
S=${1:-base}
# A directory where the ledger's lock file belongs makes every write fail (the
# temporary file's name is unique per writer, so it cannot be blocked).
LOCK=/pool/marsh/ledger.lock
cleanup() { vx rmdir $LOCK >/dev/null 2>&1; dk $S docker rm -f led-ok led-bad led-after >/dev/null 2>&1; dk $S docker network rm led-net-bad led-net-after >/dev/null 2>&1; dk $S docker volume rm led-vol-bad led-vol-after >/dev/null 2>&1; }
cleanup
expect allowed "baseline: a create works" -- dk $S docker run -d --name led-ok busybox sleep 120
vx rm -f $LOCK
vx mkdir $LOCK
expect refused "create while the ledger cannot be written" -- dk $S docker run -d --name led-bad busybox sleep 120
want "ground truth: the refused create left no container in the engine" "$(prod ps -a --format '{{.Names}}' | grep -c '^led-bad$' || true)" 0
expect refused "network create while the ledger cannot be written" -- dk $S docker network create led-net-bad
want "ground truth: no network was left" "$(prod network ls --format '{{.Name}}' | grep -c '^led-net-bad$' || true)" 0
expect refused "volume create while the ledger cannot be written" -- dk $S docker volume create led-vol-bad
want "ground truth: no volume was left" "$(prod volume ls -q | grep -c '^led-vol-bad$' || true)" 0
expect allowed "reads still work while degraded" -- dk $S docker ps
vx rmdir $LOCK
expect allowed "once writes work again, creates resume" -- dk $S docker run -d --name led-after busybox sleep 120
expect allowed "...and so do networks and volumes" -- dk $S docker network create led-net-after
cleanup
summary
