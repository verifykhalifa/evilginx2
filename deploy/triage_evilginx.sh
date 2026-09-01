#!/usr/bin/env bash
# triage_evilginx.sh — find out WHY evilginx died/stopped.
# Run as root:  sudo ./triage_evilginx.sh
# Reads journald (which persists across crashes AND reboots once the
# journald-triage.conf drop-in is installed).
set -uo pipefail

echo "===== 1. Is the service running? ====="
systemctl status evilginx.service --no-pager 2>&1 | head -20
echo ""

echo "===== 2. Last 40 journal lines (crash context) ====="
journalctl -u evilginx.service -n 40 --no-pager 2>&1 | tail -40
echo ""

echo "===== 3. OOM-kill evidence (kernel killer) ====="
dmesg 2>/dev/null | grep -iE 'killed process|out of memory|oom' | tail -10 || echo "  (dmesg unavailable or no OOM records — run as root)"
echo ""

echo "===== 4. Go panic evidence ====="
journalctl -u evilginx.service --no-pager 2>&1 | grep -iE 'panic:|goroutine|runtime error|fatal error' | tail -15 || echo "  (no panics in journal)"
echo ""

echo "===== 5. Signal / exit-code evidence ====="
journalctl -u evilginx.service --no-pager 2>&1 | grep -iE 'signal|exit code|Main process exited|killed' | tail -15 || echo "  (none)"
echo ""

echo "===== 6. Restart history (how many times it has bounced) ====="
systemctl show evilginx.service -p NRestarts -p ActiveEnterTimestamp -p ExecMainStartTimestamp 2>/dev/null || true
echo ""

echo "===== 7. Memory footprint now vs. limits ====="
systemctl show evilginx.service -p MemoryCurrent -p MemoryHigh -p MemoryMax 2>/dev/null || true
echo ""

echo "===== 8. Port bindings (should be 80/443/53/5050) ====="
ss -tulnp 2>/dev/null | grep -E ':(80|443|53|5050)\b' || echo "  (nothing bound — service is down)"
