#!/usr/bin/env bash
# install_evilginx_service.sh — install evilginx2 as a systemd service.
# Usage:  sudo ./install_evilginx_service.sh [PROJECT_DIR] [RUN_USER] [CFG_DIR]
#
#   PROJECT_DIR  - dir containing the evilginx binary + phishlets/
#                  default: /root/evilginx2          (VPS layout)
#                  dev box example: /home/ubuntu/evilginx2-master
#   RUN_USER     - OS user to run the service as (owns ~/.evilginx config).
#                  default: auto-detected as the owner of PROJECT_DIR.
#   CFG_DIR      - evilginx config dir (lures, domain, data.db live here).
#                  default: ~<RUN_USER>/.evilginx
#
# What this does:
#   1. Stops and kills ANY existing tmux/screen/manual evilginx instance
#      (so the new systemd one is the only listener — no port conflicts).
#   2. Writes /etc/systemd/system/evilginx.service from the template.
#   3. Enables it to start on boot and starts it now.
#   4. Prints the current status + the crash log tail.
set -euo pipefail

PROJECT_DIR="${1:-/root/evilginx2}"
TEMPLATE="$(dirname "$(readlink -f "$0")")/evilginx.service.tpl"
UNIT=/etc/systemd/system/evilginx.service

if [ ! -f "$PROJECT_DIR/evilginx" ]; then
  echo "ERROR: no binary at $PROJECT_DIR/evilginx" >&2
  echo "Pass the right path: sudo $0 /path/to/evilginx2" >&2
  exit 1
fi

# --- Auto-detect the user that owns the project (and thus the config) -------
if [ -n "${2:-}" ]; then
  RUN_USER="$2"
else
  RUN_USER="$(stat -c '%U' "$PROJECT_DIR" 2>/dev/null || stat -f '%Su' "$PROJECT_DIR" 2>/dev/null || echo root)"
fi

# --- Resolve the config dir ------------------------------------------------
if [ -n "${3:-}" ]; then
  CFG_DIR="$3"
else
  # Prefer an existing .evilginx under the run user's home
  HOME_DIR="$(getent passwd "$RUN_USER" 2>/dev/null | cut -d: -f6 || echo "/home/$RUN_USER")"
  CFG_DIR="$HOME_DIR/.evilginx"
fi

echo "==> Running as user : $RUN_USER"
echo "==> Project dir     : $PROJECT_DIR"
echo "==> Config dir      : $CFG_DIR"

# --- Kill any existing evilginx (tmux / screen / bare) ----------------------
echo "==> Killing any existing tmux/screen/manual evilginx instances..."
for sess in $(tmux ls -F '#{session_name}' 2>/dev/null || true); do
  if tmux list-panes -t "$sess" -F '#{pane_pid}' 2>/dev/null | xargs -r ps -o args= -p 2>/dev/null | grep -q '[e]vilginx'; then
    echo "    killing tmux session '$sess' (running evilginx)"
    tmux kill-session -t "$sess" 2>/dev/null || true
  fi
done
pkill -x evilginx 2>/dev/null || true
pkill -f '^/.*/evilginx' 2>/dev/null || true
sleep 2

# --- Render the unit --------------------------------------------------------
echo "==> Writing $UNIT"
sed -e "s|__PROJECT_DIR__|$PROJECT_DIR|g" \
    -e "s|__RUN_USER__|$RUN_USER|g" \
    -e "s|__CFG_DIR__|$CFG_DIR|g" \
    "$TEMPLATE" > "$UNIT"
chmod 644 "$UNIT"

echo "==> Reloading systemd and enabling on boot..."
systemctl daemon-reload
systemctl enable evilginx.service

echo "==> Starting service..."
systemctl restart evilginx.service

echo "==> Status:"
systemctl status evilginx.service --no-pager || true

echo ""
echo "==> Recent output from the service (should show the evilginx banner):"
journalctl -u evilginx.service -n 30 --no-pager || true

echo ""
echo "=========================================================="
echo " DONE. evilginx is now a systemd service:"
echo "   status   : systemctl status evilginx"
echo "   restart  : systemctl restart evilginx"
echo "   logs     : journalctl -u evilginx -f   (follow)"
echo "   boot-enab: enabled (starts on reboot automatically)"
echo "   crash    : auto-restarts within 5s, forever"
echo "   config   : $CFG_DIR"
echo "=========================================================="
