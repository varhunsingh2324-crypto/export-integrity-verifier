#!/usr/bin/env bash
# `make dashboard` / `make dashboard-stop`: run the Streamlit dashboard in the background, so the
# terminal stays free for the demo. pid and log live in data/dev (regenerable, rule 10).
set -euo pipefail

cd "$(dirname "$0")/.."
PORT="${DASHBOARD_PORT:-8501}"
STATE=data/dev
PIDFILE="$STATE/dashboard.pid"
LOG="$STATE/dashboard.log"
URL="http://localhost:$PORT"

running() { [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }

healthy() {  # python, not curl: one less tool to install
  .venv/bin/python -c "import sys, urllib.request as u; sys.exit(u.urlopen('$URL/_stcore/health', timeout=1).read() != b'ok')" 2>/dev/null
}

start() {
  mkdir -p "$STATE"
  if running; then
    echo "dashboard already running (pid $(cat "$PIDFILE")): $URL"
    return 0
  fi
  # setsid + nohup: the server outlives make and the terminal that started it
  setsid nohup .venv/bin/streamlit run dashboard/app.py --server.port "$PORT" >"$LOG" 2>&1 </dev/null &
  echo $! >"$PIDFILE"
  for _ in $(seq 40); do
    if healthy; then
      echo "dashboard: $URL  (pid $(cat "$PIDFILE"), log $LOG; stop: make dashboard-stop)"
      return 0
    fi
    if ! running; then break; fi
    sleep 0.5
  done
  echo "dashboard did not become healthy on $URL; last log lines:" >&2
  tail -n 20 "$LOG" >&2 || true
  stop >/dev/null
  return 3
}

stop() {
  if running; then
    kill "$(cat "$PIDFILE")"
    echo "dashboard stopped (pid $(cat "$PIDFILE"))"
  else
    echo "dashboard not running"
  fi
  rm -f "$PIDFILE"
}

case "${1:-start}" in
  start) start ;;
  stop) stop ;;
  *) echo "usage: $0 start|stop" >&2; exit 3 ;;
esac
