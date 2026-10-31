#!/bin/sh
# Start the reactor session (#1193): a Claude Code window that listens to the
# mailbox, in the detached tmux session `carrick-reactor`; attach with
# `tmux attach -t carrick-reactor`. The feed that appends PR events to the
# mailbox is a separate launchd job (`sh.carrick.reactor-feed`, see
# docs/ci/dispatch-worker.md), so events keep arriving while the session is
# restarted.
set -eu
WS=$(cd "$(dirname "$0")" && pwd)
STATE="$WS/state"
mkdir -p "$STATE"
touch "$STATE/mailbox.jsonl"
if tmux has-session -t carrick-reactor 2>/dev/null; then
  echo "carrick-reactor is already running" >&2
  exit 0
fi
tmux new-session -d -s carrick-reactor -n session -c "$WS" \
  "claude 'Start your mailbox monitor now, as CLAUDE.md describes, then route each event to its pr-<N> subagent.'"
echo "carrick-reactor started; tmux attach -t carrick-reactor"
