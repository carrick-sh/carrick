#!/bin/sh
# Start the reactor session (#1193): a feed window that appends PR events to
# the mailbox, and a Claude Code window that listens to it. Both run in the
# detached tmux session `carrick-reactor`; attach with
# `tmux attach -t carrick-reactor`.
set -eu
WS=$(cd "$(dirname "$0")" && pwd)
BIN=/Volumes/CaseSensitive/carrick-director/bin/carrick-reactor
STATE="$WS/state"
mkdir -p "$STATE"
touch "$STATE/mailbox.jsonl"
if tmux has-session -t carrick-reactor 2>/dev/null; then
  echo "carrick-reactor is already running" >&2
  exit 0
fi
tmux new-session -d -s carrick-reactor -n session -c "$WS" \
  "claude 'Start your mailbox monitor now, as CLAUDE.md describes, then route each event to its pr-<N> subagent.'"
tmux new-window -d -t carrick-reactor -n feed -c "$WS" \
  "$BIN dispatch-worker reactor feed --mailbox '$STATE/mailbox.jsonl' --state '$STATE/feed-state.json' 2>&1 | tee -a '$STATE/feed.log'"
echo "carrick-reactor started; tmux attach -t carrick-reactor"
