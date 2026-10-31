#!/bin/sh
# Start the reactor session (#1193): a Claude Code window that receives PR
# events through the carrick-reactor MCP channel, which follows the mailbox,
# in the detached tmux session `carrick-reactor`. A custom channel is not on
# the research-preview allowlist, so the development flag is needed, and it
# only works interactively, hence tmux. Attach with
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
  "claude --dangerously-load-development-channels server:carrick-reactor 'You are the Carrick reactor. PR events arrive as carrick-reactor channel tags; route each one to its pr-<N> subagent as CLAUDE.md describes. Wait for events.'"
echo "carrick-reactor started; tmux attach -t carrick-reactor"
