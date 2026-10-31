#!/bin/sh
# Start the reactor session (#1193) in the detached tmux session
# `carrick-reactor`; attach with `tmux attach -t carrick-reactor`.
#
# The session runs in the repository checkout, so it reads the code it talks
# about. Everything that makes it the reactor is passed for this session only,
# so nothing here changes how other Claude Code sessions in the checkout
# behave:
# - --settings: permissions. dontAsk refuses anything not allowed: the
#   reactor tools, Read, Agent, SendMessage and ListAgents. Bash, Monitor, file writes
#   and web tools are denied, so the session has no shell.
# - --setting-sources user: skip the checkout's project and local settings
#   and hooks.
# - --name carrick-reactor: the name the director session (carrick-director)
#   uses to message this session, and the one it messages back.
# - --mcp-config + --strict-mcp-config: only the carrick-reactor server.
# - --append-system-prompt-file: the reactor role (prompt.md).
# - --agents: the pr-watcher subagent (agents.json).
#
# Events reach the session through the server's wait_events tool, not a
# Claude Code channel: a custom channel needs
# --dangerously-load-development-channels, which asks for confirmation on
# every launch. `reactor mcp --channel` switches the server to channel
# delivery if it ever lands on an approved allowlist.
#
# The feed that appends PR events to the mailbox is a separate launchd job
# (`sh.carrick.reactor-feed`, see docs/ci/dispatch-worker.md), so events keep
# arriving while the session is restarted.
set -eu
WS=$(cd "$(dirname "$0")" && pwd)
REPO=${CARRICK_REACTOR_REPO:-/Volumes/CaseSensitive/carrick}
STATE="$WS/state"
mkdir -p "$STATE"
touch "$STATE/mailbox.jsonl"
if tmux has-session -t carrick-reactor 2>/dev/null; then
  echo "carrick-reactor is already running" >&2
  exit 0
fi
AGENTS=$(cat "$WS/agents.json")
PROMPT='You are the Carrick reactor. Start your wait_events loop now and route each event to its pr-<N> subagent as your instructions describe. Never stop the loop.'
# Keep the pane after claude exits, so a startup failure stays readable.
tmux new-session -d -s carrick-reactor -n session -c "$REPO" \
  claude "$PROMPT" \
    --name carrick-reactor \
    --settings "$WS/settings.json" \
    --setting-sources user \
    --mcp-config "$WS/mcp.json" --strict-mcp-config \
    --append-system-prompt-file "$WS/prompt.md" \
    --agents "$AGENTS"
tmux set-option -t carrick-reactor remain-on-exit on
echo "carrick-reactor started in $REPO; tmux attach -t carrick-reactor"
