#!/usr/bin/env bash
# PreToolUse hook (Edit|Write|MultiEdit): flag edits that ADD eprintln!/eprint!
# to a .rs file and redirect toward real debugging (carrick trace USDT, lldb).
# Emits an "ask" permission decision so legit host-side stderr can still pass.
set -euo pipefail

input=$(cat)

decision=$(printf '%s' "$input" | jq -r '
  ($pat) as $p
  | (.tool_input.file_path // "") as $fp
  | def adds($s): ($s // "") | test($p);
    # net-add: present in new text, not already present in the matching old text
    def netadd($new; $old): (adds($new)) and ((($old // "") | test($p)) | not);
    if ($fp | endswith(".rs") | not) then "no"
    elif .tool_name == "Write" then (if adds(.tool_input.content) then "yes" else "no" end)
    elif .tool_name == "Edit"  then (if netadd(.tool_input.new_string; .tool_input.old_string) then "yes" else "no" end)
    elif .tool_name == "MultiEdit" then
      (if any(.tool_input.edits[]; netadd(.new_string; .old_string)) then "yes" else "no" end)
    else "no" end
' --arg pat 'eprintln!|eprint!')

if [ "$decision" = "yes" ]; then
  reason='This edit adds eprintln!/eprint! to a .rs file. Per project convention, debug the guest with real tooling instead of log spam: `carrick trace` (in-process libdtrace / USDT probes, see the carrick-trace skill) or lldb sysreg dumps. If this is genuinely host-side CLI stderr output (not debugging), approve to proceed.'
  jq -nc --arg r "$reason" '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "ask",
      permissionDecisionReason: $r
    }
  }'
fi
exit 0
