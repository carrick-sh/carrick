#!/bin/sh
# Rust owns workflow/SHA policy. A failed hook alone still permits conditional
# workflow steps, so rejection kills the dedicated listener/worker/hook group.
if /usr/local/bin/carrick-xtask ci-scaler admit-job; then
  exit 0
fi
exec /bin/kill -KILL 0
