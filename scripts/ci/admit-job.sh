#!/bin/sh
# GitHub requires a .sh hook; the Rust guard owns workflow/SHA admission.
exec /usr/local/bin/carrick-xtask ci-scaler admit-job
