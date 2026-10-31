# Root tty activation

`runtime.root.tty-activation` covers first-root carrier activation racing a
completed root command. Linux authority is the cached CLI exit-status contract:
`exit 42` must return 42 regardless of how quickly the task exits. Launch tty
session and foreground authority must be initialized before guest execution;
relay acknowledgement derives from that published authority, not a fresh lookup
of a possibly retired root thread. The deterministic VM-free binding is
`root_tty_publication_survives_root_exit_before_activation` in the runtime, which
retires the root before service publication. The structural budget is zero
root-thread registry captures during tty service publication, with no wait,
retry, or guest-execution barrier added. The signed bindings are
`case_01_exit_status_propagation` (embed) and
`conformance_default_run_contract` (CLI). Docker refresh and broader signed
promotion remain the integration director's responsibility.
