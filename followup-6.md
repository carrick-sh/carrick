title: bind embedded CPL0 build cache admission to the source checkout
parent: #2271

Round 2 built a separate main worktree using the head checkout's CARGO_TARGET_DIR.
The host test executable changed, but every KVM build-script output still
watched /var/lib/carrick-conductor/repo rather than /var/tmp/1756-main.
The five family tests all passed, including the expected main-red readv and
legacy wait cases. This run is invalid as main evidence: the embedded CPL0
image retained head provenance. It must not be called a flaky semantic verdict.
A fresh separate target directory is used for the authoritative comparison.
Returning to head in the shared target also left main host ABI artifacts in
place: a compile refused the missing copy_vector_output method before any
guest ran. The director-added child-poll witness therefore uses a fresh head
target directory as well as the isolated main target.

Acceptance: a known-answer two-checkout test must show the embedded image
source identity follows the selected checkout even when Cargo target storage
is shared. Bind cache admission to source identity or reject cross-checkout
reuse; keep build input derivation in its existing owner. No semantic budget,
timeout or retry changes. No copyleft source consulted.
