# Signed gate fixture publication: v2 security rework

**Hold publication.** `1581-signed-fixtures-v2.patch` is a replacement draft,
not a landing-ready fix. The independent review found a blocking P1: candidate
code still runs as the Mac Actions runner user. That code can modify future
action files and runner command files, including the files used to return
artifact IDs and digests. Upload-step outputs are therefore not a trusted
provenance boundary. The older `1581-signed-fixtures.patch` was removed; its privileged candidate fixture build was the reason
for this rework.

The draft moves fixture construction into `signed-fixtures-pr.yml`, triggered
by `pull_request`, with `contents: read`, no checkout credentials, and no cache
save or relay secrets. It reuses the native ARM64 setup and `just
fixtures-publish` recipe from `kernel-runtime.yml`. Its runtime artifact token
belongs to the PR run, not the privileged signed-gate run, and its cache scope
is the PR ref. The trusted authorization job selects a successful producer for
the admitted head; main baseline requests use the existing main push producer.
A SHA without a successful producer is refused, never replaced with a local
Mac bundle.

The new `signed-gate fetch-artifact` command downloads by immutable artifact
ID. Before extraction it checks the producing run ID, API digest, expiration
and downloaded ZIP SHA-256 against the expected binding. The fixture tarball
then goes through the existing `verify_fixture_artifact` source-SHA,
input-identity and executable checks before restore. Artifact names only help
the trusted selector discover fixture candidates; they are not download
identity.

For results, the draft passes the upload step's artifact ID and digest to
`publish`, replacing name-only downloads. This prevents independent
`signed-result-*` name substitution, but **does not close candidate forgery**
on the existing same-user Mac runner. The candidate already receives an
Actions runtime token there even without `GH_TOKEN`, and the runner-user
filesystem access defeats the apparent trusted collector. Do not claim
requirement 3 is satisfied.

Before publication, put candidate execution behind an enforced boundary from
the Actions runner and collector: a separate unprivileged OS identity with no
runner files, runtime credentials, process inspection or sudo escape, or an
equivalent disposable execution environment. The collector and its artifact
binding must remain outside that boundary. The current runner provisioning and
signed-test sudo contracts need director verification on a Mac; this Linux
worker cannot validate that boundary or a live signed gate.

Independent Sol review (fresh agent, this rework): blocking P1 above; initial
main-baseline producer regression corrected. The review was not published
because dispatch instructions prohibit posting or opening a PR. The handoff
must keep the PR draft and publish a fresh review after the isolation change.
CLI witnesses cover correct binding, wrong run, wrong digest and substituted
bytes before extraction; existing fixture tests retain wrong-source and
wrong-input refusal coverage.

After the isolation change and director publication, run the signed gate on a
fixture-changing PR and confirm fixture restore succeeds for the admitted SHA.
No live acceptance is claimed here.
