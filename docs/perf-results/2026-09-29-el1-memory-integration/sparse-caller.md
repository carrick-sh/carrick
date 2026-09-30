# Local sparse publication through the descriptor service

Parent source: `cdb5abd64`. Contract: `kernel.el1.stage1-publication`.
The production local `sparse_materialization::publish_replacing` caller now
publishes authenticated backing through the existing driving-vCPU service.
Protocol v6 adds typed Deferred alias access: retained output remains invalid,
read-only and non-global until subsequent protection publication. Verified
receipts precede the existing retirement callback and metadata publication.
Foreign publication and replacement frame-grant retirement remain guarded.

The existing owned backing helper now accepts the already-created owner guard,
so failed planning releases the provisional grant without double retirement.
Unknown or partially completed publication fails stopped rather than releasing
possibly live backing. No production admission flag changed.

Evidence retained in sparse-*.log:
- Red: the old caller refuses guest ownership; Deferred initially exposed RWX.
- Green: actual local caller executes the real descriptor journal against live
  fixture table backing and settles its exact receipt; old bytes survive and
  new bytes remain inaccessible. The retirement callback observes completion.
- Refused planning restores provisional backing and does not call retirement.
- Host rollback and foreign/no-driving-vCPU guards remain green.
- MMU 167, EL1 114, backend 11 tests; affected Clippy, runtime compile check and
  hardware image build pass. Formatting and diff checks pass.

Limits: caller tests use a model kernel inventory authority, modeled HVF stage-2
operations and recorded maintenance. They do not execute hardware TLBI or the
outer predecessor retirement implementation. Image build is not execution.
Signed integration, complete writer closure and checkpoint acceptance remain open.
The next action is the bounded hardware integration check in the controller,
not another broad model qualification campaign.
