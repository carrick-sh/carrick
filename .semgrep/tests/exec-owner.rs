// Known-answer fixture for .semgrep/exec-owner.yml (#2305).

fn carrier_mint(raw: NonZeroU64) {
    // ruleid: carrick-exec-owner-one-receipt-allocator
    let receipt = ExecAdoptionReceipt::checked(raw);
    // ruleid: carrick-exec-owner-one-receipt-allocator
    let receipt = carrick_core_abi::service::ExecAdoptionReceipt::checked(raw);
    // ruleid: carrick-exec-owner-one-receipt-allocator
    let receipt = NonZeroU64::new(next).and_then(ExecAdoptionReceipt::checked);
    // ok: carrick-exec-owner-one-receipt-allocator
    let claim = owner.claim(identity, successor, root_generation);
}

fn carrier_park(stock: &ForkStock<UntaggedRoots>, observed: StockRelease) -> bool {
    // ruleid: carrick-exec-owner-no-carrier-park-state
    stock.released_since(observed)
}

fn carrier_probe(owner: &mut Owner, stock: &ForkStock<UntaggedRoots>) {
    // ok: carrick-exec-owner-no-carrier-park-state
    let probe = owner.probe_parked(receipt, stock, cancelled);
}

// ruleid: carrick-issued-exec-mm-one-taker
fn second_issuance(issued: IssuedExecMm) {}

impl Kernel {
    // ruleid: carrick-issued-exec-mm-one-taker, carrick-issued-exec-mm-one-public-taker
    pub fn prepare_exec_with_a_second_mm(
        self: &Arc<Self>,
        context: &KernelContext,
        issued: IssuedExecMm,
    ) -> Result<PreparedExec, ExecError> {
        todo!()
    }

    // ruleid: carrick-issued-exec-mm-one-taker
    pub fn prepare_exec_with_registry_id(
        self: &Arc<Self>,
        context: &KernelContext,
        registry_id: ThreadId,
        issued: IssuedExecMm,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<PreparedExec, ExecError> {
        self.prepare_exec_with_optional_backend(context, None, Some(registry_id), issued, failpoint)
    }

    // The private chain is allowed only inside the Kernel exec module, which
    // this fixture is not.
    // ruleid: carrick-issued-exec-mm-one-taker
    fn prepare_exec_after_reservation(&self, issued: IssuedExecMm) -> Result<PreparedExec, ExecError> {
        todo!()
    }

    // ok: carrick-issued-exec-mm-one-taker
    pub fn issued_mm_id(&self, issued: &IssuedExecMm) -> MmId {
        issued.mm_id()
    }
}
