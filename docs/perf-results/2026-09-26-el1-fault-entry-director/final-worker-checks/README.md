# Fault-entry worker verification and signed red preparation

Worker `fault-entry` converged after three director review rounds at
`a6fe8d4af4f4fb097a2801953b89c182678c1ea2`. The director independently
rebuilt the fixture, reran its host/image/contract/format/embed-compile checks,
and executed the final fixture on the pinned native arm64 Docker image.
All commands exited zero; native container cleanup is empty. This accepts
the worker for the next signed validation stage, not full integration.

The integration checkout now imports only its ABI counter/frame declarations,
fixture and named embed test. The existing EL1 image dispatcher and emitted
vectors are retained. This deliberately instrumented old-routing source must
fail the positive entry-counter assertion while preserving Linux behavior.
Its signed test binary and fixture will be frozen before importing the actual
fault-entry implementation. Signed red/green and EL1/GIC controls remain open.
