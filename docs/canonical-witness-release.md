# Release completed blind-rotation witnesses before key switching

The canonical version-10/11 prover now drops its internal coefficient,
evaluation, accumulator and decomposition-input owners immediately after the
monomial proof, before creating final key-switching witness states. Their last
use is in the completed blind-rotation relations. The resulting proof messages,
public roots and final accumulator already own every value needed afterward.

This removes the overlap between two stages' private witness allocations. It
applies to every statically selected canonical PCS backend. Original native
key owners remain retained in the caller's setup, with their original mask
lifetime counters. No randomness, dimensions, proof message, transcript frame,
public verifier check or parameter context changes. The source state cache
policy remains opt-in and unchanged.

This is a memory prerequisite for complete original-size masked PBS validation,
not a measured whole-PBS speed improvement or a security result. The native
harness and its tracked runs are documented separately. Full proof-security,
hiding, complete aggregation and performance/review gates remain open.

The complete joint-backend integration tests pass for both fields and both
versions. All four serialized proof hashes and every non-timing profile field
match the archived pre-change `canonical-joint-backend/runs/run-0.json` exactly.
The tests retain the same original key owners through versions 11 and 10,
verify decoded proofs, enforce their counters and reject altered statements and
packets. No dedicated test mirrors the explicit `drop` calls: the complete
certificates exercise the stage boundary.

Executed source archive SHA-256:
`8df48fbb6105bcaabb6f93473d99775f8319c5cdc442713d01859551e1c5c659`.
Logs and exact profile comparisons are under
`target/performance/canonical-witness-release/`.

The four ordinary canonical PBS tests also pass, covering all NAND inputs over
both fields in versions 10/11. The workspace all-target check passes with the
existing VFHE unused-macro warnings. Reproduction:

```sh
RAYON_NUM_THREADS=8 cargo test -p vfhe --release --test packed_canonical_joint_pbs -- --nocapture --test-threads=1
RAYON_NUM_THREADS=8 cargo test -p vfhe --release --test packed_canonical_backend_ordinary_pbs --test packed_canonical_shared_ordinary_pbs -- --test-threads=1
cargo check --workspace --all-targets
```
