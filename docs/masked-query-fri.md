# Shared rolling FRI for masked ordered query ladders

The opt-in `packed_polyfrim::authenticated::masked::aggregated` API now shares
both the original paired-source proximity certificate and one query-ladder
rolling-FRI certificate across an ordered batch. Each member retains its own
matrix consistency ladder, mask response and opening allowance. The existing
independent and joint-source formats remain available.

The batch frame binds the trusted parameters, original root, first index,
ordered queries, public claims and all mask responses. Strict original-source
proximity runs before fresh virtual-source combinations are sampled. Each
member's virtual source has a deterministic identifier bound to the original
root, session index and its sampled combination coefficient. All intermediate
roots bind before the joint query/lane projections are sampled.

Internal proximity routing now supports these virtual sources. Public
unmasked verification still authenticates actual Merkle roots. Masked
verification always authenticates every virtual pair against an actual path
in the original paired source and checks the data-plus-mask combination.
Consistency samples use per-member actual-source paths. Joint FRI samples
share one actual-source path across all members. Every callback must run the
expected number of times; a packet cannot choose an authentication mode.

The prover preflights every claim and the complete allowance before transcript
mutation, then reserves one allowance per member. A later Result error keeps
the reservation. Transient source caches release after the complete batch.
`VerifierSession::verify_aggregated` advances only on whole-batch success.

The base-field matrix adapter exposes `open_many_aggregated` and
`verify_many_aggregated` on the existing trusted parameters. It normalizes and
extends the caller's logical queries through the existing physical padding,
uses distinct parent/child domains and preserves the original locked owner.
The adapter tests interleave an independent opening with 1/4/16 aggregated
batches, then require independent, joint-source and aggregated calls all to
reject the exhausted owner without changing the parent transcript.

Five new core tests verify six serialized/decoded batches over BabyBear degree
6 and Goldilocks degree 3, with dense extension-coordinate matrix entries and
matching final transcripts. Mask responses agree with verified prior-format
joint-source controls. Four fresh forgeries alter either a data claim or a mask
claim and build coherent low-degree virtual oracles and genuine joint FRI.
Strict original-source FRI, matrix consistency and query-ladder FRI pass in the
selective audit; public verification rejects the original-to-virtual equation.
The bypass exists only in test audit code. Source paths, roots, member order,
schedules, replayed old certificates, missing paths and noncanonical source
views also have rejection coverage.

| Field | Batch | New bytes | Prior joint-source bytes | New / prior field entries |
|---|---:|---:|---:|---:|
| BabyBear | 1 | 23,202 | 23,199 | 248 / 248 |
| BabyBear | 4 | 57,396 | 76,029 | 614 / 803 |
| BabyBear | 16 | 194,172 | 287,347 | 2078 / 3023 |
| Goldilocks | 1 | 22,458 | 22,455 | 248 / 248 |
| Goldilocks | 4 | 55,554 | 73,620 | 614 / 803 |
| Goldilocks | 16 | 187,938 | 278,280 | 2078 / 3023 |

These are message-8192, width-2, blowup-2, one-sample component fixtures with a
21-opening lifetime. Sixteen-query packets are about 32% smaller. All serialized
field entries are counted, including repeats and scalar FRI values. The total
across 1+4+16 openings is 2940 versus 4074, below the unchanged 8192-element
numerical allowance. These counts do not prove conditional rank or adaptive
hiding for the new shared-index schedule.

The 70-test release core suite passes. The five new tests repeat with exact
packet fingerprints; all seven unmasked joint-query tests also pass with their
six prior packet records byte-identical. Both matrix adapter integration tests
pass. Logs, source archives and checked records are under
`target/performance/masked-query-fri/`.

```sh
RAYON_NUM_THREADS=1 cargo test -p pcs --release --lib -- --nocapture --test-threads=1
RAYON_NUM_THREADS=1 cargo test -p pcs --release --test masked_aggregated_adapter -- --test-threads=1
cargo check --workspace --all-targets
```

This implementation retains full virtual-source arrays and all intermediate
ladders during a batch; large native batches need further memory work. A
separate trusted canonical backend and complete-PBS integration are still
required. Complete 1/4/16-statement aggregation, robust vector proximity,
Fiat–Shamir/knowledge/security composition, hiding, original-size complete
validation, isolated security-matched byte/latency gates and independent review
remain open. No whole-security, hiding or latency certification follows from
these component results.

The final workspace all-target check passes with the existing VFHE unused-macro
warnings. The core executed archive is `executed-sources.tar.gz` (SHA-256
`93205c82697d197dd54a381f42de8e869aa83d61e745256d127bf6217df35acb`);
the adapter executed archive is `adapter-executed-sources.tar.gz` (SHA-256
`48e56eb3e4356e4d6e4cd81ed862b1be1a07ae4a53f9191a87828bef40ea1d1f`).
The adapter test's unused import was removed and its final two-test run passes.
Cargo.lock remains
`293790853366e0bc0562752d17999bab335368dd6e0c33823f1afaee8c214718`.
