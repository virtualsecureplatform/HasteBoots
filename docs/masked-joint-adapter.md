# Joint-source masked matrix adapter

`masked_polyfrim::Parameters::{open_many_joint, verify_many_joint}` exposes the
joint original-source certificate for ordered base-field matrix queries. The
existing independent methods and proof format remain available. Selection is an
explicit trusted API call, with a different proof type and distinct parent,
child-seed, child and finish domains. No proof selects its own verification mode.

Both methods use the same canonical logical table, expected source root,
complete parameter context and locked original mask session. Root/context,
whole-batch capacity and every actual logical claim are checked through the same
preflight helper before changing the parent transcript. Independent and joint
calls share one counter: switching APIs cannot refresh masks. The physical
extension and fixed high-variable queries retain the old logical dimensions.
The core batch then binds all ordered extension claims and mask responses before
its one shared source certificate, followed by independently checked masked
ladders. Parent and extension child transcripts finish with matching digests.

This is opt-in source sharing. The canonical `CanonicalPcs` implementation and
complete version-10/11 PBS entry points still use the independent adapter. A
statically selected joint backend and complete-PBS integration, full query/FRI
aggregation, original-size measurements, robust vector proximity, base-projection
knowledge, whole-proof Fiat–Shamir/hash/knowledge composition, adaptive hiding and
independent review remain open. Numerical disclosure capacity is not a theorem.

## Validation and reproducibility

The release suite passes 58 core, four independent-adapter and five joint-adapter
tests. Joint adapter tests cover decoded 1/4/16 schedules over both selected
fields, zero logical variables, equal-root/different-context rejection,
concurrent callers and mixed independent/joint calls consuming one lifetime.
They retain wrong statement/root, reordered response/query, failed late-preflight
and exhaustion checks. Frozen independent profiles preserve proof bytes and
transcripts across the common-helper extraction in both fields.

The deterministic `masked_joint_profile` example compares `independent` and
`joint` modes at matched tables, parameters, root, query list, randomness
consumption and per-query mask budget. It serializes/decodes each packet and runs
the public verifier, then checks the parent transcript and spent counter. Public
seeds/masks are test controls only. Example invocation:

```sh
RAYON_NUM_THREADS=8 cargo run --release --locked -p pcs \
  --example masked_joint_profile -- babybear joint 4 15 16
```

The JSON records retain setup/commit, prove, serialize, decode and verify times,
complete proof/transcript fingerprints and actual source-certificate/ladder
counts. Timing comparisons use the frozen executable directly after all builds
and tests finish. Per-mode non-timing records must repeat in reverse execution
order; cross-mode table, parameter, root, query and randomness fingerprints must
match. Protocol-specific proof and transcript hashes intentionally differ.
Raw records, comparisons, frozen executables and source archives live under
`target/performance/joint-source-proximity/`. These one-query synthetic component
profiles cannot establish complete-PBS latency or security-matched byte targets.

## Isolated component comparison

Runs use eight Rayon threads, logical dimension 4, physical dimension 15,
width 8 for BabyBear6 and width 4 for Goldilocks3, one PCS sampling query and
mask budget equal to batch size. Order 0 runs independent then joint; order 1
reverses it. Each row is one complete packet, including all indicated query
ladders. All builds/tests finished before timing. Per-mode proof/transcript
hashes reproduce exactly in reverse order, and cross-mode fixture, parameters,
root, queries, randomness and spent-counter fingerprints agree.

| Field | Batch | Order | Independent prove (s) | Joint prove (s) | Reduction | Independent bytes | Joint bytes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| babybear | 1 | 0 | 0.8590 | 0.8541 | 0.6% | 42784 | 42785 |
| babybear | 1 | 1 | 0.8861 | 0.9298 | -4.9% | 42784 | 42785 |
| babybear | 4 | 0 | 3.8103 | 3.3263 | 12.7% | 171133 | 148309 |
| babybear | 4 | 1 | 3.6687 | 3.3675 | 8.2% | 171133 | 148309 |
| babybear | 16 | 0 | 15.6510 | 13.4951 | 13.8% | 684525 | 570421 |
| babybear | 16 | 1 | 14.8759 | 13.0514 | 12.3% | 684525 | 570421 |
| goldilocks | 1 | 0 | 0.3030 | 0.3111 | -2.7% | 31934 | 31935 |
| goldilocks | 1 | 1 | 0.4246 | 0.3080 | 27.5% | 31934 | 31935 |
| goldilocks | 4 | 0 | 1.5165 | 0.9425 | 37.9% | 127733 | 107112 |
| goldilocks | 4 | 1 | 1.4088 | 1.0614 | 24.7% | 127733 | 107112 |
| goldilocks | 16 | 0 | 5.8566 | 4.7840 | 18.3% | 510929 | 407820 |
| goldilocks | 16 | 1 | 5.7940 | 4.1047 | 29.2% | 510929 | 407820 |

Four-query packets save 13.3% of bytes for BabyBear and 16.1% for Goldilocks;
sixteen-query packets save 16.7% and 20.2%, respectively. A one-query joint packet
adds one byte and establishes no stable latency improvement. Sixteen-query
proving improves in both orders for both fields. These component results neither
satisfy nor replace the original complete-PBS/security gates. Query-specific
ladders and their FRIs remain separate, so full query aggregation is unfinished.

The measured and final snapshots differ in code only inside the joint module's
`cfg(test)` block: the final budget-count and canonical-encoding guards were
added after timing. `source-equivalence.json` checks the production prefix and
all other code/lock bytes; both immutable source archives are retained. The
locked workspace check also passes.
