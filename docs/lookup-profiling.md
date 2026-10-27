# Lookup proving profile and constant-factor kernels

The lane-batched original-size canonical decomposition experiment gains a
prover-only phase counter API (`ProverStatistics`, `prove_with_statistics`, and
`prove_lanes_with_statistics`). Counters are not serialized or absorbed into the
transcript. The native example emits `HB_LANE_PHASES` separately from its proof
and budget metadata. A reference test compares ordinary and instrumented proof
bytes over BabyBear and Goldilocks.

Before the constant-factor optimization, the seed-42, 16-thread release profile
of canonical decomposition reports:

| Phase | Seconds |
|---|---:|
| Lookup ZeroCheck, including factor construction | 31.519 |
| Lookup terminal evaluation | 5.435 |
| Lookup sum claims and sumcheck | 5.221 |
| Reciprocal helper commitments | 4.188 |
| Lookup openings | 1.887 |
| Lookup preparation | 1.022 |
| Complete decomposition proving (includes borrow/linear work) | 51.079 |
| Complete decomposition verification | 1.416 |
| Proof serialization | 0.253 |
| Component total, including native input preparation | 52.869 |

The lookup rows are subsets of complete proving, not additional costs. They
include all eight transition lookups and both groups of eight independent
challenge pairs. Other macro proving work includes borrow preparation, canonical
linear checks and teardown. Logs and the pre-optimization binary are under
`target/performance/lane-profile/`. This is a component profile, not complete PBS.

## Optimization

R, tuple hash powers, full-domain masks, and zero borrow endpoints often repeat
the same lane vector in every Boolean cell. Their lanes need not equal one
another. The old kernels recomputed their 2k-node interpolation at every suffix
and applied the same dense matrix-vector product to every cell during folding.

The new kernels check actual table values for cell constancy, compute the full
lane interpolation once per round, and retain it in each worker's scratch data.
Product evaluation order is unchanged. Folding a cell-constant vector computes
`M0*v + M1*v` once and fills the remaining cells with the result. No serialized
cache flag or new proof assertion is introduced. After each fold the next round
checks the actual table again. Nonconstant factors use the ordinary kernels.

Degree-one packed rounds already contain all required interpolation nodes; they
now return immediately from extrapolation instead of building unused forward
differences. The verifier, declared degrees, queries and budget are unchanged.

Independent checks compare cached messages with direct Lagrange interpolation
and constant folds with an expanded ordered matrix tensor over BabyBear and
Goldilocks. A mixed lazy-zero Goldilocks test checks mathematical field equality.
These tests do not promise raw Goldilocks encoding equivalence for all lazy
representatives. Full protocol tests and native proof verification remain
required. The five-crate regression run passes 120 tests; seven Python tool tests
pass. Native performance results follow below.

## Paired original-size measurements

Both 16-thread, seed-42 profile pairs verify at original BabyBear FHE sizes:

| Pair | Baseline component (s) | Optimized component (s) | Reduction |
|---|---:|---:|---:|
| First | 52.869 | 46.069 | 12.9% |
| Confirmation | 53.205 | 45.226 | 15.0% |

ZeroCheck falls from 31.519 to 25.488 s in the first pair and from 31.954 to
24.908 s in confirmation. Sumcheck falls from 5.221 to 4.564 s, then from 5.115
to 4.544 s. Terminal evaluation falls from 5.435 to 5.196 s, then from 5.442 to
5.187 s. Commitment and opening times remain approximately stable. Each run has
exactly 376,277,702 canonical-decomposition bytes and unchanged emitted source,
helper, repetition and query dimensions. The interactive component budget is
unchanged. These component comparisons do not prove complete-PBS promotion.

Raw logs, per-phase values, paired comparison JSON, executable hashes and source
archives are under `target/performance/constant-factors/`. The baseline binary is
saved under `target/performance/lane-profile/baseline.bin`. Its reconstructed
source snapshot combines the profiled instrumentation with the three unchanged
pre-optimization kernel files from the prior lane-batching source archive; this
reconstruction is labeled explicitly. Noncompilation documentation in that
snapshot reflects its capture-time worktree. The optimized snapshot contains the
current kernel code. No source archive substitutes for the recorded executable
and runtime verification evidence.

A further candidate is direct authentication of reciprocal sums at the fixed MW
query `(I,I)` in every Boolean variable: that linear functional is exactly the
per-lane sum. It could remove the sumcheck for this linear subrelation. This is
not implemented; it requires checking the arbitrary-query PCS contract, preserving
every independent lane claim, adversarial tests, protocol versioning and an
updated budget. Remaining accumulator/key/endpoint relations and whole-proof
security stay required regardless of optional kernel improvements.
