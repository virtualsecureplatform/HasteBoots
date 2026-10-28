# Borrowed tables in complete PBS batches

The complete v6 and v7 provers now lend retained canonical source tables to the
joint Hadamard prover. They no longer clone each member's evaluation factors and
all public-key factors into a second owned factor list. Public verification,
transcript domains, arithmetic order, commitment roots and proof formats are
unchanged. The prover still owns its private witness and commitment states until
authentication finishes.

`packed_zero::batch::prove_borrowed` and
`packed_relation::batch::{prove_borrowed, canonical::prove_borrowed}` accept
borrowed factor tables. The existing owned-input APIs remain available and
construct only vectors of references before calling the borrowed path. No source
buffers are cloned by those adapters. The first-round kernels and table checks
accept borrowed tables without changing field operations or their order.

At the original source capacity of 2^21 scalars per factor, a sixteen-member
batch has 272 BabyBear or 528 Goldilocks Hadamard factor slots. Avoiding their
second field-buffer copies removes 2,281,701,376 bytes (2.125 GiB) or
8,858,370,048 bytes (8.25 GiB) of requested buffer storage at that stage. These
are counts of eliminated allocations, not observed reductions in process peak
RSS or complete latency. Native comparative measurements remain required.

ZeroCheck still creates and folds a separate reduced table per factor slot, and
retains independent equality tables per equation. Canonical PCS deduplication
removes repeated authentication but does not yet share those folded factors.
Cross-statement comparison sharing, direct hiding packed FRI and the whole-proof
security argument remain separate unfinished plan items.

## Validation artifacts

`target/performance/borrowed-pbs/` contains frozen sources, the serial build/test
controller, release logs and frozen-binary wire-control scripts. The relation
fixtures compare owned and borrowed proof bytes and post-proof transcripts at
sizes 1, 4 and 16 for both fields and both authentication formats. The canonical
fixture lends the same public factor object to every member, exercising actual
shared references rather than equal independent copies.

All eighteen targeted release tests pass: four relation tests, six sumcheck
checks and eight complete v6/v7 tests. The complete suites include forty freshly
reconstructed certificates, with four controls accepted and 36 attacks rejected.
The relation tests preserve both proof bytes and post-proof transcript challenges
between the owned and borrowed APIs. Twelve frozen-binary complete wire controls
also pass, covering 84 fresh member instances: all v6/v7 proof bytes and hashes
match the earlier owning build at sizes 1, 4 and 16 for both fields. Archived
statements, keys, FHE parameters and four PCS layouts match too.

The original-size v7 validation under `target/performance/canonical-pbs-native/`
uses the earlier frozen owning build. Its results must not be reported as native
validation or memory measurements of this borrowed implementation.
