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

ZeroCheck now also keeps one reduced table per distinct borrowed source object.
It derives a private factor-to-buffer route from immutable pointer identity and
folds each buffer once per round. Every equation still reads its original ordered
factor list and retains a separate mixed equality table, messages and checks.
Distinct table objects remain separate even if their values or commitment roots
agree. No pointer, route or alias decision is serialized or trusted by a verifier.

For sixteen members sharing the native public key, this avoids another 120
BabyBear or 240 Goldilocks first-fold buffers: 0.46875/1.875 GiB of requested
storage at that stage. It also removes their duplicate folds in later rounds.
These counts do not establish an improvement in complete process peak RSS or
latency. Source authentication continues to use the selected v6/v7 protocol;
source-object sharing is only a prover computation optimization.

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

The subsequent shared-fold build and its serial release checks are archived in
`target/performance/shared-fold-pbs/`. All eighteen targeted tests and forty
reconstructed v6/v7 certificates pass on this build too. The existing canonical
relation fixture compares its shared-object execution with independent owned
copies, checking identical proof bytes and post-proof transcript challenges.
Twelve complete frozen-binary wire controls (84 fresh member instances) also
match every earlier borrowed-build v6/v7 proof byte and hash exactly, including
all 1/4/16 groups, archived statements, keys, FHE parameters and PCS layouts.

Original-size borrowed v7 validation now completes all six 1/4/16 certificates
covering 42 fresh statements in `target/performance/borrowed-pbs-native/`. All six
serialized proof byte counts and hashes match the earlier frozen owning build
under `target/performance/canonical-pbs-native/`; archived statements, keys,
FHE parameters and layouts match too. Conditional interactive inventories are
unchanged, with 129.32427 bits for the union of 42 statements, excluding complete
Fiat–Shamir/hash/composition security.

Observed process peak RSS is 27,135,584/70,792,920 KiB for BabyBear/Goldilocks in
these borrowed-build correctness sessions, compared with
28,933,600/79,031,708 KiB in the owning-build sessions. These are process
observations from one serial 1/4/16 run per field. Compilation overlapped the
sessions, so they do not establish a comparative latency result or close the
broader performance gates. The later shared-fold native validation also passes
all six certificates and 42 statements, with exact borrowed-build proof bytes and
hashes, in `target/performance/shared-fold-pbs-native/`. Its process peaks are
27,138,660/68,722,196 KiB. BabyBear's whole-process peak is effectively unchanged;
Goldilocks's observation is lower, consistent with removing folded source copies.
These remain correctness-session observations rather than paired performance
promotion evidence.
