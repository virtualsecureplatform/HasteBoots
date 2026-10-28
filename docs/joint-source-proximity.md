# Joint original-source proximity batches

`packed_polyfrim::authenticated::masked::joint::{prove, verify}` authenticates an
ordered batch with one original-source proximity certificate. Each query still
has its own mask response, masked virtual-source consistency ladder and rolling
proximity proof. This implements actual sharing of one certificate, rather than
putting independent complete openings into a vector. It is not full query-ladder
or FRI aggregation and does not complete the plan's aggregation requirement.

The prover validates every query and actual claim before any transcript message
or allowance change. It then reserves the entire count from the retained private
mask lifetime. A later error never refunds that reservation. The fixed batch
prefix binds trusted parameters, expected source root, starting index, count and
every ordered query, claim and canonical mask response before source projection
coins. One source certificate follows. Each indexed member then uses its own
fresh mask combination challenge and original query-specific proof. A final
count/index frame seals the batch. The verifier checks the shared source first
and every response against that same caller-supplied root. Missing, extra,
reordered or nonconsecutive members fail. Optional `VerifierSession::verify_joint`
advances acceptance only after the complete batch verifies.

The new proof type stores the shared source certificate once and a vector of
`ResponseProof` packets without repeated source certificates. The ordinary
single-opening proof keeps its existing fields, order and domains. Private
preflight, response proving and response verification helpers are shared through
statically selected source-check functions; no serialized flag skips source
verification. The independent public entry point always checks its own source;
the joint entry point always checks its one batch source before any member.

One committed source has one degree/proximity obligation, independently of how
many ordered matrix responses are requested. Sharing that check is consistent
with this dependency: every member's sampled virtual-source values still have
Merkle paths under the exact original root. Any quantitative argument remains
conditional on the constituent robust vector-proximity and response-check
reductions. This change supplies no new concrete Fiat–Shamir, hash, knowledge or
adaptive hiding theorem. All mask indices and the old conservative disclosure
capacity remain charged per query; reduced certificate count is not used to
increase reuse or lower parameters. The changed challenge dependencies need
review as part of the full composition and hiding arguments.

## Validation

The selected release suite passes 58 core tests. New tests use full BabyBear6 and
Goldilocks3 coefficients and dense extension matrices, with one retained source
opened in 1/4/16 schedules. Six joint packets decode and verify, with 42 ordered
responses. The same original roots and private mask responses also produce 42
publicly verified independent openings for comparison. Prover, stateless verifier
and ordered verifier transcripts agree. Tests cover false late claims before
mutation, exhausted lifetimes, shared-source and per-query path tampering, wrong
roots/claims, dropped members, overflow, shape-preserving reordered responses,
query reordering and standalone source-proof replay. Failed ordered verification
leaves acceptance unchanged.

Two frozen independent openings per selected field preserve all non-timing
records after the helper extraction: complete parameter, root, randomness,
query, proof and final transcript fingerprints. This is a component wire
compatibility check, not a new complete-PBS security certificate. Raw tests,
frozen executables and source snapshots are retained under
`target/performance/joint-source-proximity/`.

The cumulative 1/4/16 schedule also counts every disclosed field entry, including
repeated values and zero placeholders. The joint total is no greater than its
independent reference and both remain within the original numerical mask
allowance. This checks only a disclosure count, not adaptive rank or hiding.
Noncanonical shared-source, mask-response and response-path entries reject before
changing the core transcript or ordered acceptance state.
