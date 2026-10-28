# Shared-challenge independent packed relations

`sumcheck::packed_zero::batch` proves an ordered list of independent pointwise
relations with shared matrix challenges. `snarks::packed_relation::batch` links
their individual terminal claims to the original commitments using one joint
multi-root PCS certificate. This is actual joint source authentication across
relations, rather than a wrapper around independent opening certificates. It is
a component; complete cross-statement NAND PBS composition remains unfinished.

## Protocol and API

The caller supplies trusted shapes and grouped canonical roots. Geometry must
match (base field, packing width and variable count); factor counts, polynomial
degrees and coefficients can differ. The frontend binds the entire ordered
shape/root registry, parameter context and extension degree before algebra.

Each instance has its own independently sampled equality points. All special
first-round messages are bound together before sampling the shared mixing
matrix and first matrix pair. Subsequent rounds similarly bind every instance's
message, with the round ordinal, before the common challenge. Every first-round
boundary, sumcheck recurrence and terminal equation is checked separately.
All instances therefore finish at the same ordered base-field matrix query.

The frontend binds all individual factor claims before calling the existing
full-extension-weight multi-root PCS. Claims and roots are flattened in trusted
instance/factor order; no combined root is introduced. A verifier supplies only
public shapes, parameters and roots. Private source states remain prover-only.

`packed_zero::batch::{prove,verify}` return opening obligations, not standalone
acceptance of witness values. The authenticated frontend's `prove` takes grouped
factor tables and references to canonical states, and `verify` discharges every
obligation. Its proof contains algebraic messages, grouped individual claims,
and one PCS packet. No independent per-instance PCS packets are serialized.

No base-field linear combination replaces the individual equations. In
particular, two false relations whose pointwise residuals are opposites must
both be rejected, although their sum vanishes. A conditional algebraic inventory
can union-bound the original per-instance ZeroCheck errors and add the joint PCS
error. Shared challenges correlate those errors; they do not justify multiplying
soundness probabilities or increasing security by the batch size. The underlying
fixed-word matrix-PCS assumptions, hash/Fiat–Shamir analysis and whole-protocol
composition still require review. This component is non-hiding.

The original single-relation APIs retain their transcript framing. Their first
message evaluation kernel was extracted without changing its operations. Fifty
decoded complete v3/v4/v5 toy certificates preserve exact archived wire bytes,
statement bindings and keys after this refactor. The independent callback/replay
checks also pass. Two additional current-source native v5 packets retain exact
frozen v5 bytes and bindings; these concurrent controls are correctness-only.

## Validation

Twenty relevant Rust tests pass: twelve sumcheck regressions (including the two
new batch tests), four relation integration tests and four relation unit tests.
New fixtures cover 1/4/16 instances in both fields, packing widths 1/4/8,
one-variable and larger domains, heterogeneous degrees/coefficients/factor counts, decoded
verification, common queries and matching post-transcripts. Missing, malformed,
reordered or changed shapes/messages/claims/roots are rejected.

The two new adversarial unit tests rebuild valid algebra for false witness
views under the actual root registry, derive truthful actual source claims,
and construct genuine joint PCS openings against those roots. Local algebra
and actual-root authentication each verify, but the production frontend rejects
the false individual terminal equations. The false residuals sum to zero at
every Boolean point. Honest controls pass, so rejection is not due to an invalid
opening or transcript mismatch.

## Native-capacity component comparison

The `packed_batch_relation` example compares separate aggregate-relation proofs
with joint shared-challenge authentication. Both modes bind the same complete
requested registry before proving. Each relation has three independently
committed factors satisfying `c=(instance+1)*a*b`. Prepared source states and
fixture generation are outside proving time; complete component time includes
proving and serialization. Every packet is decoded and publicly verified.

Each factor has 2^21 scalar cells at native capacity. BabyBear uses degree 6,
width 8, variables 18, left split 3 and 4096/8192 message/encoded blocks.
Goldilocks uses degree 3, width 4, variables 19, left split 4 and 8192/16384
blocks. Both modes use Q=544. Two serial native sessions reverse field and
method order with sixteen Rayon threads; no builds, tests or native PBS
correctness runs overlap these measurements.

| Field | Relations | Separate bytes | Joint bytes | Byte reduction | Complete time reduction, two orders |
|---|---:|---:|---:|---:|---|
| BabyBear | 1 | 14,230,896 | 14,176,687 | 0.38% | -8.99%, -27.94% |
| BabyBear | 4 | 56,833,317 | 28,503,953 | 49.85% | 12.77%, 6.81% |
| BabyBear | 16 | 227,215,495 | 85,270,825 | 62.47% | 13.44%, 6.39% |
| Goldilocks | 1 | 9,353,757 | 9,353,758 | one byte larger | 18.61%, -22.62% |
| Goldilocks | 4 | 37,281,201 | 22,631,809 | 39.29% | -11.40%, -7.52% |
| Goldilocks | 16 | 149,333,901 | 76,781,149 | 48.58% | 12.58%, -6.81% |

At sixteen relations, BabyBear verification changes from 0.926/0.921 s to
0.189/0.191 s, and Goldilocks from 0.562/0.439 s to 0.152/0.152 s. This supports
size and verifier-throughput benefits for larger groups. Prover improvements
are not robust across fields/orders; one relation is not an automatic win.
These are component comparisons, not a security-matched whole-PBS promotion.
Resource reports cover each process containing both modes; they do not isolate
peak memory per method.

All 36 packets (252 relation instances, 756 factor-root claims) verify. Native
proof hashes/sizes repeat exactly across order, with identical expected
statements and geometry in both modes. Raw logs/resources, commands, exact
executable, terminal status and checked comparison are under
`target/performance/shared-relation-batch/`. The build snapshot SHA-256 is
`ee9df6c821a245b712cb9cfe32d8269e5439c3b4c887a76b74e651d3f09adee9`;
all 349 Rust/manifest/lock inputs matched before measurement. Executable SHA-256:
`80d6981b75fd14d25d574b0e23e44b117fbaf97e84fcab03b17fc4bb3aa95d34`.
After timing, only documentation and the heterogeneous-factor-count regression
fixture changed; the measured production and benchmark sources remain identical.

Complete PBS still needs a batch witness/session owner and canonical stage
composition around this frontend. Independent full certificates, within-proof
v5 sharing, and this relation component do not together constitute a complete
cross-statement PBS batch. Hiding, independent security review and promotion
also remain open.
