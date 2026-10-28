# Canonical packed backend boundary

`pcs::matrix_weighted::backend::CanonicalPcs` separates canonical source
commitments and ordered terminal authentication from the concrete row encoder.
It is statically selected through trusted parameter types. Associated state and
packet types support Brakedown and the experimental masked packed adapter.
The boundary exposes logical shape, complete context, commitment, retained table,
claim encoding and ordered opening/verification operations. Backend selection,
parameters, source roots and alias decisions are never deserialized from a proof.

`CanonicalProverOracle` borrows one retained backend state and obtains its logical
table directly from that state. `CanonicalVerifierOracle` retains only trusted
parameters and the expected root. The established Brakedown verifier spelling is
an alias over the same descriptor; current callers retain their API.

`CanonicalOpeningBatch` now implements the deferred registry shared by both
backends. It binds every registered context/root before algebra, binds each
caller-derived claim before later challenges, and authenticates every used source
at sealing. Slots alias only when both complete context and root agree. Packet
counts and source ordering come from the verifier's reconstructed obligations.
Unused sources have no terminal packet; their declaration remains bound.

The legacy `OpeningBatch`/`Proof` spellings alias this implementation with
Brakedown parameters and packet types. Its original registry/claim/seal v1
frames and underlying Brakedown calls are retained. A frozen direct-dispatch
reference from commit `659db21` checks identical complete packet bytes and final
prover/verifier transcript challenges over BabyBear and Goldilocks. This checks
wire behavior, not execution-time equivalence.

The masked backend uses separate v2 registry frames and normalizes public claim
encodings before binding. Canonical root aliases share the same retained private
session. A used source preflights its own entire ordered claim list and mask
allowance atomically. Across different roots, an earlier successful opening can
spend an allowance before a later source fails; that allowance is never refunded.
The registry does not promise a multi-root transaction or refresh private masks.

## Integration scope

The existing complete PBS deferred paths now use the common registry through
their backward-compatible aliases. The masked backend is tested through the same
registry and source-descriptor implementation. Complete PBS setup, single-opening
relations, transforms and multi-root Hadamard authentication still have concrete
Brakedown types. Generalizing those remaining boundaries and producing a versioned
masked complete-PBS proof remains outstanding. Individual masked packets remain
independent openings; joint query sharing, native measurements, general hiding
and whole-proof security are also open.

The masked registry tests use two logical source shapes, one aliased root and one
unused source. The 1/4/16-claim schedules over both selected fields verify 42
serialized/decoded obligations. Counters reach 11 and 10 on the used roots, while
the unused source remains at zero. A subsequent later-root failure consumes the
first root's final ticket without refund; the exhausted alias cannot open again.
A separate byte-equivalence test covers noncanonical Goldilocks claim aliases.
These are synthetic terminal obligations, not native FHE or joint aggregation.

Validation completes with 78 selected release/locked tests: 66 SNARK component
checks and twelve complete v7/v8/v9 PBS integration tests. All sixty fresh full
binding certificates retain their expected outcomes (six controls accepted,
fifty-four attacks rejected). The locked workspace check passes. Logs, six masked
registry records, checked counts and validated sources are under
`target/performance/canonical-packed-backend-boundary/`; source SHA-256 is
`b22762e362ea8e5c0f5555b5876125c9f8ac489b56111342da68f8eae352af8d`.

Single-opening dispatch now supports shared canonical linear-identity proving and
verification. The legacy Brakedown spelling remains an alias over its original
packet shape; the masked variant enforces canonical response encodings. See
`canonical-packed-linear.md` for the independent wire and fresh-false-identity
checks. Other concrete PBS boundaries remain outstanding.

NTT authentication now uses the same boundary with backend-specific ordered
opening packets and a shared logical shape calculation. Eight frozen legacy
controls and fresh masked transform checks are described in
`canonical-packed-ntt.md`. Complete-PBS backend integration is still unfinished.

Single polynomial relations now use canonical source descriptors and borrowed
ZeroCheck factors. Contexts and roots are bound before algebra; legacy callers
retain their original framing. See `canonical-packed-relation.md`. Shared/batched
relations and complete-PBS setup integration remain outstanding.

Shared polynomial identities also have a backend entry point using the existing
canonical registry after shared-challenge ZeroCheck. It checks each equation
individually and borrows retained factors. See `canonical-shared-relations.md`;
this does not replace the existing optimized multi-root Brakedown path or claim
masked joint aggregation.

Native evaluation-key ownership and the complete-PBS setup wrapper also support
canonical backends. The original retained states carry lifetime counters across
oracle borrows; expected public setup contains no private state. See
`canonical-native-key-setup.md`. Complete masked proof composition remains open.

Accumulator linkage now shares its arithmetic/query maps across canonical
backends, with retained state authentication and backend-specific framing. See
`canonical-packed-accumulator.md`. Complete masked PBS composition remains open.

Public monomial products also compose canonical NTT and terminal authentication,
with explicit trusted evaluation parameters and private derived-root commitment
randomness. See `canonical-packed-monomial.md`; full masked PBS remains open.

Standalone extension-field lookups also authenticate original sources and
coefficient-packed reciprocal helpers through canonical backends. The selected
extension algebra is preserved. See `canonical-extension-lookups.md`; shared
comparison composition and complete masked PBS remain open.

Radix decomposition now composes canonical reconstruction, zero borrow endpoints
and per-limb extension comparisons against original source/digit roots. See
`canonical-packed-decomposition.md`; shared comparison aggregation and complete
masked PBS remain open.

Final key switching now composes canonical NTT, key-product, decomposition and
extraction authentication. The randomized public-input root has a separate
known-table check. See `canonical-packed-key-switch.md`; complete masked PBS
composition remains open.
