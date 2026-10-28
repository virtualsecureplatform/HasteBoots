# Complete canonical-backend PBS, version 10

`packed_pbs::canonical` composes every original binary NAND PBS stage through
statically selected `CanonicalPcs` implementations. Version 10 has a distinct
proof type and parent transcript domain. It supports Brakedown and the masked
packed adapter without taking backend choices or parameters from proof bytes.
The existing complete versions remain available.

Trusted setup comes from `packed_pbs::canonical_setup`, using native evaluation
keys rather than execution-trace key columns. The standalone verifier receives
only trusted parameters, public setup, ciphertexts and the decoded proof. It
receives no trace, private PCS states or separately supplied endpoints.

## Bound data and stage composition

The parent binds the version, extension degree, expected setup, complete ordered
parameter contexts, public NAND statement, blind-rotation coefficient/evaluation
roots, decomposition-input roots, four accumulator roots and the final
accumulator. Masked public ciphertext fields are normalized before binding;
serialized final-accumulator fields must already be canonical. Later derived
and challenge-dependent helper roots retain their own stage framing before the
challenges that authenticate them.

The complete path checks:

- The external-product relation against original trusted bootstrapping-key
  roots and retained evaluation states.
- Every coefficient/evaluation NTT link against those same original sources.
- Canonical integer digits for both external-product halves, using reconstruction,
  zero borrow endpoints and extension-field transition lookups.
- Accumulator additions, actual-round continuity, public initial/final endpoints
  and duplicated-half decomposition links through the original source roots.
- Public negacyclic monomial products, including both original-coefficient NTT
  links and the verifier-derived rotation factors.
- Final native key switching in the original output key/dimension: known-table
  authentication of its randomized negative-a input root, all NTT/key-product
  links, canonical digits, and truncated output extraction with the original bias.

Proving uses the backend-retained tables and original key sessions. Temporary
transformed tables are released after commitment; intermediate shifts and
compressed source views are not recommitted. Each stage's source/context
selection is derived from trusted statement layout, not a proof-carried registry.

## Trusted reuse budgets

Parameters are supplied separately for coefficient, evaluation, key, input,
borrow, reciprocal-helper, accumulator and monomial roles, plus the final-stage
roles. Logical layouts must match the original FHE configuration. Physical
masking capacity may differ by role.

For width k and R comparison repetitions, blind-rotation digit coefficients need
k+1+R openings; the sum coefficient needs k+1. Evaluation sources need k+1 and
bootstrapping-key sources one. Each duplicated decomposition input needs two;
borrow endpoints need 1+R and interior borrows 1+2R. Reciprocal helper roots need
two. With M padded rounds, accumulator inputs need k+3+log2(M), monomial products
k+1, external inputs three and outputs two. Derived monomial evaluations need
k+1. Final-stage budgets are documented in `canonical-packed-key-switch.md`.
Sessions persist across these uses. Failure does not refund prior tickets.

`prove_with_statistics` records the complete existing phase boundaries. This
makes later native profiling possible; the current tests are not timing evidence
for the performance gate.

## Current evidence and remaining gates

Both selected masked field pairs pass encrypted N=32, LWE=21 NAND fixtures with
the original native output key. Proofs serialize, decode and verify independently
of the trace. The trusted key sessions spend one opening each. Root inventory
counts all declared source/helper slots, including the randomized key-switch
input: 76 for BabyBear/sextic and 132 for Goldilocks/cubic in these fixtures.
Brakedown version-10 controls cover all four NAND truth-table inputs over both
fields, yielding eight additional decoded complete certificates.

Version, count, endpoint, child-root and child-proof mutations are rejected.
These are compatibility/tamper controls, not fresh complete malicious-trace
certificates. A separate fresh complete accumulator-linkage audit now covers
both backends and fields; see `canonical-v10-fresh-linkage-audit.md`. Other attack
classes and secure encrypted/original-size cases still require full version-10
audit evidence. Existing component and legacy binding cases do not replace it.

The masked fixtures use one proximity query to test completeness. They are not
128-bit profiles, original-size native runs or security-matched measurements.
The standalone per-limb comparisons and adapter child packets do not establish
genuine 1/4/16 joint aggregation. Public endpoints, NTT folds and scalar/packed
algebra remain exposed; selecting masked authentication does not make the whole
protocol zero knowledge. Robust vector proximity, adaptive hiding, knowledge/
Fiat-Shamir composition, independent review and promotion remain open. The
original <=2x size and >=10% latency gates, confirmed twice at matched whole-proof
security, are unchanged and have not been achieved by this new path.

The selected validation passes 163 release/locked tests: 136 SNARK component
checks, twelve legacy complete-PBS tests, nine sumcheck tests, two NTT alias tests
and four version-10 complete-PBS tests. The latter serialize/decode two masked
certificates and eight Brakedown truth-table certificates. The masked fixture
sizes are 17,508,971 bytes (BabyBear/sextic) and 12,459,125 bytes
(Goldilocks/cubic); they are not security-matched native measurements. Sixty
legacy full binding cases retain six accepted controls and fifty-four rejected
attacks. The locked workspace check passes. Logs, checked records and validated
sources are under `target/performance/complete-canonical-backend-pbs-v10/`.
