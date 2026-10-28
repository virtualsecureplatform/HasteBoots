# Canonical final key switching

`packed_key_switch::canonical::protocol` composes native negative-a digits,
coefficient/evaluation NTT links, products with the trusted original switching
key, canonical decomposition and public LWE extraction through `CanonicalPcs`.
It preserves the existing native ring/output dimension restriction and the
original output key. The legacy entry points retain their formats.

Trusted parameters separately describe coefficients, evaluations, switching-key
sources, public input, borrow columns and reciprocal helpers. Their logical
layouts must agree with the native configuration; only the reciprocal helper
uses the scalar-domain variable count. Before challenges, the parent binds all
contexts, expected key roots/configuration, final accumulator, output ciphertext
and every private coefficient/evaluation/input root.

A masked public-input root cannot be recomputed by the verifier from public
values. The new protocol therefore authenticates it with a fresh known-table
query: the expected negative-a table, root and context are fixed before sampling,
and the verifier opens the response computed from that known table. The same
retained input session is then consumed by decomposition. This is an algebraic
known-word check, subject to the component PCS and matrix-query soundness
assumptions, not a deterministic equality test of root bytes.

Every evaluation root is linked to its coefficient root by the existing
canonical NTT protocol. The product relation borrows those retained evaluation
states and the retained original key states. Decomposition enforces canonical
integer digits against the authenticated public input. Extraction uses the
shared native mask/target construction, including the original truncated a
coordinates, body correction and NAND bias; it authenticates the sum coefficient
root. Public input and extraction arithmetic share their original helper code
with legacy proving and verification.

For packed width k and R comparison repetitions, each digit coefficient needs
k+1+R openings; the sum coefficient needs k+1; every evaluation needs k+1; each
key source needs one; public input needs two; borrow endpoints need 1+R and
interior borrows need 1+2R; each reciprocal root needs two. Retained states are
reused across all of these phases. Failures do not refund earlier tickets.
Canonical PBS setup exposes read-only access to its original switching-key
owner and public descriptor for this final-stage API.

This completes the canonical final-stage component, not a complete masked PBS
proof. Shared/deferred comparisons, genuine joint aggregation, robust vector
proximity, general adaptive hiding and whole-proof security remain open. Public
NTT folds, terminal algebra and endpoints are still disclosed. No original-size
native or security-matched performance promotion is claimed here.

## Validation

N=32, LWE=21 fixtures derive the original negative-a digit columns, native key
products, inverse-transformed sum and truncated public output independently of
the prover. Each fixture checks its frequency/coefficient NTT round trip. Both
selected masked field pairs and Brakedown must serialize, decode and verify the
complete final-stage component. Tests check opening indices across NTT,
products, decomposition and extraction, plus retained key counters. Missing or
changed roots, omitted subproofs, changed public outputs and foreign randomized
key setups are rejected.

Two fresh false-public-input certificates bind the requested known-table prefix
but open the actual committed response of a different table. Strict reference
PCS replay accepts each genuine child opening under the requested prefix and
root. Production's known-table verifier rejects the expected response. This
specifically tests the new randomized-input binding, beyond replaying an honest
proof with a changed endpoint.

The structured Goldilocks fixture exposed a concrete NTT lazy-residue boundary
bug. The separate fix and independent forward/inverse definition tests are
documented in `goldilocks-ntt-aliases.md`.

All 159 selected release/locked regressions pass: 136 SNARK component tests,
nine sumcheck tests, twelve complete v7/v8/v9 PBS tests and two independent
Goldilocks NTT alias regressions. Both masked final-stage proofs decode and
verify, at 4,540,255 bytes for BabyBear/sextic and 3,491,307 for Goldilocks/cubic
in these N=32 fixtures. These sizes are not security-matched native measurements.
Two fresh false-public-input certificates pass genuine child verification and
fail the known-table check. Sixty fresh full binding cases retain six accepted
controls and fifty-four rejected attacks. The locked workspace check passes.
Logs, checked records and validated sources are under
`target/performance/canonical-packed-key-switch-boundary/`.

A separate shared-comparison final-stage entry point is now available; see
`canonical-shared-key-switch.md`. It retains this path's known-input, NTT,
native-key product and extraction checks while sharing canonical limb queries.
The per-limb proof spelling and frozen serialized bytes remain compatible.
