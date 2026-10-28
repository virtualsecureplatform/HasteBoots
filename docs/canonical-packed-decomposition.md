# Radix decomposition over canonical backends

`packed_decomposition::canonical` composes canonical linear authentication and
extension-field tuple lookups over the original retained source/digit roots.
The original decomposition APIs remain available. This canonical entry point
uses distinct framing and explicit trusted borrow/helper parameters.

Before challenges, the transcript binds the radix, active length, repetitions,
prime characteristic, extension degree, all original root contexts, and the
borrow/reciprocal helper contexts. Logical source dimensions must match; the
reciprocal helper uses the original scalar-domain variable count. Physical
masking capacities and reuse budgets may differ without changing FHE geometry.

The prover constructs one borrow chain for subtraction of the digit string from
p-1. It rejects out-of-range digits and a nonzero final borrow. Borrow columns
are committed once with private cryptographic randomness. A canonical linear
check enforces x = sum B^i*d_i and zero initial/final borrow columns. Each limb's
extension lookup checks its original digit and adjacent borrow roots against the
trusted transition table, enforcing integer canonicity in addition to field
reconstruction. No replacement digit or compressed source commitment is used.

With R comparison repetitions per limb, the original source needs one opening,
each digit needs 1+R, initial/final borrow roots need 1+R, and interior borrow
roots need 1+2R. Every reciprocal helper root needs two openings. Borrow states
remain the same through reconstruction and neighboring limb comparisons; an
oracle borrow cannot refresh their counters. Failures do not refund earlier
openings. Source and helper budgets are trusted setup choices.

This per-limb path is integrated into complete version-10 PBS. An additional
shared-comparison entry point is documented in `canonical-shared-decomposition.md`;
its complete key-switch/PBS integration remains open. Public
linear, lookup and multiplicity algebra remains exposed. No general hiding,
robust vector proximity, whole-proof security certificate or new native
performance/promotion claim follows from this integration.

## Validation

Both selected field pairs serialize, decode and verify partial-domain
reconstructions containing 0, 1, p-1, p-2, a small value and p/2. Tests check source
and digit lifetime counters and the exact borrow opening indices across the
linear check and adjacent comparisons. Missing roots/limbs, changed linear or
lookup terminals, different borrow contexts and exhausted source sessions are
rejected. The Brakedown backend also passes a decoded canonical round trip.

Fresh noncanonical certificates use integer digits for p and an actual source
of field zero. Reconstruction is therefore correct modulo p, and every
subtraction transition is valid, but the final borrow is one. Independently
replayed linear source openings and strict extension comparison proofs all
verify under the requested prefix and original roots. Production rejects the
false final zero-borrow identity. Honest proving rejects the same digit string
before spending any source opening. Borrow counters reach two at endpoints and
three at interior limbs, demonstrating that adjacent comparisons reuse the
original states.

All 151 selected release/locked regressions pass: 130 SNARK component tests,
nine sumcheck tests and twelve complete v7/v8/v9 PBS tests. Two decoded masked
decompositions authenticate 88 child openings; two fresh noncanonical-integer
certificates authenticate another 88 before failing the final borrow-endpoint
identity. The sixty fresh full binding cases retain six accepted controls and
fifty-four rejected attacks. The locked workspace check passes. Logs, checked
records and validated sources are under
`target/performance/canonical-packed-decomposition-boundary/`.
