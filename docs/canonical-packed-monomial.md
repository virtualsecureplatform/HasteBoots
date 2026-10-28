# Public monomial products over canonical backends

`packed_monomial::canonical` authenticates the caller's exact negacyclic
rotations against retained canonical coefficient sources. Trusted evaluation
parameters are an explicit caller input. The transcript binds their full
context, both coefficient contexts/roots, the public rotation plan and the NTT
root before any algebraic challenges. Logical dimensions must match the native
plan; physical masking capacities and lifetime budgets may differ.

The prover transforms each actual retained coefficient table, commits the two
derived evaluation sources with private cryptographic randomness, and links each
new root to its original coefficient root through the canonical NTT protocol.
The temporary transform tables are released after commitment. Product ZeroCheck
borrows the retained evaluation tables and the public monomial table instead of
cloning both derived witnesses.

Verification checks both NTT links, derives the monomial value from the trusted
plan, checks the product terminal identity, and authenticates both terminal
values against the derived roots. Proof metadata cannot replace coefficient
roots, trusted evaluation parameters or public exponents. Serialized masked
terminal values must have canonical encodings.

With width k, each coefficient source spends k NTT openings. Each derived
evaluation source spends k NTT openings followed by one product opening from
the same retained session. Aliased coefficient roots share their original
lifetime budget. A later-stage failure does not refund earlier tickets. Derived
witness roots are fresh per proof; the original coefficient sources are not
refreshed by this operation.

The existing optimized Brakedown entry points and formats remain available.
The new canonical entry point has distinct framing, even for Brakedown. Masked
packets still use independent child openings. Public folded NTT polynomials,
ZeroCheck messages and terminal algebra remain exposed; this integration does
not establish zero knowledge. Complete masked PBS composition, genuine joint
aggregation, robust vector proximity and whole-proof security/performance
promotion remain open.

## Validation

Both selected field pairs serialize, decode and verify width-one single-round
and width-two padded six-round products. Rotations include 0, 1, N-1, N, N+5
and 2N-1. Tests check coefficient counters and the derived roots' consecutive
NTT/terminal opening indices. Exhausted coefficient sessions cannot be refreshed
by another invocation. Changed plans, derived roots, evaluation contexts,
terminal values and missing child packets are rejected. A separate Goldilocks
case rejects an equal-valued noncanonical terminal encoding. Brakedown also
passes a decoded canonical round trip.

Fresh wrong-rotation certificates bind the requested plan but use valid algebra
for another public rotation. Both NTT children, the foreign-factor ZeroCheck
and all ten actual-root openings pass strict reference replay. The production
verifier rejects the requested public-factor terminal identity. Aliased source
roots retain counters across both NTT children and the product openings.

All 132 selected release/locked regressions pass: 111 SNARK component tests,
nine sumcheck tests and twelve complete v7/v8/v9 PBS tests. Four decoded masked
monomial cases authenticate 32 child openings; two fresh wrong-rotation
certificates authenticate another twenty before failing the public-factor
identity. The sixty fresh full binding cases retain six accepted controls and
fifty-four rejected attacks. The locked workspace check passes. Logs, checked
records and validated sources are under
`target/performance/canonical-packed-monomial-boundary/`.
