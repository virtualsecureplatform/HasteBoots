# Shared relations over canonical backends

`packed_relation::batch::backend` proves independent polynomial identities with
one shared ZeroCheck challenge schedule, then authenticates every terminal using
`CanonicalOpeningBatch`. The caller supplies ordered groups of retained source
oracles. Group sizes, factor order, relation coefficients and logical geometry
come from the statement, not the proof.

Before any ZeroCheck coins, the transcript binds normalized trusted shapes and
the full ordered registry of parameter contexts and expected roots. All groups
must share logical variable count and lane width. Physical capacities and reuse
budgets may differ per source. Proving borrows actual backend-retained tables;
no intermediate source views are committed. Each terminal identity is checked
separately before authentication, including each factor's response encoding.

The registry aliases roots only under equal full parameter contexts, binds every
ordered claim and opens each used canonical source once with its ordered query
packet. Masked root aliases consume the original retained session's lifetime
budget. There is no multi-root transaction: a later source failure can consume
earlier sources' tickets. The caller must provision budgets for every factor
occurrence, including repeated queries to an aliased root.

This is an additional backend entry point. The existing Brakedown multi-root
aggregation paths and their transcript formats remain intact. The new entry
point uses each backend's existing packet implementation. In particular the
masked adapter still emits independent child openings; 1/4/16 relation tests do
not establish genuine joint cryptographic aggregation or native PBS performance.
ZeroCheck algebra remains public and non-hiding. Complete-PBS setup integration,
robust vector proximity, adaptive hiding and whole-proof security remain open.

## Component validation

Both BabyBear/sextic and Goldilocks/cubic tests serialize, decode and verify
1/4/16 relation schedules over partial lanes, totaling 126 masked child
openings. Repeated factors reuse the same retained sessions and exhausted
budgets cannot be refreshed by a second group. Missing algebra instances,
changed coefficients, mutated terminals and missing packets are rejected.
A Brakedown round trip checks equal-root deduplication and rejects swapped
factor roles.

Two fresh opposite-residual certificates use committed factors whose pointwise
errors are +1 and -1. The adversary supplies satisfying foreign ZeroCheck
messages, then produces genuine child openings of the actual factors under the
requested roots. Independent strict registry replay accepts all twelve child
openings across both fields. Production rejects the individual terminal
identities. The original false-relation prover fails before spending a ticket;
the forged certificates consume exactly four tickets for the aliased root and
one each for the other roots.

All 108 selected release/locked regressions pass: 87 SNARK component tests,
nine sumcheck tests and twelve complete v7/v8/v9 PBS tests. The sixty fresh full
binding certificates retain six accepted controls and fifty-four rejected
attacks. The locked workspace check passes. Logs, checked records and validated
sources are under `target/performance/canonical-shared-relation-boundary/`.
