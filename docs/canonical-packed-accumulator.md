# Canonical accumulator linkage

`packed_accumulator::prove_canonical` and `verify_canonical` use statically
selected `CanonicalPcs` sources for the existing accumulator linkage protocol.
The legacy API is an alias over the same implementation and retains its original
Brakedown transcript domain and packet encoding. The masked API uses a distinct
backend-selected domain.

The transcript binds trusted native shape, initial and final accumulators, and
every ordered source context and expected root before sampling matrix queries.
All sources must have the same logical dimensions. Physical masking capacities
may differ. The public endpoints are normalized under the selected backend;
serialized masked terminal values must already be canonical.

The arithmetic and query maps remain shared: external input equals monomial
product minus input accumulator; output equals input plus external-product sum;
decomposition inputs equal the duplicated a/b halves; first and last active
rows equal the expected public endpoints; and the ordered shift queries enforce
continuity through active rounds with the existing padding correction. No
shifted or duplicated witness source is recommitted.

Proving reads actual tables retained by canonical source states. The legacy
wrapper preserves its caller's cached table references. Each source opens its
complete ordered query packet against its original root. The input accumulator
needs `3 + log2(padded_rounds)` child openings, including the wrap branch; the
external input needs three, output needs two, and other sources need one each.
Reuse budgets must count all of these, even when query points repeat. Later
source failures do not refund tickets already spent by earlier sources.

This component still exposes its algebraic terminal values. A masked PCS does
not make the enclosing linkage protocol zero knowledge. Complete masked PBS
composition, genuine joint aggregation, robust vector proximity and the full
security/performance promotion gates remain unfinished.

## Validation

The selected fields exercise single-round and padded 3/5-round relations, with
mixed physical capacities and decoded masked authentication packets. Frozen
pre-refactor code checks legacy proof bytes and final prover/verifier transcript
challenges for every case. Negative controls change an endpoint or root, mutate
a terminal and remove an opening. A Goldilocks codec check accepts equal-valued
public endpoint aliases after normalization and rejects noncanonical serialized
terminal encodings.

Fresh false-endpoint and broken-continuity certificates are built under the
requested shape, endpoints and source roots. All child openings are genuine and
pass strict public PCS replay. Production must reject the endpoint/continuity
equation itself. Honest proving of these false relations fails before spending
an opening ticket. Existing explicit noncommuting query-map tests and full PBS
binding regressions remain part of validation.

All 123 selected release/locked regressions pass: 102 SNARK component tests,
nine sumcheck tests and twelve complete v7/v8/v9 PBS tests. The six decoded
masked cases authenticate 82 child openings; four fresh false-linkage
certificates authenticate another 56 before failing production equations. Six
legacy wire/transcript controls pass. The sixty fresh full binding cases retain
six accepted controls and fifty-four rejected attacks. The locked workspace
check passes. Logs, checked records and validated sources are under
`target/performance/canonical-packed-accumulator-boundary/`.
