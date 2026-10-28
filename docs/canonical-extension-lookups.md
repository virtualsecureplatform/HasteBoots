# Extension lookups over canonical backends

`packed_extension_lookup::canonical` retains the extension-field rational lookup
protocol and replaces its concrete Brakedown source/helper authentication with
`CanonicalPcs`. The original Brakedown and shared/deferred entry points remain
available. The canonical entry point has a distinct parent domain.

Before challenge sampling, the parent binds the trusted public tuple table,
logical length, independent repetition count, extension degree, helper context
and every original source context/root. The child transcript uses direct
extension sampling with the existing complete basis convention and is seeded
from the parent after multiplicities are fixed. Its final digest binds the
algebra before PCS opening randomness.

Each repetition checks the public multiplicity-weighted reciprocal total, a
scalar extension sumcheck and an equality-weighted reciprocal identity. Partial
domains retain their prefix mask. The original extension-to-base pullback maps
the scalar identity subclaim to the source's canonical matrix query, preserving
matrix order. No compressed or broadcast source root is committed.

Coefficient-packed reciprocal helpers are committed once per repetition using
private cryptographic randomness. Their two sum/identity subclaims open through
the same retained helper session. Original source states spend one opening per
repetition from their existing lifetime budget. Source parameters may have
different physical masking capacities while retaining the same logical shape.
Helper failure or a later source failure does not refund earlier openings.

Trusted table entries and public multiplicities/source terminals are normalized
under the selected backend. Serialized masked multiplicities and source
responses must already be canonical; the explicit extension sum and helper
terminal scalars are canonicalized as well. This does not establish a canonical
encoding theorem for all existing scalar sumcheck messages.

This entry point is a standalone lookup component, not yet the shared/deferred
comparison composition for a complete masked PBS proof. It retains public
algebra and multiplicities and does not establish zero knowledge, robust vector
proximity, genuine joint aggregation or whole-proof 128-bit security. Native
security-matched size/latency gates and full PBS promotion remain open.

## Validation

Both selected field pairs exercise constant-variable and full/partial-domain
lookups with one and two independent repetitions. Serialized/decoded packets
verify against original source roots and coefficient-packed helper roots.
Tests check two consecutive openings per helper, source lifetime counters,
exhaustion, changed public tables, mutated terminals, missing packets and changed
helper roots. The Brakedown backend also passes a decoded canonical round trip.
Goldilocks coverage checks normalized trusted-table aliases and rejection of
equal-valued noncanonical multiplicities and source responses.

Two fresh foreign-source certificates use satisfying foreign witness tables
only for algebra construction. Every opening authenticates the actual retained
source and helper roots under the requested prefix. Strict reference replay
checks every scalar child and PCS packet, skipping only the disputed terminal
source equation. Production rejects that equation; ordinary proving rejects the
nonmember before spending a source opening. Only test builds instantiate the
private relaxed terminal-check specialization; no proof flag selects it.

All 146 selected release/locked regressions pass: 125 SNARK component tests,
nine sumcheck tests and twelve complete v7/v8/v9 PBS tests. Six decoded masked
lookup cases authenticate forty child openings; two fresh foreign-source
certificates authenticate another twelve before failing the source-terminal
identity. The sixty fresh full binding cases retain six accepted controls and
fifty-four rejected attacks. The locked workspace check passes. Logs, checked
records and validated sources are under
`target/performance/canonical-extension-lookup-boundary/`.
