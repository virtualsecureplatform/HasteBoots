# Shared-query extension lookups

`packed_extension_lookup::shared` proves multiple trusted tuple-lookup requests
against an ordered registry of original source roots. All sources must have the
same complete PCS parameter context. Requests can select different source slots,
public tables, repetition counts and logical prefixes. Helper geometry must match
the common scalar domain. This opt-in, non-hiding component does not change any
existing complete PBS format. Opt-in complete version 8 now composes it within
each decomposition; see `packed-shared-pbs.md`.

Every source context, root and trusted request is bound before grouped
multiplicities and extension compression challenges. All reciprocal helper roots
are fixed before independent equality points are sampled. The sum of each helper
and its equality-weighted reciprocal constraint then enter one scalar sumcheck
batch, as separate equations of degree one and three (four for partial domains).
All round messages precede each common full-extension challenge.

There is one helper value at the common terminal point, used for both equations.
The verifier checks its sum subclaim, reconstructs the reciprocal identity from
that same value and the original source claims, and authenticates both kinds of
claims. One canonical multi-root packet opens all coefficient helpers at their
common matrix query; another opens the original sources at their common pulled
query. Alias decisions come from trusted contexts and exact roots. Neither source
IDs nor routing decisions come from the proof. The helper/query bridge preserves
its lane-selector order and partial-domain mask.

The prover releases row indices after helper construction, coefficient buffers
after commitments, and the original scalar polynomial buffers after sumcheck.
It retains the commitment states until authentication finishes. Peak memory still
grows with helper count. Version 8 integrates individual decompositions; future
cross-statement composition needs bounded grouping and retained canonical
comparison witnesses. Those steps, native measurements, complete security analysis
and promotion remain unfinished.

## Validation

Both selected field profiles pass decoded public verification at request counts
1, 4 and 16. Fixtures mix one/two-column requests, one/two repetitions, full and
partial domains, and duplicate original roots. Proof and verifier transcript
challenges agree. Mutations of values, helpers, algebra, source-slot order,
counts and parameter contexts reject.

Six fresh adversarial certificates cover a control and an illegal source in the
first or last request for each field. Their scalar helper algebra and actual-root
PCS packets pass local reference verification under the requested registry. All
four illegal-source proofs then fail the public reciprocal identity, while both
controls pass. These are reconstructed helper proofs, not replayed honest proofs
with changed transcript labels. Their decoded audit records are preserved as
`HB_SHARED_LOOKUP_BINDING_CASE`.

A toy sixteen-request comparison verifies both the old deferred protocol and this
frontend on identical trusted inputs. It uses 22 helpers, three source slots with
two unique roots, and 128/32 scalar cells for BabyBear/Goldilocks, respectively.
The shared packet is 312,223 bytes versus 457,932 bytes for BabyBear and
187,226 bytes versus 219,441 bytes for Goldilocks. All 21 targeted lookup tests
and the VFHE library check pass. The final buffer-lifetime cleanup preserves
these packet sizes. It is a component size comparison, not native-capacity or
security-matched PBS performance evidence. Artifacts are in
`target/performance/shared-extension-lookups/`.
