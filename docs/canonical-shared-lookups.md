# Shared extension lookups over canonical backends

`packed_extension_lookup::canonical::shared` proves an ordered group of trusted
lookup requests at one scalar extension-field point. It retains the existing
independent sum and reciprocal-identity equations through `sumcheck::batch` and
reuses the legacy shared challenge-schedule helpers. Every request keeps its
own tuple compression challenges, public multiplicities and prefix mask.

The new parent domain binds normalized trusted requests, extension degree,
helper context and each request's source contexts/roots. A canonical opening
registry also binds every source slot, including unused slots, before the child
seed and lookup challenges. Sources share logical dimensions; their physical
mask capacities and complete parameter contexts may differ. No combined source
view or extra source commitment is introduced.

All helper roots precede equality and sumcheck challenges. The common point
pulls back to one canonical source query and one coefficient-helper query.
The same authenticated helper value must satisfy its independent sum and
reciprocal equations. Helper terminal scalars, multiplicities and masked source
responses are checked for canonical encodings. As with the standalone path,
this is not a canonical encoding theorem for every scalar sumcheck message.

Each helper uses one retained session and one opening. Each used distinct
(context, root) source pair authenticates one common-query claim. Used alias
slots must report equal terminal vectors and reuse that claim. Unused slots
have fixed zero terminal placeholders and spend no source allowance, but their
contexts/roots remain transcript-bound. A later failure does not refund earlier
helper or source openings. Private cryptographic randomness commits every helper.

The standalone canonical lookups, legacy shared/deferred protocols and complete
version-10 PBS format remain available unchanged. Canonical radix decomposition
now has a shared-comparison entry point; see
`canonical-shared-decomposition.md`. A shared final key-switch entry point is
documented in `canonical-shared-key-switch.md`; complete version-11 PBS now
integrates this component. Memory grows
with the number of reciprocal helpers; callers must bound native-size groups.
The masked adapter still emits independent child PCS proofs. Shared algebra
and fewer queries do not establish genuine 1/4/16 joint aggregation. Public
multiplicities and sumcheck algebra remain non-hiding; robust vector proximity,
adaptive hiding, knowledge/Fiat-Shamir composition, original-size performance,
matched-security bytes and promotion remain open.

## Validation

Both selected field pairs pass decoded masked and ordinary round trips over
full and partial domains with multiple requests and repetitions. Masked tests
include different physical source contexts, root aliases, an unused registry
slot, exact lifetime counters and exhaustion. Mutated source/helper terminals,
helper roots, missing packets, changed request order, changed unused slots and
out-of-range source indices reject.

Fresh foreign-source certificates generate satisfying algebra from a different
witness, then authenticate the actual retained source and helper roots under
the requested transcript. Strict reference replay authenticates all three child
openings per field and checks every scalar equation except the disputed source
terminal identity. Production rejects that identity; ordinary proving rejects
the nonmember before spending a source opening. Only test builds instantiate
the private relaxed specialization; no proof flag selects relaxed verification.

The direct comparison uses identical trusted parameters, original source roots,
logical tables and request schedules for shared and standalone canonical proofs.
Both serialized forms verify. Two source openings plus three helper openings
replace five source openings plus six helper openings: five child PCS proofs
instead of eleven. Serialized comparison bytes are:

| Field | Standalone | Shared |
| --- | ---: | ---: |
| BabyBear/sextic | 338,765 | 155,601 |
| Goldilocks/cubic | 250,364 | 115,039 |

These small one-proximity-query fixtures are component
comparisons, not secure original-size or complete-PBS performance measurements.

All 70 default release/locked SNARK unit tests and nine sumcheck tests pass
(79 tests); the 30 expensive full masked certificate audits remain opt-in.
The locked workspace check passes.

The validation archive is `target/performance/canonical-shared-lookups/`, including
checked records, release/locked test logs, workspace check and exact sources.

Complete version-11 integration is now available through
`packed_pbs::canonical::shared`; see `canonical-shared-complete-pbs.md` for its
validation and remaining security/performance gates.
