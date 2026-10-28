# Full-plan implementation ledger

Objective: implement every item in the agreed performance plan. This ledger does
not change its success criteria: complete PBS semantics, unchanged FHE parameters
and output key, a complete 128-bit proof-security argument, <=2x security-matched
baseline bytes, and >=10% complete single-PBS latency improvement confirmed twice.

## Current evidence

Fresh complete v10 bootstrapping/switching-key product, linkage, rotation and extraction certificates pass strict child and
actual-root replay on both backends and selected fields. Four controls are
accepted and forty-four key-product/endpoint/addition/continuity/digit-view/rotation/extraction attacks are
rejected after fresh proof construction. See `canonical-v10-fresh-linkage-audit.md`.
Other complete attack classes, secure encrypted/original-size audits, joint
aggregation and security/performance promotion remain open.

Version 10 now composes every original NAND PBS stage through canonical PCS
backends. Both masked field pairs pass serialized/decoded encrypted N=32, LWE=21
complete proofs, and Brakedown controls cover all four NAND inputs over both
fields. See `canonical-complete-pbs.md`. Fresh complete v10 binding certificates,
genuine joint aggregation, original-size native profiles, general hiding and
whole-proof security/performance promotion remain open.

The native final key-switch stage now composes canonical NTTs, original-key
products, canonical negative-a digits and original output extraction. A fresh
known-table opening binds the randomized public-input root that the verifier
cannot deterministically recompute. See `canonical-packed-key-switch.md`.
Complete masked PBS composition and the original security/performance gates
remain open.

Canonical radix decomposition now composes retained source/digit roots,
canonical reconstruction/borrow-endpoint checks and extension-field transition
lookups, with explicit trusted borrow/helper budgets across adjacent limbs. See
`canonical-packed-decomposition.md`. Shared/deferred composition, final-stage
integration and the original full security/performance gates remain open.

Extension-field rational lookups now expose canonical backend authentication
for original sources and coefficient-packed reciprocal helpers, retaining the
existing scalar extension algebra and base-field pullback maps. See
`canonical-extension-lookups.md`. Shared/deferred comparison composition and
complete masked PBS integration remain open.

Public monomial products now have a canonical backend entry point, composing
both original-source NTT links with the caller-derived public rotation identity.
Derived roots retain one bounded session across NTT and terminal openings. See
`canonical-packed-monomial.md`. Full masked PBS composition and the original
security/performance gates remain open.

Accumulator linkage now dispatches through canonical backend sources while
sharing the original endpoint, continuity and duplicated-half equations. Legacy
callers retain their proof shape; masked callers authenticate ordered queries
against retained source sessions. See `canonical-packed-accumulator.md`.
Remaining PBS stages and full masked composition still need integration.

Native bootstrapping/switching key owners and their complete-PBS setup wrapper
now support statically selected canonical backends, retaining original source
states and validating native layouts plus all logical parameter geometries.
Public setup remains independent of proof bytes. See
`canonical-native-key-setup.md`; masked complete-proof composition and the
original security/performance gates remain open.

Shared-challenge polynomial identities now expose canonical backend
authentication through the source registry, with retained borrowed factors and
individually checked terminal equations. Existing optimized Brakedown paths are
preserved. See `canonical-shared-relations.md`. Masked child openings remain
independent; genuine joint aggregation and complete-PBS integration remain open.

Single polynomial-relation authentication now has a canonical backend entry
point. It borrows retained source tables, binds every ordered parameter context
and root before ZeroCheck, and preserves legacy framing through typed wrappers.
Both fields pass decoded masked proofs, frozen legacy wire controls and fresh
false-relation certificates with genuine source openings. See
`canonical-packed-relation.md`. Shared/batched relations, setup ownership and
whole-proof security remain open.

Packed NTT source authentication now dispatches through the canonical backend
boundary. Shared shape logic retains the original logical transform dimensions;
masked physical padding cannot silently change them. Eight legacy byte/transcript
controls and both fields' decoded masked forward/inverse-derived cases pass.
Fresh false-transform certificates have genuine source openings and fail the
NTT equation. All 90 selected component/complete-PBS tests and the locked
workspace check pass, including sixty fresh full binding cases. See `canonical-packed-ntt.md`; remaining relation/setup
boundaries and whole-proof security remain open.

Canonical linear identities now dispatch through the packed backend boundary,
with legacy Brakedown API/wire controls and a masked variant using the retained
source sessions. Both selected fields pass decoded proofs and fresh false-identity
certificates whose genuine child openings all verify. All 85 selected component/
complete-PBS tests and the locked workspace check pass. See
`canonical-packed-linear.md`; the remaining concrete
transform/relation/setup boundaries and whole-proof security are still open.

The deferred canonical opening registry now uses a statically selected PCS
boundary shared by Brakedown and the masked packed adapter. Legacy API aliases
retain their wire/transcript behavior against a frozen pre-refactor reference.
Masked aliases share lifetime counters, unused sources spend nothing and failed
later roots do not refund prior openings. All 78 selected component/complete-PBS tests and the locked workspace check pass,
including sixty fresh full binding cases. See `canonical-packed-backends.md`.
Remaining concrete relation/setup types still need generalization before masked
complete-PBS integration can be claimed.

A masked direct packed matrix adapter now retains one logical base table,
canonical extension root and locked private mask session. It binds complete
contexts and ordered claims, uses direct extension child transcripts and checks
the entire batch budget before mutation. All 74 selected release tests pass,
including 42 decoded openings at 1/4/16-query schedules over both selected fields.
These are independent child openings on synthetic tables, not joint aggregation
or complete PBS. See `masked-packed-adapter.md`; complete-PBS backend
abstraction, joint query sharing, general masking and whole-proof security remain
open.

The experimental direct packed backend now has a revision-2 canonical encoding
contract. Goldilocks and extension coordinates normalize before the new oracle
and scalar-message encodings, with verifier rejection of noncanonical proof
entries. The field hooks preserve nonbase extension coordinates and existing
BabyBear Montgomery encoding. Scalar ordinary/virtual-first behavior and complete
PBS formats retain their existing paths. All 71 selected field/PCS/adapter/encoder
tests pass, including base/cubic byte-equivalent proofs and eight repeated rank
cases. General masking and whole-proof security
remain open; see `masked-packed-polyfrim.md`.

Direct packed PolyFRIM now has an experimental bounded-reuse masked reference.
Private high coefficients and an independent vector mask protect the intended
public-fold view, with separate same-root checks on source/mask lanes and the
virtual combined ladder. Session counters prevent silent mask refresh; numerical
capacity is checked. All 63 selected release tests pass, including sixteen
decoded masked packets and four fresh false-claim certificates. This is
implementation progress, not a hiding theorem or
native complete-PBS result. A new coefficient-space audit checks cumulative
field disclosures against actual decoded two-opening transcripts, with negative
controls. All eight rank cases and all 65 selected release regressions pass.
See `masked-packed-polyfrim.md`; general masking, quantitative soundness
and adaptive hash/Fiat–Shamir analysis remain open.

The direct packed PolyFRIM algebraic core now converts canonical Boolean tables
to vector-polynomial coefficients, applies ordered matrix folds and computes
antipodal consistency symbols without the scalar bridge's extra sumcheck.
High-variable padding preserves the terminal matrix response. A new authenticated
consistency ladder binds all layer roots/query/claim before sampling and checks
all lane transitions against exact packed Merkle roots. An experimental same-root rolling-proximity composition now projects each
packed layer and authenticates every virtual scalar query through those exact
packed roots. All 58 selected release PCS/adapter/encoder tests pass, including
32 combined packets and six fresh same-root/proximity forgery certificates.
Quantitative vector-proximity/composition analysis and hiding
remain open; this is not a certified evaluation-binding PCS or a completed
security gate. See `packed-polyfrim.md` for the construction and remaining obligations.

Independent scalar round messages now run in parallel over immutable arithmetic
metadata, with ordered collection before each common challenge. Four scalar tests
include 54 byte-exact reference certificates / 378 equations over both fields and
1/4/16-worker pools; all 62 selected Rust tests pass. All 210 toy wire-controlled
member instances remain exact. Original-size exact-wire validation now passes all six 1/4/16 certificates
(42 fresh members), preserving every proof byte/hash under
`target/performance/parallel-scalar-native/`. Clean repeated complete timing
improves 35.44–36.26% on BabyBear and 24.56–24.63% on Goldilocks across
reversed orders; all sixteen proofs verify. These conditional-profile engineering
results do not establish fully security-matched promotion. See `shared-scalar-folds.md`.

Complete-v9 phase statistics and repeated single-proof benchmarking are now
implemented with digest-linked phase/parent checks. All 96 Python checks and two
complete timed/untimed byte-equality fixtures pass. Twelve archived toy packets
remain exact and eight repeated single proofs verify. The clean sixteen-proof
pooled experiment improves complete latency only 8.05–8.42% BabyBear /
7.87–8.05% Goldilocks across reversed orders, below 10%. It measures the earlier
sequential-message build. See `joint-pbs-phases.md`; full-security matching is open.

Twenty fresh normal-key v9 certificates now cover false inputs/outputs, foreign
evaluation keys, accumulator endpoints, chain splices and duplicated views.
Two controls accept and eighteen attacks reject over both fields. All twelve
selected v7/v8/v9 integration tests pass. These small fixtures supplement the
separate helper-source audit; they are not a whole-proof security argument.

Shared scalar sumcheck now borrows the first round and pools folded sources by
immutable object identity. All four scalar-batch tests compare against independent
per-equation behavior, including byte-exact reference proofs; all fifty SNARK
unit tests pass. This removes redundant helper state copies/folds without merging
equations or changing the wire protocol. All 62 selected Rust tests pass, including complete v8/v9 integration and
bounded decomposition batches. All 210 toy wire-controlled member instances remain byte/hash exact across
versions 5–9. All six pooled native 1/4/16 certificates now verify, covering 42 fresh member
statements, with exact pre-pooling proof bytes/hashes and archived fixtures
matched under `target/performance/scalar-shared-fold-native/`. Paired performance
measurement is separate; see `shared-scalar-folds.md`.

Ten fresh complete-v9 helper-binding certificates now pass: two controls accepted
and eight foreign-helper attacks rejected across both stages/member positions.
All actual-root openings and other equations pass local reference checks. These
small zero-key algebraic fixtures do not close every whole-v9 adversarial scenario.
See `packed-comparison-batches.md` and `target/performance/comparison-batch-audit/`.

Version 9 now composes shared comparisons across complete PBS statements with
mandatory outer Hadamard, blind-rotation and key-switch packets. Ten selected
release tests pass, including 52 decoded v9 members over both fields. Its trusted
grouping, ownership and remaining validation gates are documented in
`packed-comparison-batches.md`. Digest-linked whole-v9 root inventories now
include outer helpers, and the
strict log validator checks the trusted group schedule. All 89 Python checks and
two updated integration fixtures pass. Twelve v6/v7 toy wire controls remain
exact; six new v9 toy packets verify 42 member instances. Original-size frozen
validation now completes all six v9 certificates, covering 42 fresh statements
with archived fixtures matched under `target/performance/comparison-batches-native/`.
At sixteen members, bytes fall 14.17%/27.31% versus v7; observed process peaks
are 27,624,876/76,602,808 KiB. These are pre-pooling correctness results, not
paired timing or whole-security matching. Reviewed whole-v9 security remains open.

Paired native v5/v8 timing completed sixteen decoded proofs in two execution
orders without overlapping builds/tests. Complete latency improves only
1.72–2.05% on BabyBear and 2.43–3.36% on Goldilocks, below the 10% gate.
See `shared-pbs-timing.md`; these profiles are not whole-security matched.

Streamed canonical decomposition batches now share comparisons across trusted
groups of at most four independent members. Reconstruction/endpoints remain
individual, while borrow states move into a group owner and are released after
its comparisons. Decoded 1/4/5/16 tests pass over both selected fields, with mixed
radices, repetitions and logical prefixes. Six reconstructed batch certificates
pass (two controls accepted, four noncanonical-digit attacks rejected), as do
seventeen targeted Rust tests and all 84 current v5/v8 wire controls. This is a
component now used by the experimental complete version-9 composition.
See `batched-decompositions.md`.

Complete opt-in version 8 now uses shared-query comparisons in both
blind-rotation decompositions and final key switching, while retaining all
other PBS constraints and the original output key. Twenty-five targeted Rust
tests and 88 Python checks pass, including 42 fresh decoded v8 test certificates
and twenty reconstructed malicious/control certificates. Frozen toy runs verify
84 certificates: all 42 v5 wire controls remain exact, and 42 v8 proofs match
archived statements, keys, FHE parameters and layouts. Aggregate toy bytes fall
1.56%/2.31% versus v5. Original-size validation now passes all 42 fresh statements
with archived fixtures matched. Native total bytes fall 7.24%/22.57% versus v5;
paired timing misses the 10% gate and whole-security gates remain open.
Version 8 uses within-proof sharing; version 9 adds cross-statement comparison
aggregation without claiming whole-security/performance promotion. See `packed-shared-pbs.md`.

The shared-query extension lookup frontend is implemented as
`packed_extension_lookup::shared`: each reciprocal sum and identity is checked
separately at a common scalar point, then two canonical multi-root packets
authenticate all source/helper claims. All 21 targeted lookup tests and the VFHE
check pass, including decoded 1/4/16 fixtures and six fresh foreign-source
certificates (two controls accepted, four attacks rejected). Toy sixteen-request
packets shrink from 457,932 to 312,223 bytes for BabyBear and from 219,441 to
187,226 bytes for Goldilocks versus the deferred frontend. Version 8 now composes
it within a complete single-PBS proof; version 9 now adds cross-statement
composition. Bounded native v9 runs, complete security budgets and promotion
remain open.
See `shared-extension-lookups.md`.

Shared scalar sumcheck batching is implemented as `sumcheck::batch`, with
individually checked equations, mixed degrees and a common terminal point over
full extension-field challenges. Twelve decoded fixtures cover 84 equations;
all eleven selected sumcheck tests and 86 Python checks pass. This is a prerequisite
for jointly scheduling reciprocal sums and constraints; the new lookup frontend
uses it, and version 8 composes it within individual PBS proofs. Cross-statement
comparison sharing is now composed experimentally in version 9; native validation
and complete security remain open. See `shared-scalar-sumcheck.md`.

Shared-challenge ZeroCheck now pools folded buffers by immutable source-object
identity. A shared public-key factor folds once per round, while every relation
keeps its own equality factor, messages and equation checks. No alias routing is
serialized. Both complete batch formats pass the eighteen targeted release tests
and forty reconstructed certificates. Twelve complete wire controls covering 84
fresh member instances preserve earlier v6/v7 bytes and hashes exactly. At
sixteen members, eliminating duplicate
public-key first-fold buffers removes another 0.46875/1.875 GiB of requested
storage, beyond borrowing the original sources. All six shared-fold native
certificates now verify, covering 42 fresh statements with exact borrowed-build
proof bytes/hashes. Observed process peaks are 27,138,660/68,722,196 KiB;
paired latency/memory gates remain open. See `packed-borrowed-batches.md`.

Complete v6/v7 batch proving now borrows retained source tables instead of
cloning every Hadamard factor into a second buffer. At native batch size sixteen,
this removes 2.125/8.25 GiB of requested field-buffer storage for BabyBear and
Goldilocks, respectively; paired performance gates remain open. Native
correctness sessions observe process peaks of 27,135,584/70,792,920 KiB, with no
comparative latency claim. Eighteen targeted release tests pass, including owned/borrowed proof
and transcript equivalence and forty reconstructed complete v6/v7 certificates.
Twelve frozen-binary complete wire controls (84 fresh member instances) match
all earlier v6/v7 proof bytes and hashes exactly. See `packed-borrowed-batches.md`.
The original-size frozen v7 owning build has
completed all six certificates covering 42 fresh statements across both fields,
with all archived fixtures matched. Borrowed-build native validation also completes
all six certificates and 42 statements with exact owning-build proof bytes/hashes.
Shared-fold native validation also completes all six certificates with exact
borrowed-build bytes/hashes; its resource observations remain separate.

Opt-in complete outer version 7 now deduplicates repeated canonical Hadamard
roots under a common query. Every member retains version 6 constraints and every
relation equation is checked independently; conflicting aliases reject before
random aggregation. Complete 1/4/16 decoded public tests pass for both fields,
as do canonical relation/PCS tests and all 86 Python checks. The implementation
shares protocol bodies while retaining old domains and formats. All six native
certificates now pass; comparative performance measurements remain open. Fresh v7 reconstructed-child audits
pass twenty certificates (two controls accepted, eighteen attacks rejected),
including malicious members first and last beside an honest alternate anchor.
The full release audit across versions 2–7 passes all 150 certificates in fifteen
tests, with fifteen controls accepted and 135 attacks rejected. Two-order toy
runs verify 24 packets covering 168 member instances; all
twelve v6 wire controls match archived bytes. At sixteen members, toy bytes fall
3.28%/6.76% with repeated hashes exact. Original-size native correctness covers
42 fresh statements; sixteen-member native bytes fall 3.30%/4.38% versus v6.
See `packed-canonical-pbs.md`.

Complete experimental version 6 now composes ordered NAND PBS batches with one
cross-statement Hadamard certificate. The private member backend omits only that
relation; the public batch verifier always authenticates it jointly and checks
every other native PBS constraint per member. Original evaluation tables/states
move into a batch owner, without recommitting sources. Both 1/4/16 full-batch
Rust tests pass at test dimensions; workspace/example/release checks and all
86 Python tests pass. Fifty standalone v3/v4/v5 packets retain exact archived
wire bytes. Two-order toy runs verify 24 packets covering 168 member instances,
with exact repeated hashes and archived statement/key/parameter/layout matches.
Native ring-1024/LWE-728 joint 1/4/16 validation now passes all six certificates
covering 42 fresh statements, with exact archived statement/key/parameter/layout
matches and digest-linked root inventories. Both serial correctness processes
exit successfully; conditional 42-member interactive bits remain 129.32427.
Fresh v6 reconstructed-child audits pass twenty certificates with two controls
and eighteen intended rejections, including forged members first/last beside
an honest anchor. Thirteen audits across versions 2–6 pass all 130 cases.
Process peak RSS is about 27.9/75.3 GiB for the native correctness sessions;
comparative memory and native performance gates remain open. Cross-statement
lookup sharing, hiding and whole-proof security are also incomplete.
See `packed-joint-pbs.md`, `target/performance/joint-pbs/` and
`target/performance/joint-pbs-native/`.

Shared-challenge independent relation batching is now implemented in
`packed_zero::batch` and `packed_relation::batch`. Round messages are bound
together before each common matrix challenge; every equation remains separate,
then one multi-root PCS packet authenticates all terminal factor claims. Twenty
relevant Rust tests pass, including fresh genuine-path false opposite-equation
certificates. All 36 measured packets (252 relation instances) verify. At sixteen
native-capacity relations, bytes fall 62.47%/48.58% and verification improves
substantially. Prover gains vary across orders/fields, so no general speedup is
promoted. Fifty complete v3/v4/v5 toy packets and two current-source native v5
controls retain exact archived bytes. This is a relation component, not complete
cross-statement PBS composition by itself. Version 6 composes it as described
above. See `packed-batch-relations.md` and
`target/performance/shared-relation-batch/`.

Complete opt-in protocol version 5 combines aggregated Hadamard authentication
with deferred lookup source authentication in both blind-rotation halves and
final key-switch decomposition. It has a separate parent domain, proof type and
checked version. Four version-5 full-verifier tests pass, including fresh 1/4/16
groups at test dimensions and genuine reconstructed-child attacks. Eleven
binding audits pass 110 reconstructed certificates across versions 2/3/4/5
(eleven accepted controls and 99 intentional rejections); v5 contributes twenty
cases. Workspace/example checks, release builds and 83 Python tests pass. The
conditional inventory retains conservative v4 counts and requires explicit v5
mode and unpadded source geometry. All 66 benchmark packets verify (sixteen
native, eight legacy toy wire controls and 42 fresh v5 toy cases). Two reversed
native comparisons cut bytes 4.50%/6.18%; reused BabyBear latency is only
0.26–0.30% lower, while Goldilocks varies from 0.24% lower to 0.90% higher.
Native v4 bytes and original statements/keys/parameters/layouts match archived
fixtures. This remains opt-in size optimization, not a robust prover speedup.
Original-size fresh v5 validation now passes all 42 cases (21 per field at
1/4/16) against archived statements/keys/parameters/layouts. Both correctness-only
processes exit successfully, all digest-linked root inventories match, and the
conditional 42-proof interactive inventory is 129.32427 bits. Complete
cross-statement aggregation, hiding and whole-proof security remain pending.
See `packed-deferred-pbs.md`, `target/performance/deferred-pbs/` and
`target/performance/deferred-pbs-native-fresh/`.

Deferred extension lookup source authentication is available as a separate
component API (`packed_extension_lookup::deferred`). A caller-derived registry
binds parameter contexts and roots before lookup algebra; terminal openings
authenticate every accumulated claim once per used canonical source. Helper
authentication remains immediate. Equal roots with different parameter contexts
are distinct sources. Existing standalone lookup APIs retain their original
authentication path. Complete PBS uses it only in explicit version 5; it is not
cross-statement aggregation.
Seventeen integration tests and nine lookup unit tests pass, including genuine
false-source rejection and registry/claim/shape tampering. Workspace examples
check and release builds pass. The `deferred_lookup` example compares immediate
and deferred authentication for 1/4/16 shared-source lookup groups; twelve toy
serialized packets verify across BabyBear and Goldilocks. These are smoke checks,
not native performance evidence or a whole-proof security certificate.
Subsequent serial native-capacity comparisons verify 24 packets (168 lookup
instances) in two reversed field/method orders with exact repeated proof hashes.
At sixteen groups, bytes fall 25.89%/31.38%; BabyBear complete component time is
0.64–1.88% lower, while Goldilocks varies from 2.60% lower to 3.69% higher.
This supports opt-in size reduction, not the complete-PBS latency gate. See
`packed-deferred-lookups.md` and `target/performance/deferred-lookup/native/`.
`packed_decomposition::deferred` now uses a canonical digit/borrow registry to
share source authentication across limb comparisons, retaining reconstruction
and zero borrow endpoint checks. Eleven decomposition/lookup regression tests,
nine lookup unit tests, 81 Python tests and workspace/release checks pass. Eight
decoded complete v3/v4 certificates retain exact archived bytes/hashes and
statement/key/parameter bindings after the comparison backend refactor. The
component-only measurements precede the complete version-5 integration above.

Complete protocol version 4 now offers opt-in aggregated Hadamard authentication
with the same trusted bootstrapping-key roots and canonical source linkage.
Every other stage keeps its previous backend; versions 2/3 remain defaults.
All sixteen complete-proof Rust tests, 81 Python tests and workspace/example
checks pass. All 66 measured decoded certificates verify (sixteen native,
eight repeated toy and 42 fresh v4 toy). Two reversed native comparisons cut
BabyBear/Goldilocks bytes 6.69%/8.87%; reused BabyBear time is about 1.06% lower,
while Goldilocks is 0.20–0.59% slower. Defaults retain exact archived v3 native
and toy proof bytes. The conditional budget adds an explicit aggregation term
under checked geometry; whole-security review and promotion remain incomplete.
A follow-up now verifies all 42 original-size fresh v4 cases (21 per field at
1/4/16), with archived statements/keys/parameters/layouts matched. The extended
binding audit passes ninety fresh reconstructed certificates across versions
2/3/4, including twenty v4 cases with two controls/eighteen intended rejections.
Nine binding tests and all 81 Python tests pass. Native validation runs are
correctness evidence, not new timing claims. Independent security review,
cross-statement aggregation and hiding remain pending. See
`packed-aggregate-pbs.md` and `target/performance/aggregate-pbs/`.

Packed relation aggregation now composes ZeroCheck and multi-root terminal
authentication through a separate `packed_relation::aggregate` type/domain.
Eighteen positive fixtures, canonical state reuse, caller/shape/root/claim
binding, two legacy tests and fresh fake-factor/valid-path rejection pass in six
Rust tests; all 79 Python tests and workspace/release checks pass. Two reversed
native-capacity sum-of-products comparisons for sixteen products (33 roots)
reduce relation+serialization time 15.0–25.2% BabyBear / 22.7–31.6% Goldilocks,
with 55.6%/57.6% smaller proofs and faster verification. All 36 measured decoded
certificates verify with stable hashes. This is a relation component, not a
complete PBS proof or PBS batch aggregation; original full formats/defaults and
security budgets are unchanged. Evidence: `target/performance/aggregate-relation/`;
protocol and remaining integration are in `packed-multi-root.md`.

Common-query PCS aggregation is now implemented as an experimental prerequisite
for full aggregation. It combines responses across roots using full-coordinate
extension weights and a joint random row test, while authenticating every source
column. At native source capacity, sixteen-root BabyBear and Goldilocks packets
use 48.1%/53.2% fewer bytes; two reversed opening+serialization measurements are
39.2–40.3%/30.9–47.4% faster, with faster parallel verification. All fifteen
targeted Rust tests, 79 Python tests and the workspace check pass. Serial and
parallel implementations each verify 36 packets with matching digests across
all 1/4/16 groups, fields and orders. This remains a synthetic PCS component:
complete PBS factor/batch integration, hash/Fiat-Shamir review, hiding and
promotion are incomplete. Small groups can regress; the existing complete
backend is unchanged. See `packed-multi-root.md` and
`target/performance/mw-multi-root-parallel/`.

Reciprocal-table optimization is implemented and measured: BabyBear extension
lookups batch nonzero denominators with one inversion per table and reuse the
results for helper construction and public-table sums. Goldilocks retains
individual inverse encodings, cached once, because batch arithmetic changes
valid lazy bytes. All 19 targeted Rust and 79 Python tests pass. Two reversed
native BabyBear pairs reduce reused complete time 18.353→18.115 s and
18.324→18.202 s (1.29% / 0.67%); all eight native and 29 toy serialized proofs
verify with matching reference bytes, including 21 fresh toy cases. Proof size
remains 405,612,783 bytes and the conditional interactive inventory is unchanged.
This is a small incremental timing result, not a promotion or new security
certificate. Sources/binaries/logs: `target/performance/reciprocal-table-pbs/`.

Latest security-analysis increment: `block-rs.md` now gives a proposed
random-oracle query-log reduction from an arbitrary fixed-depth Merkle root to
a fixed available word, with explicit collision and late-target-hit terms.
`tools/merkle_availability_audit.py` and five tests audit complete/partial trees,
guessed roots, programmed bad events and shape rejection; all 71 Python tests
pass. This is a model using opaque leaf payloads, not a reviewed concrete
SHA-256/bincode reduction. Multi-root timing, query budgets, Fiat-Shamir,
knowledge/hiding and security-matched promotion remain open. Evidence is saved
under `target/performance/merkle-availability-audit/`; production is unchanged.

Follow-up production-format evidence: three Rust tests now cover exact
BabyBear/Goldilocks bincode leaf extraction against production SHA-256 Merkle
paths, frozen partial histories, malformed/nonminimal encodings and valid
Goldilocks lazy encodings. The model adds shared-subtree/cycle traversal, and
`block-rs.md` records separate source/helper/final-PCS freeze points for the
extension-lookup path. All 72 Python and 14 targeted Rust tests pass. Evidence:
`target/performance/merkle-production-audit/`. This strengthens implementation
correspondence, not whole-proof security or the remaining promotion gates.

Hash resource accounting is now executable in `tools/hash_query_budget.py`:
explicit multi-root freeze schedules or a proved schedule-independent maximum,
one global collision term, exact rational thresholds and maximum admissible
query counts. Seven tests bring the Python suite to 79 passing tests. Reports
keep whole-proof certification false; no actual adversary budget, PBS root
inventory or Fiat-Shamir loss is presumed. Hypothetical resource illustrations
and the derivation are in `block-rs.md`; sources/logs are archived under
`target/performance/hash-query-budget-audit/`. Production parameters and prior
conditional interactive budget formulas are unchanged.

Complete proof root inventory is now implemented in
`snarks::packed_root_inventory`: eleven categories include main/borrow/reciprocal,
monomial and final key-switch roots. The example emits digest-linked
`HB_FULL_ROOTS` after decoded public verification. Three fresh toy proofs confirm
75 BabyBear extension, 90 BabyBear lane16 and 131 Goldilocks extension root slots;
both extension fixtures retain archived proof/statement/key hashes and byte sizes.
All 14 complete proof tests, 79 Python tests and example checks pass. Evidence:
`target/performance/complete-root-inventory/`. Counts exclude trusted key roots
and authentication siblings, and count duplicate slots conservatively. This is
per-proof topology evidence, not an adversarial grinding/query bound or a full
Fiat-Shamir/security certificate; complete security and promotion remain open.

| Requirement | State | Evidence / next missing evidence |
|---|---|---|
| Reproducible complete artifact benchmark | Implemented | `tools/bench_pbs.py`; saved BabyBear ten-run warm/cold sessions at 1/16 threads; Goldilocks complete-proof smoke. Source capture now explicitly embeds ignored Cargo.lock. Ten newer component snapshots have hash-exact recovered lock sidecars; original archives remain intact |
| Cold/reused preprocessing, phase costs, serialized bytes, memory | Implemented | JSONL/summary/provenance and source/binary archives under `target/performance/`; selected conversion tracking is explicitly partial |
| Security-matched baseline and whole-proof budget | Incomplete | Existing artifact labels remain unbudgeted; `tools/full_pbs_budget.py` now inventories the actual complete packed relation and layouts; complete packed v2 now uses direct canonical transcript sampling; a common conditional 21-proof target is now measured for complete BabyBear lane/extension profiles; independent MW adaptation review, concrete Fiat-Shamir analysis and a fully security-matched baseline remain |
| Complete-protocol challenge sampling | Implemented as version 2; security analysis incomplete | `Transcript::new_direct` frames characteristic/request kind/label/count and rejection-samples canonical residues from Merlin bytes. Complete proofs carry checked version 2 and use a new parent domain; legacy sampling remains byte-compatible by reference tests. This removes the 128-bit seed expansion wrapper but does not complete the Fiat-Shamir argument |
| Direct extension-field challenge sampling | Implemented; not a security certificate | `Transcript::new_direct_extension<Base>` binds characteristic, degree and canonical basis multiplication products, then rejection-samples each prime-field coefficient directly from Merlin bytes. Independent X^4-11 / X^2-7 and byte-stream references cover full-coordinate sampling, empty/scalar/vector framing and mode separation; existing legacy and prime-direct reference outputs pass unchanged. The ordinary PCS extension tests use this mode; existing complete packed PBS stays on prime-direct v2 |
| Extension-field arithmetic and input invariants | Implemented prerequisites; composed security still incomplete | New BabyBear degree-8/degree-6/degree-5 and Goldilocks degree-3/degree-4/degree-5 aliases have independently checked prime/irreducible-polynomial parameters, Frobenius and inverse arithmetic. The minimal arithmetic-parameter capability preserves old generator interfaces without claiming unverified generators for new fields. Extension `pow(u128)` is implemented. A reproduced BabyBear decoder range bug is fixed while valid Montgomery wire bytes are preserved. Larger fields pass direct sampling and scalar PCS tests; default protocols/field choices and the full security gate are unchanged |
| Packed sumcheck and ZeroCheck | Implemented | `sumcheck::packed` / `packed_zero`; direct terminal obligations and adversarial tests |
| Matrix-weighted commitment interface | Implemented | `RowCode` plus `pcs::matrix_weighted`; trusted dimensions and parameter/domain digests; original scalar constructor retained |
| RS fixed-word proximity analysis | Derivation and audits implemented; cryptographic reduction/review incomplete | A new RS-specific argument constructs a nonzero exceptional-challenge polynomial of degree at most n(n+1) using Berlekamp–Welch minors plus quotient-degree/pseudo-division checks. For a fixed available word it proposes n(n+1)/p^k + (1-(t+1)/n)^Q, t=floor((n-m)/3), for unpadded block width k. This covers the algebraic lifting and fixed structured/shared-column step, not Merkle word extraction or Fiat-Shamir. Existing terms dominate on all 12 audited native layouts. Symbolic/finite checks cover 38,041 challenges, all 625 tiny words and all 729 tiny two-row matrices; genuine bad-word/false-value openings with valid paths fail production equations over BabyBear and Goldilocks. All 66 Python and 11 targeted Rust tests pass. Budget formulas and measured parameters remain unchanged. See `block-rs.md`; independent review, hash/knowledge extraction and full composition remain open |
| Block-RS MW-Brakedown | Implemented as a component | Algorithm 2 encoder, padded coefficient blocks, whole-symbol authentication, layout selection; full native Hadamard proof verifies; composition/promotion still pending |
| Packed Hadamard on native full-size PBS trace | Implemented and composed | `packed_pbs --full` verifies the complete binary NAND relation through a standalone verifier; all stage roots have canonical owners |
| Packed decomposition/lookups | Canonical decomposition and scalar/tuple lookup components implemented | Original-size native sources reconstruct from the exact NTT/Hadamard digit roots; joint borrow-transition tuples prove integer value <p, with zero endpoints. Lane batching reduces this component to 376 MB; constant-factor kernels reach 45–46 s in paired component smokes and terminal reuse reduces complete-proof decomposition to about 36.57 s; complete-protocol adversarial/security review and promotion remain. See `packed-decomposition.md` |
| Extension-field canonical lookups | Opt-in complete-PBS composition implemented and measured; security/promotion pending | `packed_extension` pulls GF evaluations back to canonical base-field matrix queries with tested multiplication order; `packed_extension_lookup` uses coefficient-packed reciprocal helpers, ordinary GF sumchecks and a child transcript bound before base PCS openings. Both quintics pass full/partial-domain, constant-source and fresh false-source/genuine-opening tests; canonical decomposition exposes a separate `ExtensionProof`. Repetition counts mean independent GF pairs. `packed_pbs::prove_extension/verify_extension` now own all stages including final key switching, with checked version 3 and a separate parent domain/type. The default stays on version-2 lane comparisons. The interactive inventory now distinguishes GF algebra and base-field PCS obligations; child/parent transcript composition, MW review and Fiat-Shamir remain open. Two reversed-order synthetic native-capacity pairs reduce lookup proving by about 64% (BabyBear) / 61% (Goldilocks), with about 52% fewer bytes. Two native alternating pairs now reduce complete reused BabyBear 41.921→18.483 s / 41.298→18.384 s and Goldilocks 104.714→48.252 s / 104.354→48.314 s, with 30% / 33% fewer bytes. All 16 full-size proofs verify with matching actual fixture/key hashes; 38 Rust and 31 Python final regression tests pass. The comparison is between experimental protocols, not security-matched promotion |
| Goldilocks cubic/four-lane tuning | Opt-in complete-PBS profile implemented and measured; promotion pending | Independently checked X^3-7 field, direct sampling, scalar PCS, fresh false-source and complete batch/binding tests pass. Two reversed native comparisons reduce reused complete time 48.137→31.931 s / 48.307→31.900 s, proof bytes 1,182,299,399→614,289,399 and RSS about 9.06→8.01 GiB with unchanged FHE/key/statement hashes. All 20 native/toy benchmark proofs verify; archived/default quintic toy wire bytes match. Actual interactive inventory is 134.55 bits; Fiat-Shamir, independent composition review and security-matched promotion remain open. See `performance-results.md` |
| BabyBear stronger joint interactive profile | Opt-in profile implemented and native-validated; whole-proof security/promotion pending | Independently checked X^6-31 field and one-variable helper-row shift produce 134.90 modeled interactive bits per proof and 130.51 for the 21-proof union. All 21 native fresh cases pass at original FHE dimensions/keys, plus 42 toy fresh cases, 12 native comparison controls and two default toy controls (77 benchmark proofs total). Reversed-order degree-six reused costs 22.803/23.278 s versus degree-eight 39.789/39.924 s, with 405,612,783 versus 428,858,023 bytes; the smaller field is selected. Historical default native/toy wire hashes match. The new BabyBear21 plus previous Goldilocks21 sum to 129.32 conditional interactive bits. This is not an aggregated proof or a Fiat-Shamir/composition certificate. Native matched-baseline analysis, independent MW review and promotion remain open. Evidence: `target/performance/babybear-batch-budget-pbs/`; 46 Rust and 47 Python tests, three release builds and workspace check pass |
| Degree-six multiplication | Implemented and native-measured | Stack-based Karatsuba products and one final binomial reduction preserve the old field/protocol values. Independent integer-polynomial and legacy-serialization tests cover all 36 basis products, boundary cases and 512 deterministic random pairs. Two reversed native pairs lower complete reused PBS 23.052→18.295 s / 22.894→18.172 s (20.6%) with identical 405,612,783-byte proof hashes/layouts; decomposition median falls 18.57→13.93 s. All 21 native and 21 toy fresh-input certificates match the archived kernel hashes, plus 12 repeated controls (54 benchmark proofs). FHE parameters, native keys, protocol and 130.51-bit conditional 21-proof inventory are unchanged. All 45 targeted Rust and 47 Python tests, release build and locked workspace check pass. Evidence: `target/performance/sextic-kernel-pbs/`; whole-proof security and promotion gates remain open |
| Common conditional-target comparison | Implemented, measured and fresh-input validated; security-matched promotion pending | Two reversed complete BabyBear pairs use identical native FHE/key/statement hashes and all four shifted-helper PCS layouts at width eight/Q544. Lane16 and degree-six/one-pair inventories give 130.26/130.51 conditional bits over 21 proofs. Extension reused complete time 18.302/18.159 s versus lane 39.073/39.517 s (53.2–54.0% lower); bytes 405,612,783 versus 579,831,829 (30.0% fewer), RSS about 2.84 versus 4.07 GiB. All 50 new benchmark proofs pass, including 21 native and 21 toy lane fresh cases whose actual statements/keys/layouts match archived extension fixtures. All 53 Python and four focused Rust tests pass; the production binary/source is unchanged. `block-rs.md` maps the supplied paper to the implementation and records a tested algebraic lifting step; robust proximity/extraction, adaptive/Fiat-Shamir composition and hiding remain unproved here. Evidence: `target/performance/joint-target-pbs/` |
| Packed NTT relations | Composed into complete binary NAND proofs; security review pending | Tensor-row checks and batched canonical openings verify against the same native Hadamard roots in complete versions 2 and 3; original-size proofs verify over both fields. See `packed-ntt.md`; independent composition/security review remains |
| Packed accumulator continuity / monomial initialization | Composed into complete binary NAND proofs; batch/security review pending | Additions, active-round chain, expected endpoints and decomposition inputs share canonical roots. `packed_monomial` adds public rotation products and NAND initial LUT derivation from x+y. Blind-rotation key binding now uses trusted native public-key roots. Final key/output binding is now a linked component; standalone complete-PBS composition now owns shared roots/endpoints; aggregated batch chains and complete-protocol review remain; see `packed-accumulator.md` and `packed-monomial.md` |
| Public blind-rotation key binding | Implemented as a linked binary component | Reusable roots derive from the native public RGSW key, independently of traces; canonical Hadamard verification consumes these roots. Original-size native run and valid foreign-key rejection test pass; see `packed-bootstrap-key.md`. Key-switching-key/output binding is composed through `packed_pbs`; security and complete-protocol adversarial review remain |
| Packed modulus/key switching and extraction | Original-size final-stage component implemented | Exact public input modulus switching derives rotations/initialization. `packed_key_switch` links canonical negative-a digits, expected switching-key roots, NTT products and signed/truncated extraction to the original output LWE key/dimension. Native original-size BabyBear and small BabyBear/Goldilocks tests pass; unequal ring/padded-output dimensions are explicitly unsupported; complete-protocol security/review remain. See `packed-key-switch.md` |
| Reuse packed terminal evaluations | Implemented and measured | Packed sumcheck/ZeroCheck return already-folded terminals; canonical openings still authenticate them. Zero-variable source broadcasts retain the original path. Complete packed time improves 48.814→41.231 s and 49.051→41.169 s in alternating paired smokes, with unchanged 556,173,638 bytes. This is an experimental-backend engineering comparison, not security-matched promotion |
| Canonical complete-PBS statement and stage binding | Complete binary NAND versions 2/3 implemented; adversarial review incomplete | `snarks::packed_pbs` owns one serialized proof, all canonical roots and one shared final accumulator. Verification needs only trusted setup/PCS parameters and public input/output ciphertexts. Original-size native release proofs verify after deserialization over both fields; version 3 uses extension comparisons through final key switching. Native fresh-ciphertext tests cover both fields, wrong keys and swapped children. Complete malicious proofs for a foreign input trace, changed output body and changed last retained output-a coefficient now regenerate every child under requested parent/child domains, verify all openings in a reference replay and fail the production public-factor equations over both fields. A later test-only audit now passes foreign blind-rotation/switching keys, false initial/final endpoints, spliced active-round traces and disagreeing source views over both versions/fields: 40 independently assembled certificates, four accepted controls and 36 expected rejections, plus eight native positive controls. Actual-source algebra/opening replay is checked separately; independent adversarial review remains |
| Ordinary PipFRI | Non-hiding scalar reference implemented; production/security gate incomplete | `pcs::rolling_fri` and `pcs::pipfri` implement rolling LDT, shared fragment-pair leaves, random batch aggregation and public-point consistency. Both coefficient and Boolean-evaluation bases pass independent arithmetic and fresh malicious-proof tests over BabyBear/Goldilocks and their degree-4/degree-2 extensions, using direct coefficient-wise extension sampling. The opt-in `multilinear::pipfri::PipFRIPCS` adapter supports base/extension scalar tables, constants and batches; existing LogUp SNARKs and original-size four-stage PBS wrapper experiments verify over both fields, including public fixture/key hashes and key reuse. This reference has an extra combined-oracle root and independent query batches; a separate experimental masked/virtual-query reference now exists; concrete security parameters, fully bound complete-PBS integration and security-matched comparison remain |
| Masked scalar PipFRI | Experimental reference implemented; audit and integration gates open | `pcs::pipfri::masked` pads each fragment, adds an independent mask polynomial, omits individual fragment evaluations, and authenticates a virtual initial batch with shared folding/LDT queries. Private prover and verifier sessions enforce bounded reuse. Prime/quintic roundtrips, fresh false-claim tests and encoder equality pass. The cumulative two-opening numerical audit passes over both prime fields/bases and detects an individual-fragment disclosure negative control; adaptive hiding/RO and composed security analysis, full-PBS integration and security-matched measurements remain. A separate locked-session scalar PCS adapter now supports the existing trait, bounded batches and stateless verification; base/quintic adapter and LogUp integration tests pass, including atomic batch preflight, concurrent spending and explicit stateless-replay semantics. Eight native-size synthetic scalar openings (2^21 entries, four openings/root) verify after serialization; median opening costs are 0.449/0.638 s with 1.05/1.45 MB proofs. All 49 PCS/LogUp regression tests and the workspace check pass. Native four-stage wrapper experiments now verify two quintic proofs per field while retaining one key mask session (indices 0/1, budget 4→3→2); over-budget reuse rejects. Parallel encoding/hashing and blocked linear combinations now lower reused times 42.1→15.4 s / 106.4→40.5 s, with effectively unchanged 19.65/51.40 MB proofs and 11.9/45.3 GiB peak process RSS. Sequential-reference tests preserve full proof/transcript bytes and RNG state; two reversed-order scalar pairs confirm lower component costs. This remains an in-memory legacy wrapper, not a decoded standalone complete-PBS verifier; no performance/security promotion is claimed. See `masked-pipfri.md` |
| Ordinary PipFRI coordinate encoding | Implemented and measured within experimental backend | Base-field FFTs evaluate each nonzero extension coordinate; zero coordinates skip their FFT. Trusted extension-only roots are rejected by the selector. Generic/optimized parameter bytes, roots, full scalar proof bytes and transcript states agree over both native extensions. The scalar adapter selects this path. Two alternating native pairs reduce reused-key BabyBear 32.208→10.635 s and 32.478→10.828 s; Goldilocks 18.527→10.685 s and 18.551→10.852 s, with unchanged serialized sizes and public fixture/key hashes. These are one-reused-proof-per-process smokes, not security-matched promotion; see `ordinary-pipfri-coordinate/` artifacts |
| Packed PipFRI research gate | Open; conditional scalar-opening bridge reference implemented | `snarks::packed_scalar_opening` preserves ordered matrix products in a public multilinear kernel and reduces a whole query batch to one degree-two sumcheck and one original masked scalar opening. The conditional interactive bound is epsilon_PCS+(1+2v)/abs(E), assuming a fixed committed scalar polynomial and adaptive evaluation soundness; a base-coordinate projection lemma gives canonical base responses without asserting extension-coefficient membership. Ten bridge tests include noncommuting/independent product references, serde/public verification, 1/4/16-query one-allowance batching, fresh false-witness/genuine-source terminal rejection, an accepted non-base source projection and explicit witness recovery showing the bridge is non-hiding. A reproduced Goldilocks encoding bug is fixed by returning the exact PCS-bound value. All 81 targeted PCS/SNARK tests and the workspace check pass. This is an added sumcheck reduction, not direct packed PolyFRIM or a hiding MW-PCS. Two reversed-order capacity comparisons now verify all 24 large/12 toy proofs on identical tables and dense queries; the bridge is about 62x slower at 16 queries, despite using only 13–17% of Brakedown bytes. Keep it out of full PBS and retain MW-Brakedown. Actual FHE integration, concrete PCS/FS soundness and the direct packed consistency/proximity/hiding gate remain open. See `packed-scalar-opening.md` |
| MW-Basefold comparison | Streaming reference implemented and native comparison measured; security-matched analysis open | `pcs::mw_basefold` follows the paper’s round-interleaved fold schedule with base-field coordinate arithmetic, whole-symbol authentication and exact terminal decoding. `sumcheck::packed` / `packed_zero` now expose per-challenge callbacks; empty callbacks preserve existing framing. `snarks::packed_basefold` supplies fresh structured challenges and authenticates canonical source terminals. Independent Horner/re-encoding/noncommuting references, genuine-path invalid-degree attacks and fresh false-source certificates pass over both fields. Two alternating native Hadamard pairs verify all 16 proofs. Reused Basefold is slower: BabyBear 1.303/1.192 s vs Brakedown 0.590/0.514 s, Goldilocks 2.215/2.282 s vs 1.251/1.269 s; bytes are 2.18x / 1.63x. Keep Brakedown on the current path. This uses common experimental query counts, not security-matched parameters; 64 Rust and 34 Python tests pass. See `performance-results.md`. The after-query Brakedown API/default PBS are unchanged; security-matched analysis and any GF-query adaptation remain open |
| Convolution check | Profiled gate; deferred | After terminal reuse, complete warm proving is about 40.78 s, of which decomposition is 36.57 s (90%). Private NTT links are 0.76 s; monomial proving is 0.45 s. Prioritize lookup cost, then reassess whether a negacyclic quotient experiment is warranted |
| Full validation at batches 1/4/16 | Original-size independent validation through v5 and joint-Hadamard v6/v7 validation complete; further batch sharing incomplete | Original ring-1024/LWE-728 dimensions and original output keys are preserved. Selected BabyBear degree 6/shifted-helper and Goldilocks degree 3/width 4 profiles pass all 42 original-size fresh v4 cases, with archived native statements/keys/parameters/layouts matched; their conditional 21-proof interactive inventories are 130.51/130.16 bits. Version 5 passes all 42 fresh toy cases and sixteen native repeated-statement comparison certificates (including v4 controls); all 42 fresh original-size v5 cases also pass with exact archived fixture matches in correctness-only processes under `target/performance/deferred-pbs-native-fresh/`. These are independent single-PBS proofs with within-proof authentication sharing, not cross-statement aggregation. The older BabyBear quintic 21-proof union inventory is only 125.71 bits and is not the selected joint profile. All six v6 joint 1/4/16 original-size certificates now pass, covering 42 fresh statements with archived fixtures matched under `target/performance/joint-pbs-native/`. Whole-proof Fiat–Shamir/composition, further cross-statement stage sharing and performance promotion remain open |
| Promotion and rollout | Not achieved | Artifact engineering speedup is verified, but it does not meet the new backend's security/completeness gate |

## Composition acceptance checks

The complete verifier must reject a malicious prover that uses a valid trace for
different ciphertexts while honestly hashing the requested ciphertexts into the
transcript. Merely changing the transcript while replaying an honest proof is a
weaker test. Likewise test valid subproofs with swapped keys, adjacent accumulator
endpoints, or duplicate views of the same witness that disagree.

The completed packed backend must cover every original PBS stage. A proof of the
Hadamard relation, or a public native recomputation, is not evidence that the full
packed protocol has been implemented. Preserve operation semantics while moving
each committed relation to the packed path.

Previous implementation turns made concrete progress; the goal remains active.
No remaining research or engineering requirement has been marked complete merely
because the current tests pass.
