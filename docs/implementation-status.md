# Full-plan implementation ledger

Objective: implement every item in the agreed performance plan. This ledger does
not change its success criteria: complete PBS semantics, unchanged FHE parameters
and output key, a complete 128-bit proof-security argument, <=2x security-matched
baseline bytes, and >=10% complete single-PBS latency improvement confirmed twice.

## Current status

The implementation plan is paused and incomplete while the source is prepared
for mathematical security work. Start with [the proof guide](security-proof-guide.md)
and [review findings](security-review.md); the dated/append-only milestones below
record historical states, including superseded pending runs and source arguments.
No candidate is admitted as 128-bit classical
security or qualified for the performance gate. The original FHE parameters and
output-key contract remain requirements; correctness runs do not replace them.

The submitted-call worksheet now labels its argument `source_reviewed`, rather
than `established`: inspection and finite controls are inputs to mathematical
review, not a completed protocol theorem. This classification changes no
numerical bounds or verifier behavior. Local `target/` evidence referenced below
is not distributed by the source checkpoint and must not be assumed present
in a fresh clone.

The original-size v4 Brakedown one-query capture now passes all four correctness
proofs and four altered-output rejections. Independent observed inventories
close 539 accepted/two rejected field-receipt pairs and 160 accepted column
families, with every field/column resource counter reconciled. All four native
role roots pass exact-order and context-digest binding checks. This remains a
correctness/capture control, not a security-matched profile or timing result.

Monomial component controls pass all 20 combinations of the two representative
fields, v4/v5 and five backends, including temporal child origins, bounded
ordered-claim decoding and true/perturbed-false fixed-source task classification.
Their strict accepted proofs match 640 NTT source claims and 40 product claims
against first-declaration words. Isolated
entry binding, public-factor and terminal-equation checks also pass. These are
component controls. A focused complete accepted PBS source-word control now
passes as described below; the general adaptive reduction remains unfinished. The corrected two-field v5 Brakedown ordered-prefix regression passes on its
frozen assignment-scope revision. Its earlier failure and compile failures remain
preserved separately; earlier opening bodies remain conditional.

The final key-switch focused BabyBear v5 Brakedown control passes 128 NTT,
15 product, 16 decomposition-linear, 15 lookup-source and seven helper claims,
plus public-input/extraction word comparisons. This is an isolated accepted
component proof. Its reusable checker also passes on an accepted complete PBS proof: the full
trace projection replays 12,690 events and matches those final-stage claim groups,
with all preceding stage flags and the complete transcript continuation checked.
The all-stage word-comparison revision now passes one focused complete proof,
including 258 primary-stage source claims and every final-stage claim group.
The 20-case field/schedule/backend source-word matrix has completed with exit zero; its coverage and frozen runner/log hashes were independently rechecked in `completed-source-control-matrices-verified-audit.json`. Both controls use synthetic n32/LWE21 keys and do not qualify native
security or performance.
The 20-case earlier input/extraction-only matrix remains running.
The focused final-key temporal control also passes on its earlier frozen ledger:
28 post-identity requests from one lookup child, with zero availability/collision
events. A newer 20-case matrix covers initial identity requests and the exact
prefix target-index optimization; that matrix is running, not passed.

Complete-protocol synthetic controls pass all 20 cases and a fresh independent
file audit checks all 8,551,786 recorded events (53,485,529,000 trace bytes).
These use n32/LWE21, not encrypted native security/performance profiles.
The trace audit checks generic PCS SHA512 preimages and SHAKE inputs; it does
not record SHAKE outputs or cover primitives outside those interfaces.
An independent byte-for-byte prover/verifier XOF request comparison passes all
20 saved controls: 115848 protocol requests and 25803751742 input bytes, with
three explicitly checked harness continuation probes excluded per prover trace.
Successful native Brakedown setup/prover SHA512 inventories and conditional
stopped prover XOF/lifetime worksheets are implemented. Their remaining coupling,
honest-work coverage and all-trials premises are not security admission results.
Evidence under the performance opening inventory:
`classical-production-monomial-accepted-ntt-complete-audit.json`,
`classical-production-final-key-ntt-words-passed-audit.json`, and
`classical-production-complete-pbs-event-stream-complete-audit.json`.

The source/sampling audit covers the ordered primary relation, all configured
NTT components and first-decomposition PCS sampling for all five backend
families (Brakedown v5; v4 retry compatibility remains separate). These use
n=32/LWE=21 synthetic prefix fixtures, not complete accepted native certificates.
Lookup registry, compression/retries, helper roots, equality points, scalar
batch rounds, terminal consistency and linked parent-handoff fixtures pass.
Ordered helper handoffs and Brakedown helper-role sampling fixtures also pass.
All four first-lookup helper child sampler families pass full field audits
(v4/v5). Original-source claim registration and seal interpretation pass the
full all-backend audit, including consistent/conflicting aliases and trusted
context substitution (v4 Brakedown later stages remain excluded). The combined revision is under full regression across
both schedules and all five backends. Ordered original-source PCS handoffs and
Brakedown batch sampling pass focused v5 field fixtures. Direct/dictionary and
fragmented/virtual source child sampling is implemented and under full regression.
Second-decomposition entry and all linear rounds pass focused Brakedown v5
fixtures, bound to input 1 and the second coefficient range. Second-stage
ordered PCS handoffs and Brakedown sampling also pass focused v5 field tests;
child-backend sampler routing remains under full regression. Second-lookup
metadata, typed origins and compression scheduling pass focused v5 field tests.
Second-lookup equality/batch/terminal checks and parent-finish compilation pass
focused v5 field tests. Both lookups now have separate helper/source task
families with shared geometry, alias and framing checks; both lookups' Brakedown
helper/source samplers pass focused v5 field tests. Child-backend runtime
coverage remains under full regression. Accumulator source/lane/query-map
compilation passes focused ordered-prefix validation in both fields. Isolated query
maps and arithmetic predicates match production across 300 valid toy/native profile geometries and 20
expected packing rejections, covering all eight extensions, both schedules and
five backends at blowup 2/fragment cap 8. The current collector revision also
passes this isolated regression (2 tests, 21.85 seconds); the arithmetic fixture
checks 7,050 malformed or changed claim bundles. Ordered accumulator openings
now bind all seven sources, Brakedown row/column requests and typed child
origins. Focused and full ordered-prefix tests of this revision remain live.
Accumulator direct/dictionary consistency, projection and rolling samplers
are implemented with ordered-prefix runtime validation pending. Fragmented
projection/bridge samplers are also implemented with validation pending; scalar
mode/source/fragment binding is implemented with validation pending. Scalar
rolling and source-consistency request samplers are implemented with validation
pending; word authentication and later stages still need coupling.
Isolated arithmetic checks do not authenticate committed words.

The source-obligation baseline is complete. The current full regression is the
latest accumulator-opening collector revision. Seven superseded intermediate full runs were
intentionally cancelled (SIGTERM/Cargo 101), with explicit cancellation artifacts;
no passing result is claimed for them.
Full native geometry coverage, justified security admission and matched
latency/proof-size qualification remain open.

| Frozen correctness schedule | Independently audited fresh proofs |
| --- | ---: |
| Version 1 optimized | 210/210 |
| Version 4 atomic ZeroCheck | 210/210 |
| Version 5 atomic columns | 210/210 |

The version-5 four-case matrix also passed 40/40. Live partial groups are excluded
from these audited totals. All these runs use correctness profiles and provide
no security or performance qualification.

## Evidence history

### Classical-security implementation round

The revised plan targets conventional 128-bit classical attack cost and compares
Brakedown, optimized PolyFRIM and a new unmasked fragmented PipFRI adapter.
Versioned proof profiles are allowed; existing FHE parameters, output keys and
legacy verifiers remain intact. No adversary-model clarification is pending.

PolyFRIM's retained-source batch prover now memoizes identical ordered fold
prefixes, using private parent-state identity and canonical matrix bytes rather
than assuming equal roots identify private data. Cache admission uses a 1 GiB
data estimate; this is not a bound on total prover memory. Differential tests
exercise shared prefixes, divergent suffixes and exact duplicate queries with
full extension coefficients. They reproduce the independent generated-source
proof bytes, consistency/proximity indices and final transcript state in both
fields: seven release tests pass, with one existing manual memory test ignored.
Native performance for this change has not yet been measured.

SHA-512 now implements the existing PCS hash interface with a fixed-width
64-byte digest. Its standard known-answer, reset, serialization and truncated
input tests pass. This is primitive plumbing, not a completed classical
profile or security theorem. The SHA-512 Merkle test also matches an independent
tree and rejects altered paths; both hash tests pass. A separate length-framed
SHAKE256 byte transcript now binds protocol/profile, message labels/lengths,
challenge lengths and outputs, and supports whole-phase power-of-two index
sampling. Typed prime/extension sampling is now available through explicit
`Transcript::new_classical` / `new_classical_extension` constructors. Extension
identity precedes caller challenges, and scalar/vector requests are separated.
The byte API also supports scoped, profile-inheriting children with 64-byte
seed/finish binding. All 17 helper tests pass, including raw-stream prime
references, independent binomial-basis references, typed dispatch, child
binding and legacy compatibility. Typed parent/child and complete-PBS
integration, trusted profiles, base-field oracle storage and the fragmented
canonical adapter remain to do. These primitives are not a Fiat–Shamir theorem.

The typed transcript now exposes whole-phase index sampling with exact legacy
request replay, and linked classical extension children with parent/profile
checkpoint validation and one-time finalization. Twenty helper tests pass.
Extension-lookup child creation and the unmasked PolyFRIM adapter select the
linked classical path only for an explicitly classical parent. The six
PolyFRIM adapter tests pass, including decoded SHA-512/classical round trips
and wrong-profile rejection over both fields. These are standalone PCS results,
not complete-PBS profile integration or a security qualification.

The immutable classical descriptor now binds backend, field/basis, four role
geometries, row-code/fragmentation settings and cryptographic suite IDs under
SHA-512. Its factories create native-domain-checked Brakedown or PolyFRIM
parameters and retain them with the descriptor in an immutable role bundle.
Three profile tests pass, covering identity changes, incompatible layouts,
wrong field/backend rejection and deterministic parent construction. Complete
PBS must still consume this bundle through dedicated setup/prove/verify APIs;
descriptor validation is not a security qualification.

Version 12 now has a dedicated complete-PBS façade consuming the profile-built
role bundle. Public-key preprocessing and proof headers retain its identifier;
verification rejects a mismatched identifier before processing subproofs.
The parent uses the profile's SHAKE transcript, lookup and PolyFRIM children
inherit it, and complete-stage dispatch binds a separate v12 namespace. The
legacy entry points still select their original direct-Merlin transcripts.
Both classical truth-table tests pass: 16 small encrypted complete proofs
across both fields/backends, all four NAND inputs, reused public evaluation
keys, proof serialization/decoding and standalone verification. Altered
profile headers are rejected. These use one sample for correctness only;
native performance and complete 128-bit security remain unestablished.

### Bounded column gathering

Nonzero column hashing now gathers adjacent columns in bounded scratch tiles,
while preserving the original encoded cache, serialized leaves, tree and proof.
Reference tests cover both fields, sparse/noncanonical zero inputs and partial
tiles. The PCS/reference, ten complete regressions, workspace checks and 36
comparison-tool tests pass. The isolated eight-proof native pilot preserves all
proof digests and reports 10.51–11.43% BabyBear and 9.35–9.83% Goldilocks
reductions; its one-proof/no-warmup schedule does not establish the timing gate.
The separate pinned 16-thread warm comparison against the initial frozen v11
control is terminal: 88 complete proofs verify and preserve every corresponding
proof byte and fixture fingerprint. With one warmup and ten measured proofs
per process, BabyBear improves 40.26%/41.01% across reversed orders
(16.0144/16.1634 → 9.5664/9.5346 s); Goldilocks improves 40.07%/39.73%
(27.0741/26.9961 → 16.2260/16.2700 s). The engineering latency gate passes.
This measures all accumulated execution changes, not tiling alone. Artifacts
are under `target/performance/column-tiles/`. The separate cold comparison is
also terminal: 88 more complete proofs remain wire-identical, with repeated
median reductions of 41.35–41.49% BabyBear and 41.55–41.60% Goldilocks,
including repeated public-key commitment preprocessing. Independent
`checked-warm.json` / `checked-cold.json` files capture replay checks and log
hashes. The separate matched-input complete-v9 comparison also passes its
engineering gate: 88 complete native proofs, BabyBear 37.11–38.19% faster /
<=1.137x bytes and Goldilocks 39.12–39.41% faster / <=1.384x bytes, confirmed
in reversed orders with identical keys/parameters/encrypted statements. See
`canonical-v9/native-warm/checked-native.json`. The complete security argument
remains incomplete; security matching and promotion remain false.

The unmasked security analysis now explicitly maps same-root lane projections
to the proposed fixed-word RS lemma; a separate 30,603-challenge tiny-field
audit covers disjoint error supports and repeated/independent far lanes. This
is conditional on that lemma and fixed-word availability. A new fixed-nearby-
word consistency derivation charges both predecessor and successor errors;
two production-fold witnesses over the native extension fields pass, including
a terminal-constant case and a negative control for reusing the exact-codeword
bound. This supplies a conditional opening reduction, not rolling-FRI input
proximity, availability/FS/PBS composition or a completed concrete theorem.
Two further production-verifier controls over both extension fields exercise
ordinary and virtual-all rolling modes with genuine authentication. A word just
outside the required small radius can pass whenever three of sixteen pairs are
missed, so the larger-radius scalar tail cannot be imported for that stronger
premise. This is a radius-transfer control, not a false-evaluation attack.
A new conservative distance-sensitive rolling derivation uses fresh
univariate RS certificates for the quadratic challenge curve and an error-set
potential. Its candidate bound is 2*sum_j n_j*(n_j+1)/abs(E)+(1-delta)^Q,
under fixed-word/ideal-coin hypotheses, rather than the paper's numeric bound.
All 11 symbolic tests pass, including the prior audit and new curved families;
a separate finite model checks 262,144 nonexceptional potential steps. The
RS derivation and complete cryptographic composition still require review.
The supplied PipFRI scalar unique-decoding tail at rate 1/2 is (3/4)^Q:
Q=128 gives only 53.12 bits for that upper-bound term; exact comparison requires
Q>=309 for the term alone to reach 128 bits. This is not an attack or a complete
bound for the packed adapter. Full security remains unproved and promotion off.

A benchmark-only opening observer now records successful public PCS API calls
separately from altered-output replay. All 32 default toy proofs remain wire-
exact against the prior build, and all 12 on/off observations across both fields
and three backends preserve proof/setup/statement fingerprints. Strict reader
checks and all 42 Python comparison tests pass. The toy fixture has 157/272
successful calls for BabyBear/Goldilocks, including repeated root openings;
these observed counts are not adversarial maxima or a complete security budget.
Four native Brakedown on/off proofs also pass and preserve the original
native fingerprints: they observe 160/278 calls, demonstrating that the toy
counts are not a native inventory. Both native PolyFRIM observations now also
pass with matching counts and original native fingerprints. A separate
conditional ceiling derived from per-owner allowances charges 481/567 ordered
queries per proof, without subtracting aliases. Its coverage of every accepted
path still requires review. Seven exact opening-term worksheet tests pass;
backend-internal root freezes, hash/FS and full-PBS budgets remain unproved. See
`unmasked-polyfrim.md` and `target/performance/opening-inventory/`.

The canonical algebra worksheet now includes the four direct quadratic
ZeroChecks, all main/monomial/final NTT links, public final-input equality,
seven accumulator equations, decomposition reconstruction/borrow endpoints,
and shared tuple-lookup algebra. Its conditional 21-proof native subtotals
are approximately 2^-157.05 / 2^-162.61 before PCS/hash/Fiat–Shamir terms.
Internal Merkle declarations are inventoried separately from virtual
projection identifiers; the conditional 21-proof ceilings are 265,545 /
337,365 declarations. A combined candidate worksheet requires matching
provenance, exact sums, schedule ceilings and an explicit global Merkle-query
budget. The implemented Q=128 does not satisfy its candidate bound. Q=768
reports are hypothetical and do not change production parameters.

The pinned transcript audit identifies Merlin 3.0.0 / STROBE-128, separately
from SHA-256 Merkle hashing. Candidate reports explicitly leave Fiat–Shamir
error/query bounds unset and do not treat child-seed length as security bits
or accepted-proof root declarations as all adversarial grinding trials.
All 36 relevant Python budget/worksheet tests pass; the four accumulator
mapping/fresh-binding Rust tests also pass. The remaining security contract
needs an explicit adversary model/resource budget, as well as reviewed
reductions and full adaptive composition. The original 128-bit success
criterion is not weakened or marked achieved.

### Opt-in helper basis packing

Complete canonical v10/v11 supports helpers at the extension basis width (six /
three), with unchanged power-of-two source packing and cloned RS encoders/row
splits. The default layout and all eight original native default fingerprints
remain intact. Both new native layouts decode, verify and decrypt all four NAND
inputs with reused keys: 32 proof runs across fields/layouts/reversed orders.
All 168 fresh toy group-1/4/16 proofs and the 72-case fresh full-stage audit pass
(four controls accepted, 68 attacks rejected). Fourteen mapping/lookup tests,
four RS lifting tests, ten complete regressions and 36 comparison-tool tests pass.
The audit's independent helper queries were updated to use their trusted helper
width; no acceptance checks were removed.

Pinned four-proof diagnostics reduce complete median time by 5.43–5.49% for
BabyBear and 2.90–3.64% for Goldilocks, with max byte ratios 0.9763/0.9792. They
lack warmups/ten samples and are below the 10% target; promotion remains off.
The new fixed-word analysis uses a finite challenge subspace of size p^h,
not the larger RS-symbol field p^b. Per-opening helper exceptional terms exceed
157/162 bits but do not establish full security or a matched baseline. See
`block-rs.md`, `unmasked-polyfrim.md` and `target/performance/helper-basis/`.

### Zero-table column hashes and stronger wire checks

Canonical zero tables whose actual encoded output is also canonical zero now
reuse one identical column hash, retaining every Merkle leaf and path. New
references compare serialized codewords, entire trees and every path in both
fields, including sparse and noncanonical-zero cases. An audit also corrected
the earlier use of Goldilocks' normalizing `value()` accessor in zero guards and
reference checks: guards now require canonicality, and tests compare serialized
bytes. Archived native byte comparisons remain valid for their fixtures; the
older generic raw-value claim was too strong. All 92 PCS tests, eight complete
regressions, eight Python checks and the workspace check pass. Eight new native
proofs preserve full proof digests. Single-proof timings show about 1% lower
BabyBear time and mixed Goldilocks results, with no performance promotion.
See `unmasked-polyfrim.md` and `target/performance/zero-column-hashes/`.

### Lookup buffers and zero-row encoding

Shared canonical lookups reuse one tuple buffer per request instead of
allocating per source row. The Block-RS encoder also skips NTT work on raw-zero
rows, after its existing domain checks; lazy Goldilocks zeros keep the old path.
Raw-value reference tests and all 90 PCS tests pass, alongside eight complete
regressions, eight Python checks and the workspace all-target check. Sixteen
new native before/after proofs (eight per optimization) preserve every original
full proof digest in reversed field/mode orders. Preparation and commitment
costs decrease modestly; neither correctness-only pilot establishes the 10%
complete latency gate. Both changes preserve parameters and proof bytes.
See `unmasked-polyfrim.md` and `target/performance/lookup-buffer/` /
`zero-row-encoder/` for exact builds and terminal manifests.

### Complete lookup subphase profiling

Canonical complete v10/v11 provers now expose comparison lookup counters for
the two main decompositions. They exclude final key-switch lookups and remain
outside proof/transcript data. Native BabyBear and Goldilocks decoded proofs
preserve their original full proof digests. Helper commitments dominate the
measured lookup subphases (2.108/5.816 seconds), followed by preparation
(1.751/2.842), versus sumcheck at 1.287/1.056 seconds. These are single-proof
diagnostics, not performance certification. All eight release complete tests,
eight Python checks and the locked workspace all-target check pass. See
`unmasked-polyfrim.md` and the terminal `lookup-native-profile/` manifest.

### Pooled sumcheck arithmetic follow-up

Products with coefficient +1/-1 now initialize from their first affine factor
by copying/negating, avoiding an extension-field multiplication. Remaining
factors and verifier equations are unchanged. Expanded tests compare against
the independent scalar prover in both fields at batches 1/4/16. Release
sumcheck tests, all eight complete/compatibility tests, seven Python checks,
and the locked workspace all-target check pass. The final hoisted native pilot
preserves all eight complete proof digests in reversed orders. Single-proof
times are 4.49–5.10% lower for BabyBear and 2.62–2.63% lower for Goldilocks,
without warmups or ten measured samples. This does not establish the required
10% gain. A separate
wire-exact runner freezes both binaries and sources before comparisons.
An additional coefficient-hoisting/finite-difference candidate also passes
byte-exact native validation, but demonstrates no larger complete-PBS gain and
was removed. Stronger extension-coefficient and zero-term regressions remain.
See `unmasked-polyfrim.md` for the frozen candidate evidence and the Goldilocks
lazy-representation constraint. This arithmetic work does not resolve the
security requirements above.

### Unmasked canonical PolyFRIM experiment

A separate `CanonicalPcs` adapter now reuses joint-query rolling FRI without
private masks or opening-lifetime padding. Complete version-11 encrypted proofs
decode and verify all four NAND inputs in both selected fields. The evaluator
uses only a public evaluation key. All 72 fresh complete v10/v11 audit cases
pass (four controls accepted, 68 attacks rejected); existing strict actual-root
and child checks remain in use. The workspace all-target check passes.

All 72 PCS core tests (including two new non-base-source projection tests)
and four adapter tests pass. Complete regression tests
also preserve both frozen canonical wire controls and both ordinary Brakedown
truth tables. Three benchmark-reader tests reject mismatched schedules,
statements, keys, timings and result flags. Original-size
BabyBear and Goldilocks smokes now decode and verify, with matching native
FHE/key/statement hashes against complete canonical Brakedown controls. The
BabyBear proof is 864,192,360 bytes versus 361,248,811 (2.39x); Goldilocks is
980,814,131 versus 546,161,304 (1.80x). Raw correctness-run complete times are
505.65/391.45 seconds versus 12.95/25.37 seconds respectively, excluded from
performance comparisons. This does not justify promotion. All 168 fresh toy
certificates pass in two reversed field/backend orders. Native all-four-NAND
validation with reused keys is complete: sixteen decoded proofs under
`native-four-inputs/manifest.json`. The security
note separates exact-codeword algebra from the still-unproved robust proximity,
extraction and Fiat-Shamir composition. Defaults remain unchanged. See
`unmasked-polyfrim.md` and `target/performance/unmasked-polyfrim/`.


### Reconciled archived results (2026-10-29)

The corrected original-size Goldilocks masked run 2 completed successfully.
Its archived proving and replay exit codes are both zero; the production
report records decoded verification and altered-output rejection. The proof
is 2,632,157,742 bytes, proving takes 6,738.84 seconds, and process peak RSS
is 46,728,988 KiB. These are correctness/resource observations, with concurrent
work excluded from performance comparisons. Whole-security matching and hiding
remain uncertified. Earlier pending-run statements below are historical.

The aggregated full-stage audit also completed: 72 certificates, four accepted
controls and 68 rejected attacks across versions 10/11 and both fields.
Re-running the coverage checker confirms these counts. These small algebraic
fixtures establish neither original-size adversarial validation nor a security
certificate. Earlier pending-audit statements below are historical.

The next backend experiment should preserve original HasteBoots privacy
requirements without imposing an additional trace-hiding requirement. The
unmasked canonical PolyFRIM adapter is now implemented as an experimental
backend; see `unmasked-polyfrim.md`. Its tests and native runs are recorded
separately; no security or performance promotion is implied.


Masked query aggregation now regenerates one initial virtual source at a time,
retaining the intermediate ladders. All 70 core tests pass; six masked packet
fingerprints exactly match the previous implementation. Seven kernel tests
include direct retained/generated comparisons of bytes, sampled indices and
32-byte transcript state at batches 1/4/16 in both fields. Five canonical
context/adapter tests pass. Twelve separate-process resource controls also
verify matching proofs; 16-query peak RSS drops about 361→240 MiB in the
2^15-row width-2 fixture. See `generated-query-sources.md`. This does not establish
native batch fit, whole-PBS security or a timing improvement; full PBS regression
and the preserved earlier native/audit runs remain pending.

The first original-size masked Goldilocks run terminated at accumulator linkage:
the copied small-fixture allowance was 12, while the native owner needs 17.
Canonical opening budgets now derive from the public query schedule and reject
insufficient exposed limits before witness commitments. Remaining key-owner
allowances are checked before fresh witness allocation. Three budget tests
pass, and all four complete v10/v11 profiles retain exact archived non-timing
fields, including proof hashes. The workspace check also passes. The corrected
Goldilocks run 2 is live with allowance 17 at physical 21. See
`canonical-opening-budget.md`. No native complete-proof success is claimed.

Masked ordered batches now share both original-source and query-ladder rolling
FRI, with strict original-to-virtual authentication and the original per-query
allowances. Six decoded 1/4/16-query batches verify; 16-query packets are about
32% smaller than the prior joint-source format. All 70 core tests, repeated
component fingerprints and both base-field adapter tests pass. See
`masked-query-fri.md`. A distinct trusted canonical aggregated backend now also
passes all four small complete v10/v11 PBS cases. Native roots and fixture/FHE
geometry match the previous joint backend, while all backend domains and trusted
contexts remain disjoint. Proof bytes fall 11.3–14.2%; seven context/adapter
checks and the workspace all-target check pass. See
`canonical-aggregated-backend.md`. Native batch memory, new-schedule
hiding/security, original-size validation and the original full-plan gates
remain open; concurrent timings are not a performance claim.

A non-hiding joint-query proximity kernel now shares one rolling-FRI certificate
across 1/4/16 ordered matrix-query ladders on the same source. All 65 release
core tests pass, including fresh over-degree forgeries with valid consistency
and Merkle authentication that reject at the shared FRI fold; fresh valid FRI
proofs for substituted projections reject at the original-root binding. Six decoded
packets verify; 4/16-query packets are about 21.5/27% smaller than independent
controls. See `joint-query-proximity.md`. Masked/canonical/PBS integration,
complete-statement aggregation and all original security/performance gates remain
open. The existing masked backend is unchanged.

The canonical prover now releases completed blind-rotation witness owners before
allocating final key-switching sources. All four complete joint-backend proof
profiles (versions 10/11, both fields) retain exact archived non-timing fields,
including serialized proof hashes. Original key-owner lifetimes remain intact.
See `canonical-witness-release.md`. The first original-size Goldilocks masked PBS run terminated with an
insufficient accumulator opening allowance; no complete proof was produced.
See `native-complete-masked-pbs-profile.md`.

Original-size native masked key owners now pass resource validation in both
fields with the original FHE constants and 128 sampling queries. Four isolated
setups instantiate 88 owners and verify eight decoded openings. Retained and
transient policies have exact native parameter/table/root/proof/transcript
fingerprints. After-setup RSS falls from 9.10 to 3.48 GiB for BabyBear and from
12.54 to 5.34 GiB for Goldilocks; opening round trips cost more. See
`native-masked-key-setup-profile.md`. This closes native-key setup resource
measurement only. Complete original-size masked PBS, full security/hiding,
aggregation, security-matched performance and review gates remain open.

Eight isolated 128-query synthetic openings now measure transient caches at the
original native key-source dimensions. After-commit RSS drops by about 384 MiB
per owner in both fields, with exact proof/root/transcript fingerprints across
both cache policies and repetitions. Single-source peak RSS is unchanged and
regeneration increases proving time. See `native-source-cache-profile.md`.
Original-size masked native-key setup is measured separately; complete
original-size masked PBS remains unverified.

Masked source owners now support an opt-in transient encoded-codeword cache.
It regenerates the identical oracle once per batch and releases it afterward,
reducing idle retained allocations at the cost of extra FFT work. Retained and
transient proof bytes, roots, contexts and transcripts are compared in both
fields for 1/4/16-query batches and independent openings. See
`transient-source-cache.md`. This enables further original-size resource work;
it does not establish a full native PBS memory bound or latency improvement.

Fresh complete invalid-borrow lookup certificates now cover both blind-rotation
halves and final key switching in versions 10/11 over both fields and all three
canonical backends. All 36 new forgeries reject at the terminal reciprocal
identity while all other reported obligations hold. The prior sixty Brakedown
certificate and transcript fingerprints remain exact. All 104 selected Rust
tests pass. See `full-false-lookup-audit.md`. Broader lookup attacks, secure
original-size adversarial validation and all original security, aggregation,
hiding, performance and review gates remain open.

Fresh complete binding audits now cover the joint-source backend in both
versions 10 and 11 over both selected fields. All 60 new certificates pass
strict actual-root/NTT replay: four controls accepted and 56 attacks rejected
at the intended stages. Both transcript comparisons match, including a new
32-byte check. All 80 default SNARK tests remain green. See
`canonical-joint-fresh-binding-audit.md`. The invalid-borrow full false-lookup family now has separate coverage;
broader lookup attacks, secure encrypted/original-size audits and independent review remain
open, along with the original security/performance and full aggregation gates.

A distinct trusted joint-source canonical backend now composes complete version-
10/11 encrypted PBS proofs. Eight serialized/decoded complete proofs verify in
two isolated repetitions with identical full hashes and original native key
roots. The same 3,924 ordered responses use 1,900 source certificates. Small
version-11 proofs are 11.5% smaller for BabyBear and 9.2% for Goldilocks than
matched-geometry independent controls. See `canonical-joint-backend.md`.
Original-size/security, controlled backend timing, full query/FRI aggregation,
hiding and independent-review gates remain open.

An opt-in masked joint-source API now shares one original-source proximity
certificate across ordered 1/4/16-query batches. Each query retains its own
masked ladder and consumes its original allowance. Both core and base adapter
verify decoded batches and enforce one lifetime across independent/joint calls.
Sixteen-query component packets are 16.7–20.2% smaller with faster proving in
both execution orders. See `joint-source-proximity.md` and
`masked-joint-adapter.md`. The joint canonical backend now integrates these packets into complete PBS.
Full query/FRI aggregation, original-size/security, hiding and promotion remain open.

Two serial complete encrypted masked-PBS profile processes now verify eight
version-10/11 proofs and 3,924 actual child openings. All complete proof hashes
reproduce exactly. The version-11 timing gain is only 1.0–2.1% for BabyBear and
mixed for Goldilocks on the small one-query fixture. The original latency gate
is not met. See `complete-masked-pbs-profile.md`; original-size/security,
aggregation, hiding and independent-review requirements remain open.

Masked preflight now omits the high coefficient half selected out by the fixed
final `(I, 0)` query. The proof still authenticates the complete padded source.
Frozen comparisons preserve full proof bytes and transcripts; BabyBear component
proving improves while Goldilocks timings remain mixed. See
`masked-logical-preflight.md`. Complete security/performance gates remain open.

Masked opening preflight now reads data and mask lanes directly from the retained
paired source, removing full split buffers and their input clones. Proof and
budget semantics are unchanged. See `masked-borrowed-preflight.md`; the original
security and complete-PBS performance gates remain open.

Packed coefficient folds now use two matrix-vector products per coefficient
pair instead of three, preserving the original verifier equation and matrix
order. See `packed-fold-products.md` for tests and component timing. This does
not close the original security or complete-PBS performance gates.

Packed masked source and ladder encodings now use base-coordinate FFTs when
their domain lies in the base field. Frozen controls preserve complete proof
bytes and transcripts in both selected fields. See `packed-coordinate-encoder.md`.
The original security and complete-PBS performance gates remain open.

Fresh complete version-11 binding audits now cover both backends and selected
fields with sixty certificates: four accepted controls and fifty-six rejected
attacks. Reference replay authenticates every actual-root opening and reports
key products, canonicity, linkage, rotations and extraction separately. See
`canonical-v11-fresh-binding-audit.md`. Secure encrypted/original-size adversarial
audits, false-lookup composition cases, independent review and the original
security/performance gates remain open.

Complete canonical PBS version 11 now composes shared comparisons in both
blind-rotation halves and final key switching, with its own trusted entry point
and parent domain. Version 10 retains its proof spelling and frozen complete
wire bytes. See `canonical-shared-complete-pbs.md`. Further version-11
adversarial classes, native resource/performance validation, genuine joint
aggregation and the original security/promotion gates remain open.

Canonical final key switching now has an explicit shared-comparison entry point,
retaining known-input authentication, native key products, NTTs and original
output extraction. The old per-limb spelling keeps its serialized format. See
`canonical-shared-key-switch.md`. Version 11 integrates this component; the
original security/performance gates remain open.

Canonical radix decomposition now groups all limb comparisons through one shared
lookup point while retaining separate reconstruction and borrow-endpoint checks.
Source/digit/borrow roots keep their original retained sessions. See
`canonical-shared-decomposition.md`. The shared final key-switch component now
uses this path, and version 11 integrates it into complete PBS. The original
security/performance gates remain open.

Canonical shared-query extension lookups now support retained masked and ordinary
source sessions, independent batched scalar equations and one terminal query per
used root. Aliased slots reuse a checked claim; unused slots spend no allowance.
See `canonical-shared-lookups.md`. Version 11 integrates these comparisons;
genuine joint aggregation and the original security/performance gates remain open.

Fresh complete v10 key-product, linkage, rotation, extraction and canonicity
certificates pass strict child and actual-root replay on both backends and
selected fields. Four controls are accepted and fifty-six attacks are rejected
after fresh proof construction. These cover key products, endpoints, addition,
continuity, digit views, rotation, extraction and noncanonical digit strings. See `canonical-v10-fresh-linkage-audit.md`.
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
This stage is integrated into complete version-10 proofs; the original
security/performance gates remain open.

Canonical radix decomposition now composes retained source/digit roots,
canonical reconstruction/borrow-endpoint checks and extension-field transition
lookups, with explicit trusted borrow/helper budgets across adjacent limbs. See
`canonical-packed-decomposition.md`. Version 10 integrates this stage, including final key switching. Shared/deferred
composition and the original full security/performance gates remain open.

Extension-field rational lookups now expose canonical backend authentication
for original sources and coefficient-packed reciprocal helpers, retaining the
existing scalar extension algebra and base-field pullback maps. See
`canonical-extension-lookups.md`. Version 10 integrates the standalone comparisons. Shared/deferred comparison
composition remains open.

Public monomial products now have a canonical backend entry point, composing
both original-source NTT links with the caller-derived public rotation identity.
Derived roots retain one bounded session across NTT and terminal openings. See
`canonical-packed-monomial.md`. Version 10 integrates this stage; the original security/performance gates
remain open.

Accumulator linkage now dispatches through canonical backend sources while
sharing the original endpoint, continuity and duplicated-half equations. Legacy
callers retain their proof shape; masked callers authenticate ordered queries
against retained source sessions. See `canonical-packed-accumulator.md`.
Complete version-10 proofs now integrate this stage.

Native bootstrapping/switching key owners and their complete-PBS setup wrapper
now support statically selected canonical backends, retaining original source
states and validating native layouts plus all logical parameter geometries.
Public setup remains independent of proof bytes. See
`canonical-native-key-setup.md`. Complete version-10 proofs use these owners;
the original security/performance gates remain open.

Shared-challenge polynomial identities now expose canonical backend
authentication through the source registry, with retained borrowed factors and
individually checked terminal equations. Existing optimized Brakedown paths are
preserved. See `canonical-shared-relations.md`. Masked child openings remain
independent. Version 10 integrates polynomial identities; genuine joint
aggregation remains open.

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

### Classical fragmented backend integration (2026-10-31)

The third candidate now has a canonical ordered-matrix adapter in
`pcs/src/matrix_weighted/fragmented_pipfri.rs` and a trusted
`ClassicalProfile::fragmented_parameters` factory. It binds source geometry,
field representation, commitment, ordered matrices and claimed lane values,
draws independent extension-field lane projections, and reduces the claims
through a degree-two sumcheck to one unmasked scalar PipFRI opening. The
classical parent and extension child transcripts are linked. No masking or
lifetime allowance is introduced.

The adapter now streams its degree-two sumcheck kernel: each projected ordered
matrix product contributes directly to round evaluations without a full kernel
table. The first round reads the base source directly; subsequent rounds retain
one extension fold table, initially half the source length. A materialized
sumcheck remains only as a test reference. The scalar fragment opening itself is
still the existing reference. Base-field scalar-PCS storage, virtual combined
source oracles, shared authentication, complete classical security analysis and
security-matched performance qualification remain required. The complete PBS test now includes
all three candidate backends; test results are recorded separately from these
implementation claims under `target/performance/opening-inventory/`.

Validation passes: `cargo test -p pcs --test fragmented_adapter` (two field
tests covering constants, dense ordered matrices and batches 1/4/16, decoded
proofs, transcript agreement and altered claims/profile rejection);
`cargo test -p vfhe --test packed_classical_pbs` (both fields, three backends,
all four NAND inputs, reused public evaluation keys, decoded proofs and altered
profile rejection); and `cargo test -p vfhe --test packed_canonical_backend_wire`
(both frozen legacy wire fixtures). These are correctness and compatibility
checks, not concrete security or performance qualification.

The streamed sumcheck also passes an exact differential test against the
materialized `MLSumcheck` reference over both fields, source variable counts
0/1/3/4, widths 1/2/4/8 and batches 1/4/16 (96 cases). Every serialized round
message, challenge point and subsequent transcript output agrees. The standalone
fragmented adapter tests pass with the streamed prover. Logs:
`fragmented-streamed-differential-tests.log` and
`fragmented-streamed-adapter-tests.log` in the same evidence directory.
The complete PBS regression also passes with the streamed prover over both
fields and all three backends; see `fragmented-streamed-complete-pbs-tests.log`.
Its debug runtime is a correctness measurement and is not a performance gate.

The first streamed round now multiplies extension kernels by base-field source
values directly. The initial unbuffered native kernel comparison exposed a
regression: streamed/materialized median ratios were 1.96/4.61/7.38 for BabyBear
at batches 1/4/16 and 1.62/3.49/5.52 for Goldilocks. This comparison uses 12 source
variables, widths 8/4, 16 workers pinned to CPUs 0-15, one warm pair and ten
measured pairs in alternating order, with exact output checks. It measures the
bridge kernel only, without scalar PCS or full PBS. Raw samples and the
unbuffered source snapshot are retained in the opening-inventory evidence
directory; these results do not qualify a backend or a security profile.

The next kernel version uses resumable ordered-matrix iterators and sums all
claim kernels in a buffer of at most 4096 extension elements before multiplying
the source. This avoids repeating the three source/kernel multiplications for
each claim. The 96-case exact differential test passes with this buffered
version; native comparison is recorded separately.

Large buffered rounds now generate independent claim kernels in parallel, using
at most one stream group per Rayon worker and 4096-element partial buffers.
Smaller rounds remain sequential. An expanded exact differential test passes
120 cases, adding 10-variable sources to exercise the parallel branch over both
fields. The sequential buffered adapter tests also pass for both fields.

Three native kernel runs retain all raw samples and source snapshots in
`target/performance/opening-inventory/`; `fragmented-kernel-comparison.json`
collects the measurements. Relative to the initial unbuffered streamer, the
parallel buffered batch-16 median improves by about 52% for BabyBear and 43% for
Goldilocks. It still costs 3.70x/3.14x the materialized reference; batch-one costs
remain about 1.99x/1.63x. This is an improved bounded-memory prototype, not a
competitive or security-qualified replacement. Repeated ordered-matrix traversal
and sequential smaller rounds remain optimization targets. No default backend,
security status or production performance claim changes.

The complete toy PBS regression passes with the parallel buffered implementation
for both fields, all three backends and all four NAND inputs, including decoded
proof verification and altered-profile rejection. Evidence:
`fragmented-parallel-tiled-complete-pbs-tests.log`. Native-size correctness,
security qualification and security-matched end-to-end performance gates remain
separate requirements.

### Classical fresh-certificate audit (2026-10-31)

The test-only complete-certificate builder now accepts a hash type and an
initialized transcript. Existing legacy callers retain SHA-256 and the same
direct transcript constructor. A new classical audit uses SHA-512, the trusted
profile transcript and version-12 shared stages for Brakedown, direct PolyFRIM
and fragmented PipFRI over both selected extension fields.

For each field/backend pair it builds 18 fresh certificates: one valid control
and 17 isolated false identities covering initialization, final accumulator,
addition, chain, digit linkage, rotation, extraction, key products, canonical
decomposition and reciprocal lookups. It serializes and decodes each proof,
replays all children and actual-root openings through the strict audit verifier,
checks the complete transcript continuation, then calls the public classical
verifier and checks its specific rejection stage. Controls additionally test
version-11 payload rejection within the version-12 envelope. The fixtures use
zero/synthetic keys to isolate relations; they are not native encrypted-profile
security tests. The full run is explicitly ignored in ordinary test runs and
invoked with `cargo test -p snarks --release --lib classical_fresh_binding --
--ignored --nocapture`. Results belong in
`target/performance/opening-inventory/classical-fresh-binding-tests.log`.

The full classical run passes for both fields and all three backends: 108
decoded fresh certificates, six accepted controls and 102 rejected false
certificates. Each case also passes the complete child/actual-root replay and
the expected algebraic-validity and transcript-continuation checks. The six
controls reject an inner version-11 payload. The log inventory is checked for
exactly 18 distinct cases per field/backend pair in
`classical-fresh-binding-summary.json`. `cargo check -p snarks --tests` passes.
These checks improve regression coverage; availability/proximity, extraction,
Fiat-Shamir composition and conventional 128-bit work-factor qualification
remain unproved requirements.

The legacy version-11 Brakedown audit also passes after the shared test-builder
refactor: two controls and 34 rejected fresh false certificates, with complete
child/root replay and transcript checks. Evidence:
`classical-audit-legacy-regression-tests.log` (the two `v11_ordinary_` tests).

### Direct PolyFRIM base-field storage (2026-10-31)

The direct canonical adapter now retains honest source polynomials, FFT
codewords and shared ordered-prefix fold states in the base field. Its new
base-storage prover hashes the unchanged extension-field leaf encoding and
embeds only authenticated pairs for proof emission. Random projections and
rolling FRI remain in the extension field; projections multiply extension
weights directly by base values. Prefix sharing preserves complete parent
identity and ordered matrices, with the same 1 GiB cache-admission estimate
using actual base-field element sizes. This remains an additional-cache
estimate, not a whole-prover memory bound.

The extension-storage reference is available through an arithmetic-only policy
that is omitted from parameter serialization. The trusted parameter context,
roots, proof format, verifier and transcript are unchanged. Eight adapter tests
pass, including 30 exact proof-byte/transcript comparisons over both fields,
constants, dense noncommuting matrices, shared prefixes and batches 1/4/16.
The 11-variable/eight-lane cases exercise parallel FFT and Merkle hashing.
Retained-codeword payload byte counts are checked against the actual base or
extension element size. Four non-base-source and compact-codec tests pass,
preserving the verifier's general extension-alphabet contract. Evidence:
`polyfrim-base-storage-parallel-adapter-tests.log` and
`polyfrim-base-storage-nonbase-tests.log` in the opening-inventory directory.

Native performance measurements, further projection reuse, direct compact
emission, full security analysis and backend qualification remain required.

The workspace all-target check and complete toy PBS truth-table tests also pass
with base storage enabled (both fields, three backends, decoded proofs and
standalone public verification). Evidence:
`polyfrim-base-storage-workspace-check.log` and
`polyfrim-base-storage-complete-pbs-tests.log`. These checks do not substitute
for native-size correctness or security/performance qualification.

The fresh-certificate audit also passes after enabling base storage: all 108
decoded certificates complete the strict child/root replay, six controls verify
and 102 false certificates reject at their expected stages. The exact inventory
is checked in `polyfrim-base-storage-fresh-binding-summary.json`; the full log is
`polyfrim-base-storage-fresh-binding-tests.log`.

### PolyFRIM projection reuse and native PCS arithmetic comparison (2026-10-31)

The base-storage prover now groups projection rows by exact retained state
identity at each layer and scans each shared codeword once. All original
ordered statements, sampled weights, identifiers and authentication packets
remain present. It never merges states merely because their roots match. The
eight adapter tests pass, including 30 exact proof/transcript comparisons with
the extension-storage reference (`polyfrim-projection-reuse-tests.log`).

`pcs/examples/polyfrim_storage_profile.rs` compares the combined base-storage
and projection-reuse path against extension storage, with 16 workers pinned to
CPUs 0-15, one warm pair and ten alternating measured pairs. It uses 12 source
variables, widths eight/four, blowup two and eight experimental queries. Dense
matrix batches mix shared long prefixes, shared shorter prefixes and distinct
queries. Every one of the 132 opening proofs is serialized, decoded, publicly
verified, checked for transcript agreement and compared byte-for-byte with the
reference. Serialization and verification are outside the timing intervals;
cold setup is not timed. This is not a full-PBS or security-matched comparison.

The batch-16 median opening time falls by about 51% for BabyBear and 30% for
Goldilocks. Retained source-codeword payload is 262,144 bytes in each base
representation, versus 1,572,864/786,432 bytes in extension storage. These payload
counts exclude coefficients, tree nodes and allocator overhead and are not RSS
measurements. Raw samples and source hashes are recorded in
`polyfrim-storage-native-profile.log` and `polyfrim-storage-native-summary.json`
under the opening-inventory evidence directory. No security qualification,
default-backend change or end-to-end speed claim follows from this measurement.

### Direct dictionary emission for PolyFRIM (2026-10-31)

The normal base-storage compact prover now interns hashes while emitting
consistency roots/paths, rolling-FRI roots/paths and packed projection paths.
It no longer retains a complete full-hash proof before compressing it. Raw
hashes remain in transcript bindings and oracle trees; each temporary queried
path is mapped into dictionary indices before retention. Emission follows the
existing canonical first-use traversal, and the strict dictionary expander and
full verifier are unchanged. The extension-storage reference keeps its
materialized fallback for differential/adversarial-source fixtures.

The classical trusted profile now has a distinct `PolyfrimDictionary` encoding
variant and immutable parameter factory. It belongs to the existing PolyFRIM
algorithm family, binds the codec in the trusted profile, and is appended after
the existing backend variants to preserve their serialized tags and profile
identifiers. The full-PBS and fresh-certificate suites include this variant.

The existing dictionary roundtrip/rejection tests pass with direct emission.
New classical SHA-512 tests compare exact compact bytes with the independent
extension-storage prover followed by compression, compare expanded full bytes,
check transcript continuations, decode the proof and publicly verify it over
both fields, constants, dense matrices and batches 1/4/16. Full PCS regression,
profile factory, workspace and complete PBS results are recorded separately in
the opening-inventory evidence directory. This encoding change adds no claimed
security level, hiding or backend qualification.

The complete PCS library regression passes after the rolling-emitter refactor:
91 tests pass and three manual arithmetic profiles are ignored. This includes
the two new classical direct-emission tests (24 exact compact/full comparisons),
legacy dictionary rejection tests and rolling, fragmented and masked-protocol
coverage. The three profile-construction tests and updated workspace all-target
check also pass. Evidence: `direct-compact-pcs-suite.log`,
`direct-compact-profile-tests.log` and
`direct-compact-profile-workspace-check.log` in the opening-inventory directory.

Complete toy PBS truth tables pass over both fields for all three algorithm
families and both PolyFRIM encodings (32 valid decoded proofs plus altered
profile rejection). The expanded fresh-certificate audit passes 144 decoded
cases: eight controls verify and 136 false certificates reject at their expected
stages after complete child/root replay and transcript-continuation checks.
Evidence: `direct-compact-complete-pbs-tests.log`,
`direct-compact-fresh-binding-tests.log` and its checked inventory
`direct-compact-fresh-binding-summary.json`. The previously measured native PCS
executable is archived as `polyfrim-storage-native-profile-frozen` with its hash
in the original timing summary; those measurements precede this emitter change.
Native-size correctness, full security analysis, matched backend selection and
end-to-end performance qualification remain incomplete.

### Unmasked virtual-initial fragmented PipFRI (2026-10-31)

`pcs::pipfri::virtual_source` introduces explicit scalar opening version two.
It retains the original packed-fragment commitment, derives the random combined
initial word from those committed codewords without building its own Merkle
tree, and authenticates that virtual word through packed fragment paths at the
rolling-FRI locations. The same locations check public-point folds, eliminating
the separate consistency query batch and its duplicate ladder paths. The proof
contains only the following public-fold roots, the rolling proof and one packed
fragment pair per rolling sample. No masks, sessions or lifetime counters are
introduced. The ordinary version-one reference remains available.

Both selected extension fields pass 32 total scalar cases covering both bases,
fragment lengths 2/8, counts 1/2/4/16, full extension coordinates and zero/one
point coordinates. Values match an independent tensor contraction and the old
reference. Decoded proofs verify and transcript continuations agree; malformed
version/dimensions/paths/values reject. Fresh certificates binding a false vector
of fragment evaluations while using genuine source words, public folds and
authentication paths reject specifically at the public-fold terminal check.
The proofs have one fewer public root and smaller serialized size in these
fixtures. Evidence: `unmasked-virtual-pipfri-tests.log`.

The canonical streamed matrix bridge has an opt-in virtual variant with distinct
domains and a trusted `FragmentedPipfriVirtual` profile factory. Existing profile
tags/identifiers and the ordinary bridge are retained. Adapter, full-PBS and
fresh-certificate suites cover the new variant. Shared sampling changes the
security composition: old independent-query budgets are not a qualification
for this version. Availability, joint proximity/public-fold soundness,
Fiat-Shamir/knowledge composition and concrete work-factor analysis remain
required, along with native-size correctness and performance qualification.

The virtual matrix adapter tests pass for both fields, constants and batches
1/4/16, including decoded public verification, transcript agreement, altered
claims/profile rejection, equality of packed roots with the ordinary bridge,
and rejection of an ordinary-version retained state. The three profile factory
tests and workspace all-target check also pass. Evidence:
`virtual-fragmented-adapter-context-tests.log`,
`virtual-fragmented-profile-tests.log` and
`virtual-fragmented-workspace-check.log` in the opening-inventory directory.

The expanded fresh-certificate audit passes all 180 decoded cases over ten
field/variant combinations: ten controls verify and 170 false certificates
reject at their expected stages after strict complete child/root replay and
transcript-continuation checks. Evidence:
`virtual-fragmented-fresh-binding-tests.log` and the checked 180-case inventory
`virtual-fragmented-fresh-binding-summary.json`. This remains a synthetic-key
toy algebraic audit, not a native encrypted-profile or security certificate.

The complete toy PBS truth-table tests also pass over both fields and all five
explicit protocol/encoding variants: 40 valid decoded proofs across the four
NAND inputs, plus altered-profile rejection, with reused public evaluation keys
and standalone public verification. Evidence:
`virtual-fragmented-complete-pbs-tests.log`. No native performance or conventional
128-bit qualification is inferred from these correctness checks.

### Native classical correctness harness (2026-10-31)

`vfhe/examples/performance/classical_native_validation.rs` runs the classical
version-12 facade against the original BabyBear/Goldilocks binary FHE constants
(ring 1024, LWE/output 728), without changing noise, bases or output keys. It
constructs the evaluator from its public evaluation key, reuses one trusted
preprocessing setup, checks NAND decryption, drops each private trace, serializes
and decodes the proof, invokes the public verifier, and rejects altered output.
The default schedule covers all four NAND inputs; `--fresh-21` covers separate
fresh proofs in groups 1/4/16 with key reuse. All five explicit variants are
available. Query counts are explicit experimental correctness parameters; the
example emits no timing data and marks security/performance qualification false.

The harness records FHE-parameter, native public-key, trusted setup, profile,
statement and proof fingerprints. Its BabyBear virtual toy smoke passes all four
inputs. The native BabyBear Brakedown control also passes all four inputs with
decoded public verification and altered-output rejection at the original
dimensions. Its native-key fingerprint matches the archived canonical-v9 and
sextic-kernel controls. Evidence and a frozen executable/hash manifest are under
`target/performance/classical-native-validation/`; the harness check and toy log
are under `target/performance/opening-inventory/`. Other native variants and
fresh-21 schedules remain separate pending validation; no performance or
128-bit proof-security claim follows from these one-query correctness runs.

The native Goldilocks Brakedown control also passes all four NAND inputs,
bringing the two-field native control inventory to eight valid decoded proofs
and eight altered-output rejections. Both native public-key fingerprints match
the archived canonical-v9 controls. The virtual fragmented native runs have now
completed for the frozen pre-compiled-matrix validation build, as recorded below. Native
logs and per-field control inventories are in the same validation directory.

Both virtual fragmented native truth tables pass: eight further valid decoded
proofs and eight altered-output rejections, with unchanged native FHE, public
key and per-ordinal statement hashes compared with Brakedown. The complete
two-field/two-variant inventory contains 16 native proofs. Evidence:
`native-control-and-virtual-summary.json`, per-field virtual summaries and logs
under `target/performance/classical-native-validation/`. This validates the
frozen executable recorded in its manifest, before the compiled-matrix change;
the other variants and fresh-21 schedules remain incomplete.

### Compiled public matrices in the fragmented bridge (2026-10-31)

The streamed kernel now classifies public matrices once per proof into scalar,
sparse or dense actions. Scalar/sparse actions avoid traversing zero entries at
every node; dense matrices retain the original multiplication. Noncanonical
matrix entries retain the dense path, and the optimized paths preserve the
original multiply/add operations for retained entries. No profile, transcript,
wire format or verifier changes are introduced.

Six kernel tests pass (two manual profiles ignored), including 240 dense and
structured proof comparisons, independent materialized-kernel algebraic
verification, and raw-field-representative regressions. Both ordinary and
virtual adapter suites also pass. The structured comparisons require exact
bytes and transcript agreement with the prior dense streamed schedule.
New coverage found that the independently materialized and prior streamed
schedules can have different Goldilocks message representations for structured
inputs; they are not universally byte-identical. Both schedules' algebra is
checked, and this optimization preserves the actual prior streamed wire rather
than silently normalizing it. The earlier 120-case dense comparisons remain
valid observations, not a universal representation-equivalence theorem.
Evidence: `fragmented-compiled-matrix-complete-tests.log`,
`fragmented-compiled-matrix-final-tests.log` and
`fragmented-compiled-matrix-adapter-tests.log` in the opening-inventory directory.

The workspace all-target check passes. A native structured-kernel comparison
uses 16 workers pinned to CPUs 0-15, one warm pair and ten alternating measured
pairs, comparing compiled actions with the prior dense streamed schedule.
At batch 16, median kernel time falls about 42% for BabyBear and 30% for
Goldilocks; all measured proof/point/transcript byte strings agree. The input
mix includes scalar, identity/zero, sparse noncommuting and dense matrices.
The raw log retains the old variable label `materialized` for the baseline,
but in this structured comparison that baseline is the prior dense streamed
schedule, not the independently materialized polynomial prover. This distinction
is explicit in `fragmented-compiled-matrix-native-summary.json`; raw samples are
in `fragmented-compiled-matrix-native-profile.log`. These are kernel-only
engineering measurements, not a full-PBS speed gate or security qualification.

### Native PolyFRIM family and base-stored scalar fragments (2026-10-31)

The frozen native dictionary-PolyFRIM runs pass all four NAND inputs over both
fields, including decoded public verification and altered-output rejection.
FHE parameter, native public-key and per-ordinal statement hashes match the
Brakedown controls. The frozen validation inventory now contains 24 native
proofs across all three algorithm families, with dictionary PolyFRIM and virtual
fragmented PipFRI as the two new family representatives. Evidence:
`native-three-family-summary.json` and per-field dictionary logs/summaries under
`target/performance/classical-native-validation/`. Other encoding variants,
updated-build native runs and fresh-21 schedules remain incomplete. These
one-query correctness fixtures are not security-matched performance controls.

The virtual fragmented canonical prover now stores honest source coefficients
and encoded words in the base field, hashes the same embedded extension leaves,
and embeds pairs only for wire emission. Evaluations use at most one fragment's
temporary extension buffer; combined words and subsequent public-point/FRI
folds remain in the extension field. The original extension arithmetic is kept
for aggregation to preserve serialized representatives and transcript bytes.
The scalar reference remains available and the verifier/commitments/profile
identifiers/proof format are unchanged. The private virtual prover state is now
separate from the ordinary reference state.

The scalar base-storage tests pass 120 exact commitment/proof/transcript cases
over both fields, both bases, lengths 2/8, fragment counts 1/4/16, zero/one/random
data and noncanonical zero representatives. Four scalar tests also retain full
extension-source and fresh-false-value coverage. The two matrix adapter tests,
workspace all-target check, complete toy PBS suite (40 decoded proofs) and
180-case fresh-certificate audit all pass after enabling base storage. Source
payload counters cover coefficients/codewords only, excluding tree, table and
allocator overhead; they do not claim a whole-prover RSS bound. Evidence:
`virtual-fragment-base-storage-wire-tests.log`, `virtual-fragment-base-storage-core-tests.log`,
`virtual-fragment-base-storage-adapter-tests.log`, `virtual-fragment-base-storage-workspace-check.log`,
`virtual-fragment-base-storage-pbs-tests.log` and
`virtual-fragment-base-storage-fresh-summary.json` in the opening-inventory
directory. Full security analysis and end-to-end performance qualification
remain required.

### Updated native compatibility validation (2026-10-31)

The release native-validation harness builds after the compiled matrix and
base-stored virtual fragment changes. Its executable is snapshotted separately
as `target/performance/classical-native-validation/optimized-runner`, with a
SHA-256 manifest; the earlier frozen runner is retained. Native virtual runs
over both fields have been started; their final results remain pending.
`tools/compare_classical_native_validation.py` validates complete four-NAND or
fresh-21 schedules and requires exact reference/candidate records, including
setup, statement and proof hashes. Smoke checks pass for both existing field
logs, and six malformed/incomplete record fixtures are rejected. This check
does not establish security or a performance gate.

The complete updated PCS library suite passes (99 tests, four manual profiles
ignored); evidence is `optimized-complete-pcs-tests.log` under opening-inventory.
The first completed optimized Goldilocks native virtual proof has exactly the
same validation record, including proof hash, as its frozen reference. Full
four-case native schedules remain pending. The sequential runner
`tools/run_classical_native_validation.py` supports all five variants and both
fields, including fresh-21 schedules, records actual process exit status and
binary/log fingerprints, and validates complete schedules before marking a job
passed. Integration fixtures confirm that complete records with a successful
exit pass, while truncated records and nonzero exits fail. Output directories
are exclusive so existing evidence cannot be silently truncated or restarted.

The first completed optimized BabyBear native virtual proof also matches its
frozen record exactly. Both four-case virtual schedules continue. A separate
sequential updated-build matrix now covers Brakedown, full PolyFRIM, dictionary
PolyFRIM and ordinary fragmented PipFRI over both fields; its driver log is
`target/performance/classical-native-validation/optimized-matrix-driver.log`
and per-job status/logs are in `optimized-matrix/`. These jobs remain pending
until their actual processes terminate and the runner validates each schedule.
README and the version-12 native validation section in `docs/unmasked-polyfrim.md`
now document the reproducible commands and correctness-only scope.

The updated native BabyBear Brakedown job has terminated successfully with all
four decoded/verified proofs and altered-output rejections. All four complete
records match the frozen control exactly; evidence is
`optimized-matrix/babybear-brakedown.json` and its compatibility report in the
native-validation directory. The sequential matrix has advanced to full
PolyFRIM. A separate all-five-variant, both-field fresh-21 driver is now running
from the same frozen optimized executable (`optimized-fresh21-driver.log`,
per-job evidence in `optimized-fresh21/`). Its 210 planned proofs are pending,
not completed validation; neither driver supplies security or timing evidence.

The conditional classical work-cost arithmetic is now explicit in
`tools/classical_work_cost.py`: given justified nonnegative polynomial
all-trials success coefficients in a common charged work unit, it minimizes
work per success over all positive integer budgets using exact arithmetic.
It does not assume a selected query cutoff. Linear/quadratic 128-bit closed
forms and 56 exhaustive small-budget comparisons pass. The derivation and
conditional-history premise for retries are documented in
`docs/unmasked-polyfrim.md`. This supplies arithmetic for the eventual gate,
not the missing protocol coefficients or a security qualification.

The updated BabyBear Brakedown fresh-21 job has terminated successfully:
21 decoded/publicly verified proofs with reused public keys/setup and altered
output rejections. Its log fingerprint matches the terminal status record;
the first four proof records match the frozen four-NAND control except the
explicit schedule group labels. Evidence is in
`optimized-fresh21/babybear-brakedown{,-compatibility}.json` under native
validation. That driver has advanced to full PolyFRIM. Two optimized Goldilocks
virtual records now match the frozen reference, with that schedule still live.
The work-cost tool also rejects floating-point/boolean coefficients; 64 further
exhaustive cubic comparisons and malformed-input checks pass.

The native correctness harness now exposes the approved width (BabyBear 8/16,
Goldilocks 4/8) and blowup (2/4/8) grids; the sequential runner forwards these
and the existing fragment-cap selection. Defaults and the running frozen native
executables are unchanged. `cargo check -p vfhe --example
classical_native_validation` passes (`classical-native-geometry-check.log`).
A toy BabyBear virtual width-16/blowup-4 run is pending in
`classical-native-geometry-toy-babybear.log`. These options enable geometry
validation, not a completed security-qualified parameter search.

The fragmented bridge's conditional algebra reduction is now stated explicitly
in `docs/unmasked-polyfrim.md`: independent per-claim/lane extension coefficients
give a `1/|E|` false-compression event for a fixed false residual vector, and the
degree-two ν-round sumcheck adds at most `2ν/|E|` before reduction to the scalar
opening. The derivation matches both adapters' binding order, independent
coefficient draw, sumcheck degree and terminal equation. It deliberately leaves
source availability/extraction at the first query, adaptive scalar opening and
full Fiat–Shamir/all-trials composition as premises; it is not whole security.
The nondefault BabyBear toy geometry has completed two proofs and is continuing.

The width-16/blowup-4 BabyBear toy run has now terminated successfully with all
four NAND cases, decoded public verification and altered-output rejection;
its summary accompanies `classical-native-geometry-toy-babybear.log`. A
Goldilocks width-8/blowup-8 toy run is now pending in the analogous log. Updated
native virtual compatibility has reached two exact records for BabyBear and
three for Goldilocks; both native schedules and both sequential drivers remain
live. These are partial native results, not completed matrices.

The updated Goldilocks native virtual run has now terminated with exit zero.
All four original-size NAND proof records match the frozen build exactly,
including profile/setup/statement/proof fingerprints and proof sizes. Each
proof was decoded and publicly verified, with altered-output rejection.
Evidence: `goldilocks-virtual-optimized-status.json` and
`goldilocks-virtual-optimized-compatibility.json` under native validation.
BabyBear virtual has three exact completed records and remains live. The
Goldilocks width-8/blowup-8 toy run and both sequential drivers also continue.
The optimized Goldilocks result uses one-query correctness profiles and
establishes no security or performance qualification.

Future sequential validation runs now enforce cross-backend identity of FHE
parameters, native public keys and per-ordinal statements within each field.
Integration fixtures pass with matching identities and fail when a later
backend changes its public-key digest. This runner change does not hot-update
the already running drivers; their completed logs still require the same
cross-backend comparison during final inventory validation.

The Goldilocks width-8/blowup-8 toy process has terminated successfully with
all four NAND cases, decoded public verification and altered-output rejection.
Its log and summary are `classical-native-geometry-toy-goldilocks.log` and
`.summary.json` in opening-inventory. Both added nondefault toy geometries now
pass; these eight proofs do not validate the full geometry search grid.

Updated native full PolyFRIM over BabyBear has terminated successfully with
all four NAND cases, decoded public verification and altered-output rejection.
Its terminal log fingerprint is valid and its FHE parameter, public-key and
per-case statement fingerprints match the frozen Brakedown control. Evidence:
`optimized-matrix/babybear-polyfrim.json` and
`babybear-polyfrim-control-compatibility.json` under native validation. The
four-case driver has advanced to dictionary PolyFRIM; the fresh-21 PolyFRIM
job and the final BabyBear virtual case remain live. This adds an encoding
variant to correctness coverage without establishing security or timing gates.

Added the `classical_profile_grid` example to inventory the parameter-search
geometry across every existing extension degree (BabyBear 4/5/6/8 and
Goldilocks 2/3/4/5), approved widths, blowups 2/4/8 and fragment caps
8/10/12/14/16. It exercises all four trusted parameter constructors for each
candidate and emits fingerprints or admission errors. Compilation/execution
is pending in `classical-profile-grid.log` under opening-inventory. Its
one-query feasibility inventory is distinct from full-PBS correctness and
security-qualified parameter selection.

Updated BabyBear native virtual has terminated successfully too. All eight
native virtual records over both fields exactly match the frozen build and
match the field controls' FHE/key/statement identities. The aggregate evidence
is `optimized-virtual-summary.json`; per-field terminal status and compatibility
reports are alongside it in native validation. The parameter grid is still
running (417 candidates emitted so far, no construction rejections).

A conditional fixed-depth Merkle partial-word extraction argument is now
written in `docs/unmasked-polyfrim.md`. It extracts available leaves from the
pre-challenge query graph and bounds later unknown-preimage openings by a
fixed target set, plus one global collision term. It explicitly handles
untagged internal hashes via depth/index-dependent parsing and requires
deterministic resource envelopes or expected predictable exposures for
adaptive stopping. Production leaf-encoding audits, actual first-query
freeze placement, all-trials root/work bounds, RS decoding/proximity and
Fiat–Shamir composition remain required before applying it to qualification.

The grid inventory has now terminated successfully with all 624 requested
candidate combinations present exactly once. Of these, 585 construct all four
role parameters, with 585 distinct profile identifiers. The 39 rejections are
exactly Goldilocks degree-5 / width-4 combinations: the extension degree exceeds
the lane width. Evidence: `classical-profile-grid.summary.json` alongside the
full log in opening-inventory. This prunes incompatible geometry, not security
parameters. The encoding audit also identified that extension-field sequence
deserialization reads D coefficients without rejecting extras; a focused
regression across all eight extension types is compiling before the fix.

The extension decoder regression reproduced acceptance of five coefficients
for a degree-four element (`extension-wire-shape-before.log`). The decoder now
requires exactly D coefficients, checking for extras after reading the required
entries. Serialization is untouched. The regression covers exact-byte zero
round trips and short/overlong vectors for all eight existing extension types.
The algebra library suite, frozen legacy wire fixtures and virtual scalar PCS
decode/verification tests are running after the fix; their results are pending.
The running native drivers use the earlier frozen executable and are not
evidence of this later decoder change.

After the decoder fix, all 29 algebra library tests and all four virtual scalar
PCS tests pass, including decoded proofs and exact reference-wire comparisons.
The initial frozen-legacy fixture command terminated during compilation with
E0463 missing `lattice`/`trace` dependency artifacts (and a Cargo cache-lock
warning); it did not execute fixture assertions. It is being retried alone
after the other builds terminated, with evidence in
`extension-wire-shape-legacy-fixtures-retry.log`. The production leaf-encoding
audit now documents actual byte prefixes, context/index placement, trusted
shape checks and concrete field interpretation for the Merkle availability
premise. Full adaptive freeze/RS/Fiat–Shamir obligations remain open.

The frozen optimized BabyBear dictionary PolyFRIM job has terminated with all
four native cases passing; every complete validation record exactly matches
the earlier frozen dictionary control. Its compatibility report is in
`optimized-matrix/babybear-dictionary-compatibility.json`. The four-case driver
has advanced to ordinary fragmented PipFRI; the full-PolyFRIM fresh-21 job is
still running. These executables predate the extension decoder tightening.

The isolated frozen-wire retry has now passed both BabyBear and Goldilocks
fixtures after the extension decoder fix. Together with the 29 algebra tests
and four virtual PCS tests, this verifies the focused malformed-length
rejection and preserves the checked valid legacy encodings. Evidence:
`extension-wire-shape-legacy-fixtures-retry.log` (two passed),
`extension-wire-shape-after.log` and `extension-wire-shape-virtual-pcs.log`.
The first failed build log is retained as compilation-failure evidence rather
than presented as a protocol failure or a passing fixture run.

The transcript analysis now gives an explicit conditional phase-emulation
argument for the framed implementation under an ideal variable-output XOF:
injective requests, exact rejection-sampled field vectors, and uniform
power-of-two index vectors sampled as one phase. It separates this assumption
from concrete SHAKE256 security, and separates parent/child fingerprint output
collisions from guessed seed/finish links that need late-target accounting.
The latter requires all candidate link slots and their processing cost, not
accepted-proof fork counts. No numeric whole-protocol bound is inferred;
uniform prefix state predicates and rolling/vector proximity remain open.

The native harness and runner now expose `--helper-basis` for Brakedown and
direct PolyFRIM, using extension-degree helper width while preserving the
selected source width. This exercises an already supported trusted-profile
geometry and can reduce unused helper lanes; fragmented variants reject the
option because their bridge requires source-width helpers. A Goldilocks
dictionary toy run at source width 8, helper width 3 and blowup 4 is compiling
in `classical-helper-basis-toy-goldilocks.log`. Defaults and frozen running
native executables are unchanged; no new performance claim is made.

The helper-basis Goldilocks dictionary toy run has completed two decoded,
publicly verified proofs so far and continues. The profile-grid example now
also accepts `--helper-basis`, separately inventorying extension-degree helper
packing for the three nonfragmented encodings across the existing fields,
degrees, source widths and blowups. Its run is pending in
`classical-helper-basis-profile-grid.log`; the earlier 624-candidate source-width
inventory remains separate evidence. The native drivers are still live.

The rolling analysis now states an explicit conditional component state:
current minimum error potential at least delta, or a fixed future original
farther than delta. The pointwise disagreement-set inclusion establishes
closure under arbitrary derived-word and terminal messages; the final
whole-vector phase supplies the `(1-delta)^Q` bad-to-good bound. This is an
ideal fixed-word-game argument, still dependent on a uniform RS exceptional-set
lemma and a coupling to the actual first-query/virtual-source execution.
It does not condition fresh coins on the absence of future hash failures,
and it does not assert full noninteractive knowledge security.

The Goldilocks dictionary helper-basis toy run has terminated successfully:
four NAND cases at source width 8, helper width 3 and blowup 4, with decoded
public verification and altered-output rejection. FHE/key/per-case statement
identities match the preceding Goldilocks toy geometry control. Evidence is
`classical-helper-basis-toy-goldilocks.summary.json` and its log. The separate
helper-basis profile inventory remains live (125 records so far).

The helper-basis inventory has now terminated successfully. All 144 requested
nonfragmented combinations appear exactly once: 135 construct their four
role parameter sets and nine reject Goldilocks degree 5 at source width 4.
The 135 admitted identifiers are distinct; 18 coincide with the earlier grid
where helper degree already equals source width, and 117 are additional.
Together the two inventories contain 702 distinct feasible profiles. Evidence:
`classical-helper-basis-profile-grid.summary.json` and its full log. These are
one-query construction checks, not security-qualified choices or full native
validation of every profile. A check of both updated examples is running in
`classical-helper-basis-examples-check.log`.

Both updated examples pass their compilation check. The base-stored virtual
source commit now encodes independent fragments in parallel and hashes packed
leaves in parallel for trees with at least 128 leaves, preserving indexed
collection order. Small-tree hashing stays sequential. No transcript, profile
or proof format changes. The exact extension-storage differential suite now
also covers fragment length 128 to exercise parallel hashing, increasing its
base-storage comparisons from 120 to 180 cases across both fields. Its run is
pending in `virtual-base-parallel-commit-tests.log`. Per-worker temporary leaf
buffers are additional private memory; no whole-prover RSS or speed claim is
made, and the frozen native drivers predate this commit-path optimization.

The expanded virtual scalar suite has now passed all four tests: 180 exact
base-storage/root/proof/transcript comparisons, plus the retained general
extension-source and fresh-false-value checks. Evidence is
`virtual-base-parallel-commit-tests.log` (16 Rayon workers, four passed).

The parallel commit path also passes both matrix adapter integration tests
(`virtual-base-parallel-adapter-tests.log`). The frozen optimized native
four-case matrix has finished every BabyBear encoding variant, including
ordinary fragmented PipFRI, and has passed Goldilocks Brakedown. The latter's
four records exactly match its frozen control; BabyBear ordinary fragmented
matches control FHE/key/statement identities. Reports are in `optimized-matrix/`.
That driver has advanced to Goldilocks full PolyFRIM; the BabyBear full-PolyFRIM
fresh-21 job is still running.

The NTT row-point amplification boundary is now available as an opt-in trusted
profile version two (`new_atomic_ntt`) with a distinct transcript identifier
and profile ID. It draws all width-by-row-variable coins in one XOF phase,
including correct zero-row handling. Descriptor version one, legacy schedules
and their verifiers remain selectable. The outer classical PBS encoding stays
version 12; the expected profile distinguishes schedules. Children inherit
the new selection, and the harness/runner expose `--atomic-ntt`. The snarks
compilation check passes; focused helper/profile/NTT tests are compiling in
`classical-atomic-ntt-tests.log`. Full new-profile validation and whole security
remain pending; this change does not assert that the previous schedule is
insecure or justify a query count.

The first focused atomic test run passed helper schedule inheritance and
profile separation, but its NTT fixture requested unsupported 8/16-point
native transforms. The fixture now uses supported 32-point transforms with
both zero and positive row-variable counts; its retry is compiling in
`classical-atomic-ntt-tests-retry.log`. Complete toy truth-table coverage for
the atomic profile has also been added for both fields and all five encoding
variants (40 decoded proofs planned); those new end-to-end tests have not yet
run. The original profile-one truth-table tests remain separate and unchanged
in selection.

The focused atomic retry has now passed all three selected tests: helper
schedule inheritance, trusted-profile separation/selection, and exact row-point
phase/tail comparisons for both fields with zero and positive row-variable
counts, retaining the old schedule's reference comparison. The 40-proof atomic
toy PBS suite is building in `classical-atomic-ntt-complete-pbs-tests.log`.
Fresh-certificate atomic audit entrypoints have also been added for both fields
and all five variants (180 cases planned); they have not yet been executed.

The atomic toy suite has finished building and is running. The 180-case fresh
audit has now been started in release mode with 16 workers pinned to CPUs 0-15;
its build/run log is `classical-atomic-ntt-fresh-tests.log`. Both remain pending,
and neither supplies a formal security qualification.

The atomic toy PBS suite has now passed both field tests: 40 decoded complete
NAND proofs across all five variants and their altered-profile-header rejection
checks (`classical-atomic-ntt-complete-pbs-tests.log`). This includes the current
strict extension decoder and parallel virtual-source commit path.

The Brakedown analysis now includes a conditional padding-consistency step:
decoded nonzero padded coefficients survive h independent base test rows with
probability at most p^-h; otherwise a supplied zero-padded response differs
from the decoded RS combination and column sampling sees at least D-t rejecting
positions. The existing n(n+1)/p^h envelope dominates this extra near-case event.
`docs/block-rs.md` states its fixed-word/phase premises. Both production padding
regressions pass with accepted controls, actual malicious RS columns, genuine
Merkle paths, decoded proofs and zero structured queries, covering source and
helper widths in both fields (`brakedown-authentic-padding-tests.log`). Full
availability/RS/Fiat–Shamir composition and knowledge extraction remain open.

The atomic profile's release fresh-certificate audit has now terminated
successfully over both fields and all five variants: 180 unique cases,
10 accepted controls and 170 rejected freshly generated false certificates.
Both test entrypoints pass. The exact inventory and log fingerprint are in
`classical-atomic-ntt-fresh-tests.summary.json`. These fixtures use synthetic
or zero public keys to isolate relations; they are not native encrypted-profile
security evidence. Native atomic-profile validation and matched performance
qualification remain outstanding, alongside the full formal security argument.

The release native harness now builds with atomic profile selection, the
strict extension decoder and parallel base-source commit. It is snapshotted
as `atomic-runner` with binary and relevant source fingerprints in
`atomic-manifest.json`, separate from prior runners. An all-five-variant,
both-field native four-case matrix has started with `--atomic-ntt`; its driver
and job evidence are `atomic-matrix-driver.log` and `atomic-matrix/`. Results
remain pending and use one-query correctness fixtures.

The previous runner's BabyBear full-PolyFRIM fresh-21 schedule has terminated
successfully. All 21 decoded/publicly verified cases reject altered outputs;
FHE/key/per-ordinal statements match its Brakedown fresh-21 control, and the
first four proof records match its four-case run except schedule labels.
Evidence is `optimized-fresh21/babybear-polyfrim-control-compatibility.json`
and the terminal job record. That driver has advanced to dictionary PolyFRIM.
The row-code analysis also now states a conditional component predicate for
single/shared-batch openings, retaining separate random-test and complete
column-phase transition bounds; global composition remains open.

The atomic runner's BabyBear Brakedown native job has terminated successfully
with all four cases. Its FHE/key/statements match the version-one control while
its independently trusted profile descriptor/ID differ as intended. Terminal
binary/log fingerprints and the cross-control report are in `atomic-matrix/`;
that driver has advanced to full PolyFRIM. The earlier runner also passed
Goldilocks full PolyFRIM and advanced to dictionary validation; its cross-field
inventory still needs final validation after all jobs terminate.

The unmasked scalar analysis now handles gamma power weights explicitly:
the joint-fragment proximity term has degree factor f-1, not the independent-
weight bound. It gives separate conditional scalar bounds for the virtual
initial source and ordinary materialized reference; the latter needs a smaller
rolling radius to retain an initial-link distance gap. The virtual shared
indices are analyzed by one applicable rejecting set, not independent tails.
The symbolic audit supports one/four/eight fragments and all 12 tests pass.
Its two-point eight-fragment control has seven nearby gamma values, exceeding
the six allowed by incorrectly omitting the degree factor. Evidence is
`fragment-power-curve-audit-tests.log`. All results remain conditional on
RS/availability/XOF and full composition premises; no query count is promoted.

Both completed full-PolyFRIM jobs now have verified control reports: Goldilocks
on the earlier optimized runner and BabyBear on the atomic runner. Their four
native NAND cases preserve FHE/key/statements; the atomic profile differs from
version one as intended. Each driver has advanced to dictionary PolyFRIM.

`tools/fragmented_opening_terms.py` now evaluates the conditional scalar/bridge
formulas exactly for supplied role geometry, fragment cap, field and query
count. It mirrors physical constant padding and charges f-1 for gamma, with
separate reference/virtual radii and sampling phases. Four tests pass, covering
closed-form terms, the native helper geometry, constant/one-fragment edges and
invalid inputs (`fragmented-opening-terms-tests.log`). It does not choose Q,
validate a concrete field/domain or certify the excluded global security/work
terms. The one-query helper example is retained only as an arithmetic artifact.

The work-cost calculator now accepts a nonnegative constant failure term and
an independently justified minimum attacker budget. This prevents global
honest/verifier oracle queries from being silently treated as attacker work.
The exact minimization checks the low-budget endpoint as well as saturation
neighbors; for nonnegative coefficients the unsaturated success/work ratio
is convex, so these suffice. Pure-constant cases are handled separately.
Four tests pass, including 243 exhaustive constant/linear/quadratic/cubic and
minimum-budget models, original 128-bit closed forms and invalid-input checks
(`classical-work-cost-offset-tests.log`). The resource envelopes and any
minimum budget still require proof; neither is inferred from honest timing
or an accepted transcript, and protocol qualification remains false.

Atomic-profile BabyBear dictionary PolyFRIM has now terminated successfully
with all four native cases. Its FHE/key/statement identities match the control;
the cross-control report and terminal fingerprints are in `atomic-matrix/`.
That driver has advanced to ordinary fragmented PipFRI. The earlier native
matrix and version-one fresh-21 driver remain live.

The earlier runner's Goldilocks dictionary native job has terminated with all
four cases passing and exact frozen-control record agreement. Its compatibility
report is in `optimized-matrix/`; that driver is running the last ordinary
fragmented Goldilocks job.

New harness builds emit a separate `HB_CLASSICAL_PROFILE` diagnostic with
canonical descriptor bytes, both fingerprints, schedule and role geometry.
The diagnostic reader independently decodes the current native field types,
checks the basis table/suites/canonical bincode and binds displayed geometry to
those bytes. Future runner jobs check requested geometry/schedule and record
whether the header was available; `--require-profile-header` can require it.
Older frozen logs remain supported and their existing proof-record schema is
unchanged. This diagnostic parser does not load verifier profiles from proofs.

The BabyBear atomic/helper-basis header toy run passed all four NAND cases,
decoded verification and altered-output rejection. Independent Python decoding
and fingerprint checks pass, including actual role widths 8/6 and toy variable
counts. Six tampered headers are rejected, including a nonminimal bincode
integer with recomputed hashes. Evidence: `classical-profile-header-toy.log`
and its summary. The analogous Goldilocks/version-one header run is pending
in `classical-profile-header-toy-goldilocks.log`. Running frozen native drivers
predate this logging-only addition and are not restarted.

The Goldilocks/version-one descriptor-header toy run has now terminated
successfully with four NAND cases. Independent decoding verifies its native
degree-three basis, suites, descriptor fingerprints and helper widths 4/3;
all proofs decode/verify and altered outputs reject. Its summary accompanies
`classical-profile-header-toy-goldilocks.log`. Together with the BabyBear run,
both native harness field representations and both schedule versions have
diagnostic interoperability coverage (toy geometry only).

The conditional Merkle availability analysis now also uses a shared
predictable target set across roots: at most two child-digest targets per
exposed internal-sized hash input plus declared root values. Its conservative
global envelope is `H(H-1)/2^(h+1) + H(2H+R)/2^h`, avoiding a repeated H^2
target charge for every root. The optional `--global-targets` worksheet and
nonnegative affine-attacker-work coefficient helper are implemented while
retaining the old default calculation. Nine hash-budget tests pass, including
480 resource-envelope comparisons (`global-merkle-target-tests.log`). H/R and
their attacker-work envelopes still require all-trials proof, not observed
successful-run counts; source/link coupling and whole security remain open.

The native harness and runner now accept mutually exclusive uniform
`--queries Q` or `--role-queries A,B,C,D` options, in source/main-helper/
final-source/final-helper order. Per-role counts bind through all four trusted
parameters and the descriptor. Uniform logs retain their previous schema;
nonuniform logs carry `queries: null` and explicit role counts. The comparison
reader rejects malformed, conflicting, Boolean, out-of-range and noncanonical
count metadata, and checks the counts against any descriptor header.
Three focused regression tests pass (`test_classical_query_metadata.py`).

The BabyBear atomic-profile toy run with counts 1/2/3/4 passed all four NAND
cases, decoded public verification and altered-output rejection. Independent
descriptor decoding and fingerprints confirm the actual bound counts;
evidence is `opening-inventory/classical-role-queries-toy.log` and its summary.
These counts are correctness fixtures, not a derived security selection.

The prior optimized native matrix completed all 40 proofs across both fields
and five variants; its summary audits terminal status, log/binary fingerprints
and native control identities. The ongoing version-one fresh-21 matrix has
completed BabyBear Brakedown, direct PolyFRIM and dictionary PolyFRIM (63
proofs). The newer atomic matrix has completed all five BabyBear variants and
Goldilocks Brakedown (24 proofs). Additional post-run audits verify the
BabyBear dictionary fresh-21 and Goldilocks atomic Brakedown fingerprints,
terminal exits and control FHE/key/statement identities. Both matrix drivers
remain active; no timing or security qualification follows from these runs.

The native correctness harness now dispatches all eight existing extension
types through complete PBS setup/prove/decoded-verify paths, selected with
`--extension-degree` (BabyBear 4/5/6/8, Goldilocks 2/3/4/5). Defaults remain
BabyBear 6 and Goldilocks 3. The runner rejects field/degree mismatches before
creating output and requires records to match the requested degree. Its
diagnostic decoder now checks the complete basis table for each of these
trusted types. This connects the existing feasibility inventory to end-to-end
candidate validation; it does not select a security-qualified candidate.

`cargo check -p vfhe --example classical_native_validation` passes for all
dispatches (`classical-extension-degree-check.log`). Nine focused Python tests
pass, including descriptor parsing for all eight fields and both schedules,
wrong-basis/unknown-field/truncated/trailing descriptor rejection, query-count
metadata and exact work-cost arithmetic. A Goldilocks degree-2 virtual-source
toy run is pending in `classical-extension-degree-toy-goldilocks2.log`; no
new-degree end-to-end pass is claimed until it terminates successfully.

The Goldilocks degree-2 toy run has now terminated with exit zero: all four
NAND cases decode/verify and reject altered outputs, and independent decoding
confirms its version-two descriptor/basis. Its summary is alongside the log.
The compiled binary is now running the other seven field/degree combinations
sequentially, using virtual fragmented proofs and width 8 for Goldilocks
degree 5. BabyBear degrees 4 and 5 have each completed four cases with audited
terminal status, log fingerprints and descriptor bindings. Other degree runs
are pending; these are toy correctness checks, not native qualification.

The conditional security notes now give two explicit coupling constructions:
first-declaration snapshots yield one deterministic completed word per
root/trusted-geometry pair across grinding branches, and registering all
64-byte candidate-input windows gives an ideal-XOF link bound
`M(M-1)/2^513 + M*B/2^512`. These are conditional lemmas, with global resource
caps rather than successful-proof counts. The implementation-wide declaration
audit, consistent whole-PBS bad-state predicate, receipt obligations,
attacker-work envelopes and knowledge argument remain open. No full security
certificate or new eligible query count follows from the notes.

The atomic native matrix has additionally completed Goldilocks direct
PolyFRIM (28 total completed proofs). Its four records match the control's
FHE parameters, public keys and statements, with terminal exit/log fingerprint
audited in `atomic-matrix/goldilocks-polyfrim-control-compatibility.json`.

All eight extension types have now completed the atomic-NTT virtual-fragmented
toy PBS schedule: 32 decoded proofs, four NAND inputs per type. Terminal exits,
log fingerprints, all descriptor basis tables and bound profile IDs were
audited. FHE parameters, public keys and statements match across degrees of
each field, including the width-8 Goldilocks degree-5 case. Coverage and
per-log evidence are in
`opening-inventory/classical-extension-degree-complete-summary.json`.
These checks cover toy geometry and one backend, not all native candidate
profiles or security-qualified queries.

The native runner now also rejects a source width smaller than the selected
extension degree before binary lookup or output creation. Ten focused Python
tests pass, including subprocess checks of invalid field/degree/width
preflight (`classical-extension-degree-python-tests.log`).

The security notes now identify literal PCS root/claim declarations and their
coin ordering in both prover/verifier paths; source fingerprints are in
`classical-pcs-declaration-audit.json`. Virtual identifiers are explicitly
distinguished from extractable Merkle roots. The audit leaves the multi-phase
joint PolyFRIM projection argument open: separate vector challenges cannot be
silently treated as one fresh atomic matrix challenge. A conditional NTT
bad-state argument is also written for the atomic-row schedule, ending in a
false PCS claim outside bounded row/compression transitions. Parent/lookup
declaration ordering, full state composition and knowledge/work bounds remain
unfinished; these additions do not certify whole security.

The shared canonical lookup source/helper phase audit is now documented from
the actual preflight, source registry, child/multiplicity binding, helper-root
binding and separate scalar sumcheck paths. A conditional component state
argument fixes one invalid request/repetition, bounds tuple-compression
exceptions, treats every raw reciprocal draw (including rejections), then
reduces to a false helper equation or PCS claim. It explicitly uses L<p and
r!=0: source multiplicities must not wrap the characteristic, and masked
helper rows must be forced to zero. It does not import the interactive
repetition product into an adaptive first-query bound.

Source fingerprints are recorded in
`classical-parent-lookup-declaration-audit.json`. Three new finite-field model
tests check tuple-hash exception degrees, rational discrepancies against
arbitrary public multiplicities, and counterexamples when the characteristic
or excluded-zero premises are removed. All 13 `test_classical*.py` tests pass
(`classical-parent-lookup-state-tests.log`); five existing packed equality/NTT
tests also pass (`classical-ntt-state-equality-tests.log`). These checks support
the local algebraic reasoning, not a protocol theorem. Full source/bridge
coupling, parent composition, knowledge extraction and attacker-work envelopes
remain unproved, so no security-qualified query selection or promotion occurs.

An explicitly selected version-three trusted profile now groups every joint
PolyFRIM projection weight into one extension-vector challenge phase, in the
same layer/member/lane layout used by the arithmetic. It also retains the
atomic NTT row schedule. `new_atomic_phases` and the harness/runner option
`--atomic-phases` select it; the latter is mutually exclusive with
`--atomic-ntt`. Version-one/two factories and their existing projection paths
remain intact. The new schedule marker, suite and profile version bind its
different challenge stream; it cannot be inferred from a proof.

Three focused Rust tests pass: schedule inheritance into checked children,
distinct profile IDs/parameter construction, and independent projection-phase
and transcript-tail comparisons for both fields across versions 1/2/3.
Evidence is `classical-atomic-phases-tests.log`. All 13 focused Python tests
pass with descriptor parsing now covering all eight fields and all three
schedules (`classical-atomic-phases-python-tests.log`). A version-three
BabyBear dictionary toy run is pending in
`classical-atomic-phases-toy-babybear.log`; partial records are not a pass.
This removes the multiple-phase projection grouping obligation for version
three, not the remaining fixed-word/vector, parent-state, knowledge or work
obligations. No whole-security or performance qualification is claimed.

The frozen version-two native matrix has completed Goldilocks dictionary
PolyFRIM as well (32 proofs total). Its terminal exit, log fingerprint and
control FHE/key/statement identities are audited in
`atomic-matrix/goldilocks-dictionary-control-compatibility.json`.

The version-three targeted toy runs have both terminated with exit zero:
BabyBear dictionary and Goldilocks direct PolyFRIM each pass all four NAND
cases, decoded public verification and altered-output rejection. Independent
descriptor parsing verifies version three and its suite/basis. Their FHE
parameters, keys and statements match the corresponding field controls.
Summaries accompany `classical-atomic-phases-toy-{babybear,goldilocks}.log`.
These eight proofs validate the new projection schedule at toy geometry;
they do not provide native or security-matched performance evidence.

The complete truth-table tests and manual fresh-certificate audit now also
have explicit version-three entries for both fields and all five variants,
while retaining the existing version-one/two entries. The full version-three
truth-table run is active in `classical-atomic-phases-complete-pbs-tests.log`;
its final status and the new fresh-certificate cases remain pending.

The complete version-three truth-table run has now terminated with exit zero:
both tests pass across all five variants, yielding 40 decoded NAND proofs
and 40 profile-tamper rejections. The log and independently checked summary
are `classical-atomic-phases-complete-pbs-tests.{log,summary.json}`.

The feasibility grid now accepts `--atomic-phases`, alone or together with
`--helper-basis`, and reports the descriptor version on each record. It
constructs all four real parameter sets with the selected version-three
factory, retaining version one as the default. Both inventories are active
in `classical-atomic-phases-profile-grid.log` and
`classical-atomic-phases-helper-basis-grid.log`. Final coverage/admission and
profile-ID comparisons are pending; partial rows are not completed grids.

The version-three manual fresh-binding suite has started with release mode,
16 Rayon workers and CPUs 0-15, logging to
`classical-atomic-phases-fresh-tests.log`. Compilation is still active; no
new 180-case pass is claimed. The two frozen native matrix drivers also
remain active. A source inspection identified repeated full native-plan
construction just to obtain a root in PolyFRIM parameter setup; a possible
root-only caching optimization remains unimplemented and needs exact-root/
parameter-byte compatibility checks before adoption.

Both version-three feasibility inventories have completed. The source-width
grid has 624 candidates, 585 constructed and 39 rejected, exactly matching
version-one geometry/admission with distinct profile IDs. The helper-basis
grid has 144 candidates, 135 constructed and nine rejected; 18 IDs overlap
source-width helpers, yielding 702 distinct feasible version-three profiles.
Audited summaries accompany both logs. This is feasibility coverage, not a
selection of secure query counts.

The version-three fresh-certificate audit also terminated successfully:
180 distinct cases across ten field/backend groups, with ten controls
accepted and 170 false relations rejected. Every group contains exactly the
18 expected attacks and both Rust test terminals pass. Its summary is
`classical-atomic-phases-fresh-tests.summary.json`. This release build predates
the following root-only setup cache; it remains toy correctness evidence.

The native BabyBear/Goldilocks NTT implementations now expose a root-only
lookup preserving exactly the native plan's root and errors. On first use
they reuse an existing full plan or create/drop one native plan, then retain
only the root per domain. PolyFRIM parameter setup uses this lookup instead
of rebuilding a full plan for each repeated root request. No root is derived
from a different generator, and no transform table is retained by this cache.
Two tests pass for both fields: raw/serialized root equality, native errors,
reuse of retained plans, and concurrent requests across fields/domains
(`ntt-root-cache-tests-retained-plan.log`). Complete before/after proof-byte
comparison is pending in `ntt-root-cache-pbs-babybear.log`; no PBS timing or
performance-gate claim follows from the setup change.

The frozen version-two native matrix has additionally completed Goldilocks
ordinary fragmented PipFRI (36 proofs total), with exit/log and control
identities audited. Goldilocks virtual remains running. The older fresh-21
matrix is still active on BabyBear ordinary fragmented proofs.

The root-only setup cache now also has complete before/after proof evidence.
BabyBear dictionary and Goldilocks direct PolyFRIM each completed four decoded
NAND proofs with the new setup path. All eight structured records, including
proof hashes/sizes, profile descriptors, trusted setups, statements and native
keys, equal the saved pre-cache records exactly. Public verification and
altered-output rejection pass. Summaries accompany
`ntt-root-cache-pbs-{babybear,goldilocks}.log`. This is toy wire-compatibility
evidence for the setup optimization; no native proving-time gain or whole
security qualification is inferred.

The remaining parent-phase audit identified two packed ZeroCheck blocks that
were still split across calls: the k independent equality points, and the
mixing matrix followed by first-row challenges. The implemented interactive
bound cannot simply be assigned to an arbitrary later separate phase. Trusted
descriptor version four now groups these blocks, for both single and batched
ZeroCheck, while inheriting atomic NTT rows and joint projections. Versions
one/two/three retain their existing calls, suites and constructors. The new
factory/CLI is `new_atomic_zerocheck` / `--atomic-zerocheck`; schedule flags are
mutually exclusive and the diagnostic decoder supports the fourth suite.

Three focused Rust tests pass, including exact challenge-vector and transcript
tail references across all four schedules and both fields. Sixteen focused
Python tests pass, including small-field examples distinguishing a full atomic
block from a conditioned separate phase. The new phase-bound helper requires
explicit schedule four. The accompanying fixed-table ZeroCheck argument
derives equality, joint-mixing/row and remaining-round transition terms; it
does not establish source coupling, whole-parent knowledge or attacker work.
Evidence: `classical-atomic-zerocheck-tests.log` and
`classical-atomic-zerocheck-state-tests.log`.

Version four passes the complete toy suite: 40 decoded NAND proofs and 40
profile-tamper rejections across both fields and all five variants. Its
release fresh-binding audit passes all 180 distinct cases (ten controls,
170 false-relation rejections). Both legacy frozen-wire fixtures still pass.
Logs/summaries use the `classical-atomic-zerocheck-` prefix. Both examples also
type-check with the new flag (`classical-atomic-zerocheck-examples-check.log`).

The frozen version-two native matrix has now completed all 40 proofs across
ten field/backend groups. Terminal statuses, binary/log fingerprints and
control identities are audited in `atomic-complete-native-summary.json`.
The older version-one fresh-21 matrix has completed BabyBear ordinary
fragmented PipFRI too (84 completed proofs across its first four backends);
its 21-case control comparison is recorded, and BabyBear virtual is active.

A release version-four runner is built and frozen with source/binary
fingerprints in `zerocheck-manifest.json`. Its native matrix is active in
`zerocheck-matrix/`, requiring independently decoded descriptor headers.
BabyBear Brakedown has passed all four native NAND proofs, with version-four
header and unchanged FHE/key/statement control identities audited. The full
matrix is not yet complete. Version-four source-width and helper-basis
feasibility inventories are also active; their final coverage is pending.
All of these remain correctness/feasibility evidence, without security-derived
queries, matched timing/size gates or default promotion.

Both version-four feasibility inventories have now terminated successfully.
The default grid has 624 candidates / 585 admitted; helper-basis has 144 / 135.
Geometry/admission match version three while IDs are disjoint between schedule
versions. The 18 overlapping helper layouts give 702 distinct feasible
version-four profiles. Status/log fingerprints and full record comparisons
are checked in the per-grid summaries and
`classical-atomic-zerocheck-grids-complete-summary.json`.

The parent semantic audit now spells out the integer canonical-decomposition
implication by telescoping borrow transitions, and the deterministic native
blind-rotation/key-switch induction under truthful decoded-table constraints.
New checks use the production transition tables and native polynomial digit
extraction for both fields at radix sizes 5/8, including negative values/zero
and field-congruent noncanonical aliases. Both tests pass in
`classical-canonical-native-contract-tests.log`.

The inline first-query interface now recovers proposed prior field coins from
already queried consumed-byte fingerprint preimages, rather than assuming
phase queries occurred in protocol order. A later producer cannot repair an
earlier query's snapshot; late hits and output collisions remain separately
charged ideal-XOF events. Two receipt tests pass, including the existing
independent sampler/receipt comparison and the new recovery/snapshot model
(`classical-first-query-receipt-tests.log`). The deliberate late-hit fixture
tests interpretation, not the probability of such a hit. No production
transcript encoding changed in this addition.

Source fingerprints for these local arguments are recorded in
`classical-parent-native-contract-audit.json`. A complete admissible-prefix
interpreter, the full source/virtual-word coupling, all-trials resource/work
envelopes and knowledge statement remain unresolved. These local implications
and tests are not whole-security qualification.

Version-four native BabyBear direct/dictionary PolyFRIM and ordinary
fragmented PipFRI have also passed all four NAND cases each, bringing the
matrix to 16 completed proofs. Their version-four headers, terminal exits,
log fingerprints and unchanged FHE/key/statement control identities are
audited. BabyBear virtual and the remaining Goldilocks groups are pending.

`polyfrim_opening_terms.shared_stage_schedule` now derives opening ceilings
from the actual shared verifier's stage loops, independently of owner-lifetime
allowances. It records per-stage call/query counts for NTTs, products, linear
decomposition, used lookup slots, accumulator carry/endpoint maps, monomial
checks and final extraction. Accepted-path call ceilings are [86,8,64,7] for
default BabyBear and [150,16,112,13] for default Goldilocks; ordered queries
are bounded by [255,8,176,7] and [279,16,196,13]. Source aliasing can reduce
these numbers, but honest zero-root aliasing is not assumed in the ceiling.

The report tool exposes `--stage-ceiling`, mutually exclusive with the older
per-owner option. It checks observations against the new limits and uses
separate call/query ceilings for rolling and packed internal-root counts.
Nine focused tests pass (`classical-shared-stage-schedule-tests.log`). The
source audit and checked native observations are in
`classical-shared-stage-schedule-audit.json`. A hypothetical query-1024 report
runs successfully in `classical-shared-stage-opening-terms.json`; it remains
a conditional opening subtotal, with whole-security and promotion disabled.
No query profile was selected from that partial result. Complete hash/XOF
resource and attacker-work envelopes remain separate obligations.

The lookup resource analysis now handles the production reciprocal retry
loop with an analysis-only first-rejection stop. A fixed compressed M-row
table excludes at most M+1 extension values; each fresh reciprocal draw
therefore contributes at most (M+1)/q. Outside that event, each pair uses
exactly two scalar phases. `lookup_first_retry_bound` and four lookup-state
tests cover the arithmetic, duplicate entries and zero. Production behavior
is unchanged. All-trials charging and admissible-prefix interpretation remain
required; this is not a complete transcript or sampler-byte resource bound.

`classical_work_cost.all_trials_envelope` now supplies the arithmetic for
charging every verifier submission: if adversarial phase requests and
submissions are each at most work T, a maximum adversarial phase error e
and per-submission phase caps (v_i,e_i) give linear coefficient
e + sum(v_i*e_i). A resource cap V per submission and honest offset H give
(1+V)T+H, provided adversarial requests/declarations of that resource are
also charged at least once each. No independence is assumed. Unbounded
reroll loops cannot be supplied as finite caps without a separate argument.
Six work-cost tests pass, including exhaustive small-budget comparisons
with varying submission counts. This is conditional arithmetic; actual
verifier phase/resource caps and the complete reduction remain unfinished.

The version-four native matrix has now completed all BabyBear variants and
Goldilocks Brakedown (24 proofs). Newly completed virtual/Brakedown groups
have audited version-four headers, terminal/log fingerprints and control
FHE/key/statement identities. Goldilocks direct PolyFRIM is active; the older
fresh-21 BabyBear virtual job also remains live.

Goldilocks direct PolyFRIM has now completed and its four decoded native
proofs have been independently audited against the frozen version-four
binary fingerprint, descriptor, terminal exit, log hash and Brakedown control
FHE/key/statement identities. This brings the version-four native matrix to
28 audited proofs. Goldilocks dictionary is running; fragmented and virtual
groups remain pending. These concurrent correctness runs supply no timing
or performance-gate evidence.

The conditional PolyFRIM opening evaluator now supports blowups 2, 4 and 8
and separate query counts for the four roles. The uniform-query option remains
available and mutually exclusive with role counts; the default blowup-two
calculation is preserved. Geometry-dependent field terms and the rolling tail
use the selected expansion. Ten focused tests pass, including expansion
tradeoffs, invalid geometry inputs and unchanged default results.

The checked report `classical-role-blowup-opening-terms.json` evaluates both
fields at hypothetical role counts [1024,1056,1088,1120] and blowup four.
Each role retains its own count, the uniform summary is null, and both override
flags are explicit. Original observation fingerprints are revalidated; no
proof or trusted profile is modified. Whole-security and promotion flags
remain false. These counts are evaluation inputs, not selected secure parameters.

Documented scalar virtual-source coupling conditional on a single complete
packed source word supplied by availability. The gamma-weighted full-domain
word is fixed before rolling challenges; the callback authenticates both
coordinates at every sample. The virtual identifier is not a Merkle root.
The malicious virtual-pair test now requires rejection specifically at the
fragment-combination check with authentic source paths. Both field tests pass
(`classical-virtual-source-coupling-tests.log`). Global availability, interpreted
first-query histories and matrix-bridge extraction remain separate obligations.

The virtual matrix adapter integration tests now reject reuse of a decoded
proof after reordering valid claims together with their outputs, and after
reversing noncommuting matrix sequences with freshly recomputed true outputs.
This checks ordered-packet binding beyond false-value mutations. Both fields
pass across the existing constant and multi-variable geometries and batch
sizes 1/4/16 (`classical-virtual-ordered-binding-tests.log`). No production
encoding or verifier behavior changed in this test extension.

The resource worksheet now exposes ideal-XOF link terms separately from
Merkle hashing: M(M-1)/2^(h+1) for fingerprint collisions plus M*B/2^h
for hits on previously proposed windows. `xof_work_coefficients` expands
caller-proved affine M/B caps into nonnegative constant/linear/quadratic
coefficients consumable by the existing work-cost evaluator. Eleven hash/XOF
tests pass; exhaustive small-resource checks verify both domination and the
exact slack from replacing M(M-1) by M^2. The caps must cover receipt producers,
all trials and verifier queries. No candidate-input length or window cap is
inferred from a final proof, and whole-security qualification remains pending.

The work evaluator now composes explicit phase, Merkle and XOF all-trials
polynomials before minimizing work per success (`--components`). All three
families and exact constant/linear/quadratic terms are required; component
provenance is retained and protocol/security/performance qualification stays
disabled. Eight work-cost tests pass, including direct equivalence to the
summed polynomial and a case where adding oracle errors makes an otherwise
exact 128-bit phase target fail. The synthetic report
`classical-composed-work-regression.json` exercises this behavior; its inputs
are not claimed as native profile resource bounds. Actual complete phase
coverage and proved resource caps remain unfinished.

The trusted profile grid now accepts mutually exclusive `--queries Q` and
`--role-queries A,B,C,D`, with positive counts passed to all four real parameter
constructors. Default counts remain one. Nonuniform output uses null for the
uniform count and emits the four role counts. A version-four helper-basis
run at [2,3,4,5] emits 144 rows: 135 admitted and nine rejected, exactly matching
the previous geometry/admission results; every admitted profile ID changes.
Four invalid CLI cases reject before emitting inventory rows. Typecheck and
run/audit evidence are `classical-grid-role-queries-{check,run}.log` and
`classical-grid-role-queries-summary.json`. The counts exercise configuration;
they are not security-derived or promoted defaults.

The corresponding full-width version-four grid at [2,3,4,5] also completes:
624 rows across all five backends, with 585 admitted and 39 rejected. Every
geometry/admission result matches the prior query-one grid and every admitted
profile ID differs. The audited log and summary are
`classical-grid-role-queries-full.log` and
`classical-grid-role-queries-full-summary.json`. This includes ordinary and
virtual fragmented profiles; it supplies construction evidence, not PBS
correctness, query security or performance eligibility. Both existing native
matrix processes were confirmed live and left running without restart.

The first-query transcript model now includes a strict borrowed frame decoder
for the production kind/LE64-label/LE64-message format. A test checks exact
SHAKE input equivalence to production framing, every truncation boundary,
unknown frame kinds, oversized lengths and trailing incomplete bytes. Both
frame/receipt model tests pass (`classical-prefix-frame-tests.log`). This code
is test-only: production transcript bytes and verifier behavior are unchanged.
Structural framing does not establish stage-label admissibility or linked
child replay; the complete verifier-prefix interpreter remains unfinished.

The frame model is now connected to field-receipt interpretation: completed
field requests must have exact 24-byte descriptors and immediately matching
80-byte receipts with the same label. Recovery uses only the supplied frozen
producer database; a terminal current-phase request is left uninterpreted.
Both supported primes pass snapshot tests and rejection cases for orphan
receipts, label changes, malformed sizes and intervening frames. Three model
tests pass (`classical-framed-receipt-tests.log`). This is test-only field-phase
interpretation; byte phases, typed basis/stage admissibility, linked children
and whole-verifier reduction remain unfinished.

`fragmented_opening_terms.shared_terms` now combines all four roles using
the shared-stage PCS call ceilings, retaining each role's geometry and query
count. Each call contributes one bridge, without multiplying its compression
error by ordered claim count. Reference and virtual sampling modes remain
distinct. Six fragmented-budget tests pass; four hypothetical reports using
the two native field geometries are recorded in
`classical-shared-fragmented-opening-terms.json`. These are accepted-path
opening subtotals, not FS all-trials coefficients or security-derived profiles;
parent algebra, availability/links, work caps and extraction remain excluded.

The prefix model now interprets mixed byte/field phases. Inline byte receipts
must immediately match an eight-byte count request, label and output length;
field receipts retain frozen-producer recovery. Orphan receipts and crossed
receipt kinds reject. Current terminal requests remain uninterpreted, and
inline bytes are explicitly proposed coins rather than proof of a prior
oracle query. Three focused tests pass (`classical-mixed-receipt-tests.log`).
Production framing and verifier execution are unchanged; typed stage/basis
admissibility and child-link replay remain outstanding.

Goldilocks dictionary now contributes four more independently audited native
version-four proofs, bringing the matrix to 32/40. Frozen binary, descriptor,
terminal/log fingerprints and public FHE/key/statement controls all match.
Goldilocks ordinary fragmented is running; virtual remains pending. These
correctness results do not establish a security or timing gate.

Classical extension-challenge sampling now caches the complete immutable
basis-table encoding by `(base field, extension field)` Rust type. Every phase
still absorbs the same full bytes, while warm calls avoid rebuilding the
D-squared products and D-cubed coefficient table. Concurrent cold requests
compute outside the lock and reuse one retained entry. Independent binomial
references now cover all eight supported types at counts 0/1/17 and compare
both sampled values and transcript tails. Concurrent type isolation/reuse
also passes. All 27 helper tests and both virtual matrix adapter integration
tests pass (`classical-basis-cache-{helper,adapter}-tests.log`). No proof
format/profile change or native performance-gate claim is introduced.

Extension coefficient conversion now uses `E::from_base_fn` directly instead
of allocating a temporary `Vec<B>` for every sampled E element. Coefficient
order and field construction remain exact under the trait contract. All 27
helper tests pass, including independent values/transcript references for all
eight supported extension types (`classical-direct-coefficient-helper-tests.log`).
This removes allocations without a native timing claim.

The older version-one fresh-21 matrix has now completed and audited all five
BabyBear backends plus Goldilocks Brakedown: 126/210 decoded native proofs.
The two newly completed groups have verified frozen binary, terminal status
and log fingerprints. BabyBear virtual matches its Brakedown control's full
FHE/key/statement identities; Goldilocks Brakedown establishes that field's
fresh-21 control. Goldilocks direct PolyFRIM is live. This is separate from
the version-four 32/40 matrix and provides no current-profile security or
performance eligibility.

The classical rejection sampler now converts each accepted integer directly
into the requested output type while collecting. Prime challenges allocate
their field vector directly; extension challenges retain base coefficients
instead of an intermediate u128 vector before indexed extension construction.
The candidate stream, count framing, rejection handling and consumed-byte
receipt are unchanged. All 27 helper tests pass, including independent prime
and all-eight-extension value/transcript references
(`classical-typed-sampler-helper-tests.log`). This reduces intermediate storage;
native time/RSS and the full performance gate have not been established.

The test-only prefix interpreter now validates typed field requests against
the trusted base modulus and the exact preceding prime/extension markers.
Extension phases require the complete trusted basis encoding and coefficient
counts divisible by the trusted degree, including terminal candidate requests.
All eight supported field types pass tests rejecting changed basis bytes,
changed modulus, wrong phase kind and incomplete extension coefficient counts.
Four prefix/receipt tests pass (`classical-typed-prefix-tests.log`). This adds
typed phase interpretation, not application-stage admissibility or child-link
replay, and introduces no production verifier or transcript change.

The prefix model now recovers a child's parent-seed producer from the frozen
first-query XOF database. It requires the exact child initialization, matching
trusted profile, child label/context and the parent's fork frame immediately
before its 64-byte seed request. Later producer insertion cannot repair the
earlier snapshot; changed profile/label/context rejects. Five focused prefix
tests and all 29 helper tests pass (`classical-child-prefix-tests.log` and
`classical-child-prefix-helper-tests.log`). This establishes the modeled seed
link interface only, conditional on the oracle database/no-collision premise;
it does not validate parent stages or completed child-return links.

The model now also resolves a parent's child-finish digest through a known
finish producer, checks its terminal 64-byte finish request, recovers its seed
producer, and compares the exact parent query prefix and inline seed receipt.
Return labels must match the fork. Six prefix tests and all 30 helper tests
pass (`classical-child-finish-prefix-tests.log` and
`classical-child-finish-helper-tests.log`), including foreign-parent, changed
seed/label, absent producer and unchanged first-query snapshot cases. This is
test-only link interpretation under the oracle/no-late-hit premises. Recursive
first-query chronology, application-stage admissibility and the complete
bad-state/work/extraction composition remain outstanding.

The query-history model now records each distinct input once, reuses its
output on repeats and automatically reconstructs the database strictly before
that input's first query. Structural dependency replay resolves seed/finish
links recursively using each producer's own snapshot, with successful-input
memoization. Dependencies must be earlier queries, so the replay is acyclic.
Six prefix tests pass (`classical-recursive-prefix-tests.log`), including a
complete parent/child return and an attempted repair by querying the finish
producer later and repeating the parent candidate. The original snapshot
still rejects. This remains a test-only structural replay under no-collision
premises; complete trusted-profile/type/stage admissibility and whole-proof
bad-state/work/knowledge composition are not established.

Documented an explicit application-knowledge lemma for the original public
evaluation-key contract. Given the same public key used by trusted setup, an
extractor can run the existing public evaluator on the statement's inputs
and return its native trace when the output matches. Accepted extraction
failure is contained in the incorrect-native-output event, so this lemma
adds no error beyond the still-unproved whole soundness bound. It does not
extract from key-root-only VerifierSetup or recover tables matching proof
commitments. Both public-evaluation-key regression tests pass, covering all
four NAND cases per field with the secret-key scope ended before the worker
runs (`classical-public-trace-extraction-tests.log`). Generic PCS knowledge,
complete soundness/FS/work composition and qualification remain outstanding.

Audited the actual version-twelve outer prefix and static shared-stage
dispatch. The outer tuple binds setup, 17 PCS contexts, normalized statement,
primary root vectors and endpoint before randomized stages; trusted dimension
and child-count checks precede the first such stage. Stage order is fixed by
the trusted configuration and ClassicalShared type. Borrow/helper, monomial
auxiliary and final-stage roots are explicitly left to their child bindings.
Source fingerprints and the bound-field/stage inventory are recorded in
`classical-outer-prefix-stage-audit.json`. This is an outer-boundary audit,
not a completed admissible-prefix interpreter or whole security certificate.

The outer binding now has an executable test-only decoder. It compares the
trusted version/degree/setup/context/statement prefix byte-for-byte, then
decodes primary roots and endpoint using trusted vector counts, canonical
encodings and full consumption. Oversized candidate counts reject before
allocation; trusted setup types remain serialize-only. Both field tests
recover the payload and reproduce the production `bind_inner` transcript
continuation, and reject wrong version, wrong root counts and trailing bytes
(`classical-outer-prefix-decoder-retry-tests.log`). The initial build attempt
used an unavailable raw append API; the corrected reference uses an explicitly
checked raw-tuple serializer through the existing typed transcript interface.

The frozen version-four native matrix has completed all 40 proofs across ten
field/backend groups. Every terminal status, frozen binary/log fingerprint,
version-four descriptor and FHE/key/statement control identity was independently
rechecked (`zerocheck-complete-native-summary.json`); its original live handle
returned exit zero. The corresponding fresh-21 matrix is now running with
that same frozen binary and version-four headers under handle 95581, starting
with confirmed live BabyBear Brakedown PID 2669772. The older fresh-21 matrix
continues separately. These are correctness runs, not security/performance
qualification or tests of later sampler implementation optimizations.

Audited the shared decomposition/lookup prefix directly through its verifier
calls. The d+1 borrow roots precede reconstruction randomness; canonical
requests, source registry and multiplicities precede the lookup child seed.
Reciprocal helper roots intentionally follow compression/reciprocal challenges
and precede equality points. Documented separate source/count and helper-
identity bad-state boundaries so the reduction does not incorrectly freeze
helpers before their defining challenges. Six source fingerprints and the
ordered boundaries are in `classical-decomposition-prefix-stage-audit.json`.
No protocol change or completed child-stage interpreter is claimed.

Completed the parent-stage binding inventory for accumulator, monomial and
final key-switch/extraction verification. Source, endpoint and auxiliary-root
bindings precede their relevant challenges. The audit also identifies that
accumulator response dimension checks follow lane sampling, so rejected
submissions must contribute verifier phases/resources. Four source fingerprints
and exact stage ordering are recorded in
`classical-remaining-parent-prefix-stage-audit.json`. This completes the source
inventory only; component prefix grammars and complete conditional bad-state,
all-trials resource and security-derived parameter composition remain pending.

`classical_parent_phases.packed_stages` now inventories the native parent
NTT and degree-two ZeroCheck stages with explicit phase multiplicities and
conditional errors. It requires schedule four and an approved field/width;
older schedules reject. Native phase totals for BabyBear widths 8/16 are
208/185 and Goldilocks widths 4/8 are 357/320. The common NTT compression
phase uses the fixed first-nonzero residual bound without assuming independent
response polynomials. Three focused tests and all 24 classical tooling tests
pass. Four reports and six source fingerprints are in
`classical-packed-parent-phase-inventory.json`. Linear/accumulator/known-input,
lookup, PCS and complete FS/resource terms remain explicitly excluded; no
query count or security-qualified profile is selected.

The parent inventory now includes fixed-residual folds for two main linear
reconstructions, final linear reconstruction, accumulator identities and the
known final input. Documented first-false-equality/first-vanishing-fold bounds
and the accumulator's fixed shift/replication/sparse-correction interpretation,
without conditioning on future authentication. The per-phase term is
((2k-1)/p)^k with no equality-count multiplier. Native phase totals become
278/250 for BabyBear widths 8/16 and 432/390 for Goldilocks widths 4/8.
Four focused tests and all 25 classical tooling tests pass; the existing
explicit noncommuting accumulator-map test passes for both fields.
Reports are in `classical-packed-parent-linear-phase-inventory.json` and
`classical-accumulator-residual-map-tests.log`. Lookup, PCS, availability and
complete admissible-prefix/FS/resource composition remain excluded.

The parent inventory now includes native canonical lookup algebra. Main/final
transition tables have 512/64 rows and three columns; full logical domains
give degree-three scalar identity equations. Lookup phase totals are 98 for
BabyBear and 140 for Goldilocks: compression, reciprocal and equality phases
per request, then only one shared scalar sumcheck round sequence per
decomposition. Reciprocal error separately records the raw rational escape
and first-retry stopping event; no conditional accepted-r denominator is used.
The per-round scalar error tracks a first false separate equation and assumes
no independence across equations. `--extension-degree` includes these terms
in the conditional parent subtotal. All 28 classical tooling tests pass.
Fifteen compatible extension/width reports and five source fingerprints are
in `classical-parent-lookup-phase-inventory.json`. PCS, complete prefix/FS,
oracle-resource and whole soundness/knowledge composition remain excluded;
byte/zero-count identity/link phases are not omitted from the outstanding
oracle-resource accounting merely because they have no algebraic error term.

The compact verifier now checks trusted packet geometry before cloning and
expanding dictionary indices. The preflight bounds consistency/projection
sample counts, member/layer counts, lane-value widths, Merkle path lengths and
rolling roots/queries; virtual-original paths must be empty. It also rejects
dictionary lengths above the total possible hash references. Saturating size
arithmetic preserves oversized trusted-parameter behavior without introducing
a new query-count allowance. Semantic/authentication checks still run in the
full verifier; accepted encodings and transcript bytes are unchanged.

All four compact tests pass (`classical-compact-preflight-blowup-tests.log`),
covering 72 decoded classical packets across both fields, constants and
multi-variable geometries, blowups 2/4/8 and batch sizes 1/4/16, plus existing
legacy roundtrips. New malformed-shape/dictionary cases require rejection
at preflight before index expansion and without transcript mutation. This
bounds that expansion by trusted packet shape; it does not complete the
global hash/XOF/work envelope or security/performance qualification.

`authentication_resources` now counts direct/dictionary PolyFRIM verification
hash outputs from trusted sample/member/layer geometry. It separates the two
packed authentication traversals, rolling derived Merkle checks and the extra
context hash recomputed for each rolling leaf. Dictionary reference ceilings
exclude those recomputed contexts and include actual stored internal roots;
virtual identifiers remain separate. Repeated samples/paths are conservatively
counted without deduplicating draws. Twelve opening-tool tests pass, including
explicit path traversal counts across all three blowups. The native observation
report `classical-polyfrim-authentication-resource-report.json` integrates role
ceilings and hypothetical counts/expansion while retaining disabled security
and promotion flags. Higher-level context/identifier hashes, preprocessing,
XOF and all-trials work envelopes remain excluded.

Rolling-FRI now reuses its fixed parameter context: once per Merkle tree in
proving and from the already absorbed binding in verification. The original
leaf tuple/wire/profile is preserved. An independent original-tuple reference
checks identical roots and every path for both default extension fields,
both leaf roles and blowups 2/4/8; a counted hash wrapper verifies tree
construction uses one context plus leaf/internal hashes. All eight rolling
tests and all four compact tests pass
(`classical-rolling-context-cache-reference-tests.log`,
`classical-rolling-context-compact-tests.log`).

The resource evaluator now defaults to this reuse and retains an explicit
uncached model. Twelve opening-tool tests pass. The checked cached report
`classical-polyfrim-cached-authentication-resource-report.json` removes exactly
the previously charged repeated leaf-context outputs while leaving opening
error terms unchanged. Higher-level binding contexts are still excluded from
that authentication subtotal. This is an implementation/hash-count improvement,
not measured native speedup or completion of the performance/security gates.

`classical_candidate_terms` now composes the conditional parent algebra and
four-role PCS subtotals directly from a caller-selected canonical descriptor.
It verifies schedule-four/native role geometry, compatible widths, query
counts, fragment caps and backend-specific fields, and recomputes the exact
profile ID. Direct/dictionary PolyFRIM conservatively charge ordered-query
ceilings; ordinary/virtual fragmented profiles charge call ceilings with
their separate scalar bounds. Eight completed native descriptors reproduce
their recorded identities (`classical-candidate-{field}-{backend}.json`).
All 31 classical tooling tests pass, including rejection of old schedules and
non-native geometry. Brakedown opening terms are explicitly not integrated
in this evaluator. It emits only a conditional ideal-game union; complete
source/prefix/FS, oracle/work, knowledge and native performance obligations
remain listed, and security/promotion/query-selection flags stay false.

Brakedown is now included in that conditional descriptor composition. Its
opening evaluator follows the actual block-RS constructor's power-of-two
coefficient padding and minimum 32-block domain, checks the native NTT order,
and uses the conditional available-word/subspace and padding argument from
`docs/block-rs.md`. One shared test/column phase pair covers a batch by selecting
its first false claim; the tool does not multiply this error by claim count.
Q with-replacement draws are retained in the tail even when transport caps
distinct columns at the domain length. Three Brakedown tests and all 31
classical tooling tests pass. Both actual native Brakedown descriptors match
their profile identities (`classical-candidate-{field}-brakedown.json`). The
conditional evaluator now covers all five variants; full source/prefix/FS,
hash/XOF/work, knowledge and matched native performance obligations remain.

The Rust profile grid now supports optional `--emit-descriptors`, emitting the
exact bincode profile after all four factories succeed and null for rejected
candidates. Default output remains unchanged. Full and helper-basis grids at
role counts [2,3,4,5] produce 585 and 135 admitted descriptors respectively,
covering 702 unique factory-admitted profiles after overlap. Every descriptor
decodes, matches its metadata/profile ID and passes the combined conditional
evaluator. Prior geometry/admission/ID records match; all 144 default helper
records remain byte-for-byte identical. Duplicate/unknown emit options reject
before output. Evidence is in `classical-grid-descriptor-{helper,full}-run.log`
and the corresponding summary JSON files. These are constructed candidates,
not selected secure parameters or completed native proof/performance gates.

Documented the conditional composition behind the candidate subtotal: one
fixed source-table assignment per root/trusted context, unique promised
decoding (projected to the base field where needed) or a fixed zero fallback.
An out-of-promise source remains a false PCS task for every claim; it is not
assumed to open as zero. With no accepted false PCS task, the native contract
and universal auxiliary-task reductions leave a first false parent task,
bounded by its conditional phase union. Candidate reports now name that
source contract and explicitly keep actual hash/XOF coupling false. Complete
noninteractive/source-prefix/resource composition is still required.

The version-four fresh-21 matrix now has 42 audited proofs: BabyBear Brakedown
and direct PolyFRIM. Both groups have matching frozen binary, version-four
headers, terminal/log fingerprints and all FHE/key/statement identities against
the original fresh-21 Brakedown control. BabyBear dictionary and the older
Goldilocks PolyFRIM job were confirmed live and left running without restart.

Fragmented authentication resources are now derived separately for ordinary
and virtual openings: rolling paths, packed source paths, the ordinary public
ladder, nested packed-source contexts and standalone ladder contexts. Genuine
internal roots and virtual identifiers remain distinct. A counted SHA-512 Rust
test matches authentication plus binding metadata across 24 verifications
(both fields, blowups 2/4/8, both scalar bases and both modes), recorded in
`classical-fragmented-authentication-hash-retry-tests.log`. Eight fragmented
tool tests and all 31 classical tooling tests pass. The candidate evaluator
now exposes role/total authentication bounds for all five variants; ten native
descriptor reports and source hashes are in
`classical-native-authentication-resource-inventory.json`. These use current
source formulas at frozen descriptor geometries, not measured old-run counts.
Higher-level hashes, preprocessing, XOF and full all-trials work remain excluded.

Canonical field sampling now has an analysis-only resource envelope. For n
coefficients and per-candidate rejection probability r, stopping after more
than R candidates for any coefficient costs at most n*r^R; outside that event
raw bytes are bounded by n*R*ceil(bit_length(p-1)/8). Documented independence
of accepted values from rejection counts, so conditioning on this stop does
not bias accepted values. Production retains its unbounded rejection loop.
Typed parent, Brakedown, direct-projection and fragmented-bridge request
shapes supply a conservative per-phase coefficient ceiling. The evaluator
reports both raw-stream and receipt-producer-input byte bounds at R=512.
All 34 classical tooling tests pass, including exhaustive small-stream checks.
Ten native reports and six source fingerprints are in
`classical-native-sampler-resource-inventory.json`. Total phase counts, byte
challenge outputs, link/identity producers and complete first-query/work
composition remain outstanding; no global resource bound is claimed.

Audited the separate Brakedown column-byte rejection loop. Its existing
u64::MAX cutoff rejects a whole domain-sized block for power-of-two domains;
it is not the single-block masked sampler used by the other adapters.
Added an analysis-only R=8 retry envelope with exact cutoff/rejection error,
byte-query and output-byte ceilings, charging every independent draw across
all role call ceilings before transported-column deduplication. Production
and version-four transcript bytes are unchanged. Exhaustive three-bit streams
check stopping probability and conditional uniformity for five domains;
all 36 classical tooling tests pass. Complete transcript and all-trials
resource coupling remains unfinished.

Added PCS-only schedule-four XOF invocation accounting to candidate reports:
two producers per field phase (including empty typed identities), detached
child seed/finish and both checkpoints, plus rolling/member/column index
queries. Ordinary fragmented mode has one more index phase per opening than
virtual mode; dictionary transport leaves all transcript counts unchanged.
Byte output lengths are separated from field rejection streams. All 37
classical tooling tests pass, including both-field accounting invariants.
Parent stages, lookup children, input/frame lengths and actual first-query /
all-trials composition are still excluded; global resource qualification stays
false. Native fresh-21 BabyBear version-four dictionary and older Goldilocks
dictionary processes were confirmed live and left running.

Extended XOF invocation counts to the parent stage inventory and all three
shared lookup children. Included the otherwise absent empty identity phases,
seed/finish queries and both lineage checkpoints. Verified that the shared
scalar sumcheck has one common challenge per round and no extra batch-mixing
challenge. Reports explicitly stop at the first rejected lookup reciprocal,
as already charged in lookup terms, and at the Brakedown byte retry envelope.
All 38 classical tooling tests pass across both native fields and all five
backends. Input/frame/stream lengths and actual first-query/all-trials
composition remain outstanding; global resource qualification remains false.

Combined verifier invocation counts with canonical-sampler and Brakedown
column retry envelopes. Candidate reports now separate field raw output,
receipt fingerprint output and producer inputs, byte-challenge output and
checkpoint output. Additional sampler stopping error charges every field
phase and all Brakedown role calls, while lookup reciprocal stopping remains
in the existing parent lookup union. All 39 classical tooling tests pass;
increasing the field candidate limit tightens its error while doubling its
raw byte ceiling without changing query counts. This is a stopped ideal-game
output bound, not an input-length or full adversarial/all-trials resource
certificate. Production retry behavior is unchanged.

The original schedule-one fresh-21 matrix now has 147/210 independently
audited proofs. Goldilocks direct PolyFRIM finished its 21-proof group with
terminal exit zero; verified its log fingerprint, frozen runner/manifest
fingerprints, decoded public verification and original FHE/key/statement
identities against Goldilocks Brakedown fresh-21. Evidence is in
`optimized-fresh21/goldilocks-polyfrim-control-compatibility.json` under the
native validation artifact directory. The original Goldilocks dictionary
and version-four BabyBear dictionary processes were confirmed live. These
are frozen-runner correctness results, not current-source performance or
security qualification. Transcript input/frame byte bounds remain unfinished.

Extension challenge construction now reuses a per-element coefficient buffer
instead of collecting every base coefficient before constructing extension
values. All eight selected degrees fit in an eight-element stack buffer;
larger generic degrees retain a reusable heap fallback. Coefficients are
sampled in ascending basis order before calling the indexed constructor,
preserving generic constructor order semantics. The common phase builder
retains descriptors, rejected-byte receipts and transcript framing. The
independent eight-field reference now also covers 257 extension values.
All 30 helper tests pass (`classical-streamed-extension-helper-tests.log`).
Both virtual fragmented adapter tests pass, recorded in
`classical-streamed-extension-adapter-tests.log`. Native runtime/RSS improvement
has not been measured, and running frozen validation binaries do not contain
this change.

Added additional PCS frame/input-increment accounting, separate from XOF
invocations. Audited statement/response bindings, joint/member consistency
metadata, scalar sumcheck info/rounds, child initialization, root/terminal
messages and ephemeral checkpoints. Counts include the field-kind/basis and
index-domain frames. A loose 64-bit successful-slice bound supplies bytes per
frame without adding production limits. Reports explicitly exclude registry
and parent frames and pre-existing parent prefixes. All 40 classical tooling
tests pass, including unchanged dictionary framing and three fewer index
frames per virtual opening. This is not yet a full prefix/input or all-trials
resource certificate.

Added the parent frame inventory: typed field frames, all three lookup child
links/checkpoints, constructor/schedule/outer binding, NTT folded responses,
ZeroCheck and enclosing task metadata, shared comparison and registry frames.
Combined it with PCS increments to bound any stopped verifier framed prefix,
then included raw receipt producer inputs in a maximum XOF input bound and
overlapping 64-byte window ceiling. Counts remain descriptor-bound and expose
each metadata contribution. All 41 classical tooling tests pass. Adversarial
candidate-prefix determinacy, source coupling and all-trials/hash/work
composition remain unfinished; no complete security claim is made.

Added conditional XOF all-trials cap derivation from the finite eligible input
length and verifier producer ceiling. With charged adversarial queries and
verifier submissions each at most T, M <= (1+V)*T+h and predictable windows
B <= max(0,L-63)*M. The native wrapper requires an explicit honest offset h;
all oracle producers count even if their inputs are ineligible for registering
link windows. Eligibility must still be proved to preserve every relevant
producer. Twelve hash-budget tests and 42 classical tooling tests pass,
including exhaustive small all-trials envelopes and monotone honest offsets.
The resulting polynomial is XOF-only and conditional: actual prefix/source
coupling, Merkle/algebraic/sampler terms and complete work composition remain.

Added a bounded-history variant of the structural first-query recovery model.
It filters producer inputs while retaining original global query indices and
per-producer first-query snapshots. Recovery survives an oversized unrelated
earlier producer and a sufficient bound, and rejects an insufficient bound.
Documented why filtering preserves bounded actual traces outside output
collisions and retains every relevant late-link target window. This is a
length-filter lemma, not arbitrary stage/source admissibility. Six focused
recovery tests pass (`classical-bounded-prefix-recovery-tests.log`).

Version-four BabyBear dictionary fresh-21 finished with exit zero. Independently
verified descriptor version four, frozen runner/manifest and log fingerprints,
all 21 decoded correctness records and FHE/key/statement identities against
the original BabyBear Brakedown fresh-21 control. Its compatibility artifact
is `zerocheck-fresh21/babybear-dictionary-control-compatibility.json`; this
matrix now has 63/210 audited proofs. Version-four BabyBear fragmented and
older Goldilocks dictionary processes were confirmed live and left running.

Added standalone PCS binding-hash counts to candidate reports: one context
per Brakedown call; R+2 direct PolyFRIM and R+3 dictionary PolyFRIM hashes;
four ordinary and seven virtual fragmented binding hashes. These are in
addition to the existing authentication formulas. New counted SHA-512 Rust
integration coverage checks 90 actual verifications across both native fields,
three blowups, three batch sizes and all five adapters. The first harness
compile required an associated-error Debug bound; after fixing it, all cases
pass (`classical-adapter-hash-resource-retry-tests.log`). All 43 classical
tooling tests pass. Parent parameter-context hashes, preprocessing and full
all-trials/source/security composition remain excluded.

Inventoried parent context hashes by stage/role, including both executions of
outer validation, original key checks, seventeen outer contexts, factor/NTT /
radix/lookup/registry/alias contexts, accumulator/monomial and final-key checks.
Role ceilings are [28*d+64, 2*d+7, 14*s+39, s+8]; dictionary contexts cost two
hash outputs and other selected contexts one. Two direct SHA-512 profile-ID
computations are also included. Candidate reports now expose the resulting
typed verifier invocation hash ceiling, still excluding honest preprocessing.
All 44 classical tooling tests pass. This parent formula is source-derived;
the existing counted Rust test covers standalone PCS verification only.

The same audit corrected framing contributions: include the constructor's
trusted-profile frame, and charge three statement/response frames per
Brakedown call to cover both single and batch bindings. Earlier frame/XOF-work
artifacts are historical snapshots of their recorded source hashes; revised
verifier input/hash inventory records these corrected inputs. Actual
first-query/source and all-trials/security composition remain unfinished.

Added a complete-certificate parent-context audit with a transparent PCS wrapper
that counts only parent context calls while delegating all adapter operations.
It covers both fields and all five variants using synthetic toy keys; its
explicit ignored test is `complete_classical_parent_context_counts_match_stage_inventory`.
The complete audit passed all ten synthetic-key certificates: the four parent
context counts exactly match the source-derived formulas for both fields and
all five variants. Evidence is in `classical-complete-parent-context-tests.log`
(one test, ten complete certificates, 120.51 seconds). This does not replace
native encrypted-profile validation or establish a security theorem.

Added joint filtered Merkle/XOF all-trials arithmetic: root windows from both
oracle families contribute affine declaration caps, including all verifier
submissions and explicit honest offsets. `candidate_oracle_work` binds the
polynomials to an exact descriptor and requires hash, XOF and root offsets.
Downscaled digest tests now derive window byte width from digest bits; native
512-bit inputs retain 64-byte windows. Thirteen hash-budget tests and all 45
classical tooling tests pass. Root-filter/source preservation and complete
algebraic/sampler/work/knowledge composition are still explicit obligations.

The first-query audit identified a schedule-four Brakedown gap: its Q column
draws are sequential eight-byte queries, so the interactive iid tail cannot
simply be treated as a single arbitrary-prefix fresh phase. No attack is
claimed; that coupling still needs a proof for old schedules. Added an opt-in
Rust schedule five instead: one domain-bound 8*Q byte request, uniform masked
draws with replacement, then transport-only deduplication. Its profile suite
and ID are distinct; versions one through four keep their original paths.
New flags inherit through detached and scoped children. The factory rejects
unrepresentable byte vectors without imposing an attacker-work query cutoff.

Initial schedule-five tests passed 31 helper tests and three focused PCS
tests, including decoded batch verification for both fields and profile-ID
separation. The first helper compile needed documentation on the new getter;
that lint was fixed. Final revalidation after scoped-child inheritance passed
all 31 helper tests and three focused PCS tests, with logs
`classical-atomic-column-helper-final-tests.log` and
`classical-atomic-column-pcs-latest-tests.log`. Native harness/grid and strict
descriptor/resource tooling for version five are still pending; frozen native
validation jobs remain version four or earlier and do not validate this change.

Version-five tooling is now connected: strict descriptor suite/byte-count
decoding, inherited parent field bounds, atomic Brakedown query/output/frame
accounting, no column-retry error, and the extra constructor schedule frame.
The grid, native harness and sequential validation runner accept mutually
exclusive `--atomic-columns`; both Rust examples type-check. All 48 classical
tooling tests and thirteen hash-budget tests pass. Runner conflicts reject
before output/job creation, and three grid conflicts reject before rows emit.

Built and exercised the actual version-five grid with role counts [2,3,4,5].
Full-width output has 624 rows (585 constructible), helper-basis output 144
(135 constructible), giving 702 unique admitted descriptors after 18 overlaps.
Verified every ID, complete basis, role/field/backend metadata and candidate
resource report; no security/performance gate is promoted. Evidence is in
`classical-atomic-column-grid-{full,helper}.log` and
`classical-atomic-column-grid-summary.json` under performance artifacts.

Added version-five complete fresh-certificate tests for both native fields
and all five variants (18 attack/control cases each). The release native
runner build is live under session 50333 (`classical-atomic-column-native-build.log`),
and the explicit fresh binding audit is live under session 20111
(`classical-atomic-column-fresh-binding-tests.log`). Neither is yet claimed
complete; check terminal results before using them as validation evidence.

The version-five release build completed. Frozen runner `columns-runner`
has SHA-256 `8a4a1ab2db2e1f6cc6aecc2ad9008761c41807e48fbd08bb7c507ea005d228cc`,
with source hashes in `columns-manifest.json`. Started the original-dimension
40-case matrix under session 96250 (`columns-matrix-driver.log`). BabyBear
Brakedown completed four NAND cases: independently verified terminal state,
binary/log fingerprints, version-five descriptor, decoded public verification
and original FHE/key/statement identities against the version-four control.
Evidence is `columns-matrix/babybear-brakedown-control-compatibility.json`;
the other matrix groups remain pending. These concurrent runs are correctness
checks, not matched performance measurements.

Added exact combined conditional classical work arithmetic and CLI. It sums
parent/PCS/sampler phase errors, Merkle and XOF all-trials polynomials before
minimizing over every positive integer attacker-work budget. Honest XOF offsets
also receive conservative phase opportunities. The CLI requires all honest
offsets; no positive numerical result selects queries or enables promotion.
All 52 classical tooling tests pass, including weak-query/weak-field rejection,
large honest offsets, both fields/all variants and component-before-minimum
composition. Two scenarios from actual emitted version-five native headers are
in `classical-version-five-native-combined-work-scenarios.json`; their offsets
are explicit hypothetical inputs. Actual prefix/source/filter and complete
soundness/knowledge composition remain unfinished.

Extended the outer binding decoder with an initial-product task interpreter:
trusted shape plus ordered context/root handles, alternating recovered
evaluation roots and original key roots. Tests commit real constant tables,
check a nonzero residual against zero key tables, and reproduce the production
verifier's first equality/mixing phases before a deliberately malformed later
suffix rejects. Both fields, all five backends and schedules four/five pass
(20 combinations, two tests), recorded in
`classical-initial-task-false-source-prefix-tests.log`. The first compile
needed an explicit SHA-512 trait qualification on a context call; fixed before
the broader runs. Full arbitrary candidate-prefix/source interpretation and
all remaining stages are still outstanding.

Version-five BabyBear PolyFRIM completed its four native NAND cases. Verified
terminal/binary/log/descriptor evidence and FHE/key/statement identities against
version-five Brakedown; the matrix is now 8/40 independently audited, with
`columns-matrix/babybear-polyfrim-control-compatibility.json` as evidence.
The native dictionary group remains live.

All 90 BabyBear schedule-five fresh-binding cases completed (18 cases for each
of five backends); the Goldilocks audit is still running. Captured the actual
running test executable from `/proc/2698584/exe` into immutable artifact
`columns-fresh-binding-audit-binary`, so later Cargo test rebuilds do not lose
its provenance. Checked every completed BabyBear case/acceptance flag and
recorded the stable log-prefix and executed-binary hashes in
`columns-fresh-binding-babybear-partial-audit.json`. This is partial toy-key
audit evidence, not terminal success for the full job or native qualification.

Added complete first-equality-query input interpretation: trusted framed
profile header, canonical outer binding, recovered context/root task bindings,
typed vector/prime markers and exact modulus/count descriptor. An independent
raw SHAKE256 and rejection sampler matches the production field block for both
fields, five backends and schedules four/five (20 combinations). Malformed
trailing data, requested counts and repeated-root bindings reject. Evidence:
`classical-complete-initial-query-prefix-retry-tests.log` (two tests passed).
Added SHA3 only as a snarks test dependency for the independent reference.

The initial reference failed because the manually reconstructed prefix omitted
`typed request kind`; fixing it also corrected the resource worksheet. Regular
prime phases have four frames, regular extension phases five, while direct
empty identities remain four. Protocol bytes/query counts were unchanged.
All 52 classical tooling tests pass. Revision-three input/work inventory uses
actual Q=768 factory scenarios and labels them separately from native Q=1
correctness controls; the initial attempted equality check caught that query
count distinction before any report was emitted. Neither scenario is admitted
as 128-bit security. Complete later-phase/source/knowledge coupling remains.

The full version-five fresh-binding job terminated successfully: 180/180
constructed cases across both fields and five backends, with ten controls
accepted and 170 false certificates rejected. Verified every case, the stable
earlier BabyBear log prefix, captured running binary hash and fresh test source
hash. Evidence is `columns-fresh-binding-complete-audit.json`; these use toy
synthetic keys, not native encrypted profiles. Native version-five validation
is now 24/40 independently audited: all five BabyBear groups plus Goldilocks
Brakedown. Binary/log/header and FHE/key/statement compatibility checks pass;
the Goldilocks PolyFRIM group remains running.

The initial-prefix audit now interprets the first mixing query as well as the
initial equality query. It recovers equality coins from a frozen view of known
consumed-byte producers, checks exact receipt length and canonical rejection
replay, and enforces the production first-message shape and zero boundary.
A later producer cannot repair an earlier empty history snapshot. Independent
SHAKE replay matches both production challenge blocks across both fields, all
five backends and schedules four/five (20 combinations). The two focused tests
pass in `classical-initial-mixing-prefix-tests.log`; source/log fingerprints are
in `opening-inventory/classical-initial-mixing-query-prefix-audit.json`.
This remains a partial executable audit, not the all-stage security argument.

Version-five native validation is now 28/40 independently audited. Goldilocks
PolyFRIM passed four proofs with terminal status, binary/log fingerprints,
canonical descriptor and per-case FHE/key/statement compatibility checked
against its Brakedown control. Evidence is
`columns-matrix/goldilocks-polyfrim-control-compatibility.json`.

The first-primary prefix interpreter now covers every remaining sumcheck
challenge under a supplied frozen producer-history view. It reconstructs the
reduced shape and mixed first claim, parses bounded canonical round messages,
checks paired boundary sums and replays earlier receipts to derive later
claims using independent Lagrange interpolation. Nonzero consistent fixtures
exercise the recurrence, and inconsistent sums/surplus bytes are rejected.
Both focused tests pass across 20 field/backend/schedule combinations in
`classical-complete-zerocheck-prefix-tests.log`. Per-round challenge matrices
and the whole production ZeroCheck dispatcher's continuation agree. Evidence
is `opening-inventory/classical-complete-zerocheck-prefix-audit.json`. Complete
source-word coupling, later-stage interpretation and PCS authentication remain
separate obligations; no security or performance promotion follows.

Two existing fresh-21 groups completed and passed independent terminal,
binary/log fingerprint and per-case FHE/key/statement compatibility audits:
optimized Goldilocks dictionary (version one), and atomic-ZeroCheck BabyBear
fragmented (version four). Their `*-control-compatibility.json` reports bring
those separately tracked schedules to 168/210 and 84/210 audited cases. The
version-five native matrix remains 28/40 audited. These are correctness checks.

The first-primary round interpreter now exposes a conditional fixed-source
residual interface. It returns the prior ordered matrix query and expected
claim, folds assigned source tables, builds the public mixed equality table
and computes the reduced relation sum minus the expected claim. Missing or
wrong-dimension assignments fail. The special first matrix folds original
factors only; later matrices also fold equality. Tests compare its equality
terminal with production ZeroCheck and retain nonzero residuals for the false
source fixture. Changing the current response while preserving its boundary
sum leaves the prior assigned residual unchanged. Both focused tests pass
across 20 combinations in `classical-assigned-residual-invariance-tests.log`;
fingerprints/scope are in
`opening-inventory/classical-assigned-residual-prefix-audit.json`. The fixed
assignments are supplied premises, not extracted Merkle words. Whole-word
assignment justification and all-stage coupling remain unfinished.

Added a recorded-preimage first-declaration word audit for Brakedown columns,
packed PolyFRIM source pairs and PipFRI fragment pairs on both native fields
(extension degrees six/three). It reconstructs actual source roots from
canonically decoded leaves, checks trusted geometry/position, and exercises
immutable root-window snapshots with zero completion of unavailable leaves.
Late exposures cannot repair the frozen word and are detected as prior-target
hits. The focused integration test passes in
`classical-word-history-all-grammars-tests.log`; exact scope and fingerprints
are in `opening-inventory/classical-source-word-history-audit.json`. This is
an executable conditional availability interface, not the full adaptive
coupling or source-decoding theorem.

Version-five Goldilocks dictionary finished four native proofs and passed
independent terminal/binary/log/descriptor and per-case FHE/key/statement
compatibility checks against its Brakedown control. The matrix is now 32/40
audited; Goldilocks fragmented is running. Evidence is
`columns-matrix/goldilocks-dictionary-control-compatibility.json`.

Added a reference bounded-distance source-assignment decoder to the recorded
word audit. A monic Welch system, exact quotient and joint whole-column error
check recover unique near source polynomials, including rank-deficient
fewer-error cases. Brakedown tests cover padding and nonconstant row codes;
direct PolyFRIM and fragmented PipFRI recover their different source layouts
and extension-coordinate-zero projections. Clean and radius-corrupted sources
recover; coordinatewise-near/jointly-far words and invalid padding use the
zero fallback. Goldilocks decoded tables are compared semantically, preserving
raw leaf spelling independently. The focused integration test passes in
`classical-all-source-assignment-tests.log`; scope/fingerprints are in
`opening-inventory/classical-fixed-source-assignment-audit.json`. This covers
reference geometries, not all bases/constants or the full security theorem.

The optimized version-one Goldilocks fragmented fresh-21 job finished and
passed independent binary/log/terminal and FHE/key/statement compatibility
checks. `optimized-fresh21/goldilocks-fragmented-control-compatibility.json`
brings that separately tracked schedule to 189/210 audited proofs. Version
five remains 32/40 audited, with fragmented running.

Expanded fixed-assignment audits to all eight extension bases and zero-variable
sources: 32 extension-backed cases plus six Brakedown cases, including both
base fields and Brakedown encoded padding. All pass in
`classical-complete-basis-constant-assignment-tests.log`. Reviewing production
constant queries corrected an over-strong draft premise: direct/scalar dummy
entries need not repeat; assignments restrict the decoded physical table to
dummy bit zero before projection, matching `(I,0)`/zero-point queries. Tests
change unused entries in base and higher extension coordinates while retaining
the logical assignment. Brakedown's coefficient-padding promise remains.
Evidence is `opening-inventory/classical-all-basis-constant-assignment-audit.json`.
Global source/child ordering and all-stage coupling remain unfinished.

Version-five Goldilocks fragmented native validation completed four proofs
and passed independent terminal/binary/log/profile and FHE/key/statement
compatibility checks against the field's Brakedown control. The native matrix
is now 36/40 audited; Goldilocks virtual is running. Evidence is
`columns-matrix/goldilocks-fragmented-control-compatibility.json`.

Added explicit virtual-initial word coupling to the source-history audit:
16 cases across all eight extension bases and two scalar fragment geometries.
It replays production gamma from the exact source binding, derives the
combined word from frozen fragments, compares its full domain to independently
combined coefficients and checks every production sampled pair against the
frozen source. Virtual paths are empty; pair mutation fails specifically at
fragment-combination verification. The identifier's recorded actual preimage
is metadata and cannot be used as a Merkle word. Prover/verifier continuations
match. The focused integration test passes in
`classical-virtual-derived-word-tests.log`; source/log fingerprints and scope
are in `opening-inventory/classical-virtual-derived-word-audit.json`. Global
linked-child ordering and full application coupling remain unfinished.

Extended the structural query-history audit with root declarations inherited
through production parent/child/grandchild seeds and finish links. Independently
encoded bytes match production states; ancestor-only roots reach nested
challenges and child-only roots reach resumed parents. Candidates queried
before required seed/finish producers stay inadmissible after late repair
attempts. Bounded declarations use the first eligible global input, preserving
original query indices while omitting oversized windows; unfiltered and bounded
first declarations are explicitly distinguished. All 32 helper tests pass in
`classical-inherited-root-helper-full-tests.log`. Exact scope/fingerprints are
in `opening-inventory/classical-inherited-root-ordering-audit.json`. This is
structural link/root inheritance, not all-stage grammar or joint-oracle root
filter preservation; the full security claim remains unqualified.

Aligned recorded source-word completion with the joint eligible SHA/XOF
work model. Both oracle input families declare windows before responses;
frozen graphs filter oversized preimages. Oversized queries retain global
chronology, invocation counts and collision accounting. New tests exercise
first eligible SHA declarations after oversized SHA/XOF carriers and late
preimage repair after eligible XOF declarations; all existing assignment and
virtual cases still pass in `classical-joint-root-history-tests.log`. Added
the conditional bounded-path filter lemma with its actual-input-size and
source-ordering premises explicit. Evidence is
`opening-inventory/classical-joint-root-history-audit.json`; full application
resource coupling and stage composition remain unfinished.

Version-five native validation is complete and independently re-audited:
40/40 original-size proofs across both fields and all five backends, every
NAND case, decoded verification, altered-output rejection and shared native
keys/statements. `columns-matrix-complete-audit.json` fingerprints every log
and metadata file against the frozen runner. This remains Q=1 correctness
validation. Started the same binary's fresh-input schedule, 21 proofs per
group (210 total), in `columns-fresh21`; actual running executable hash and
CPU affinity 0..15 were checked. Launch evidence is
`columns-fresh21-launch.json`, exec session 49719, initial child PID 2714553.
No concurrent correctness timing qualifies for performance promotion.

Made the selected native SHA512 input ceiling explicit: at most two valid
byte slices/output on a <=64-bit runtime gives L_h=2^64-2. Source inventory
covers metadata, Brakedown namespaces, Merkle pairs and profile IDs; actual
PCS committing/proving/verification asserts the two-update limit across the
existing 90 verification cases. Candidate oracle/work calculations now use
this SHA ceiling separately from framed XOF lengths and report both window
counts. All 52 classical Python tests, 13 oracle-budget tests and the Rust
hash-resource test pass. Evidence is
`opening-inventory/classical-native-hash-input-audit.json`; revision-four
input/work inventory recomputes ten Q768 factory scenarios with unchanged
hypothetical honest offsets and no admission. All-stage coupling still remains.

The version-five fresh-input schedule has its first independently audited
group: BabyBear Brakedown, 21/210 proofs. Binary/log/header/terminal and
FHE/key/statement compatibility checks pass against the earlier atomic
ZeroCheck fresh-21 control. Evidence is
`columns-fresh21/babybear-brakedown-control-compatibility.json`; BabyBear
PolyFRIM is now running. The version-five four-case matrix remains complete
and audited at 40/40.

Extended the first primary relation prefix through its terminal-value-to-PCS
handoff. It recovers the last coin block, complete ordered query and final
equality vector, parses bounded terminal values, applies backend validation
and checks the terminal equation. The recovered opening preserves trusted
source contexts/roots. In a fabricated algebraically consistent certificate,
the first claim is false for its assigned committed source; production full
relation rejection and transcript continuation match direct replay of the
recovered first PCS task. Wrong equations/oversized counts fail parsing. Both
focused tests pass across 20 combinations in
`classical-first-false-opening-prefix-tests.log`; evidence is
`opening-inventory/classical-first-opening-boundary-audit.json`. This covers
the pre-PCS boundary, not backend complete query grammars or later stages.

Implemented complete raw-input interpretation for the first Brakedown row
challenge and version-five atomic column phase. It inherits the recovered
primary opening, checks exact context/source/query/value bindings and trusted
row geometry, resolves the row receipt before bounded response parsing, and
checks the trusted column domain/Q-byte request. Independent raw SHAKE replay
matches both field coins and every index draw before deduplication. Missing
producers, changed roots/counts and surplus bytes fail. Full PCS rejection
continuations match. The focused tests pass with all 20 baseline cases, four
row-query cases and two atomic-column cases; evidence is
`opening-inventory/classical-brakedown-two-phase-prefix-audit.json`. Schedule
four replay is compatibility evidence only. Other PCS grammars and later
application stages remain unfinished.

The older version-four BabyBear virtual fresh-input job completed and passed
independent terminal/binary/log/profile and FHE/key/statement checks against
its field control. `zerocheck-fresh21/babybear-virtual-control-compatibility.json`
brings that separate schedule to 105/210 audited proofs; Goldilocks Brakedown
is now running. Version-five fresh-input validation remains 21/210 audited.

Added first-opening child-seed query interpretation for direct/dictionary
PolyFRIM and ordinary/virtual fragmented backends. It enforces actual claim
normalization, exact ordered source/query/value binding, backend label/context
and seed request. Independent raw SHAKE reproduces parent continuation and
the typed child header (profile, full basis and zero-count identity receipt).
All 16 non-Brakedown cases pass while retaining the full 20-case prefix suite
in `classical-first-pcs-seed-prefix-tests.log`. Evidence is
`opening-inventory/classical-first-pcs-child-seed-audit.json`. Nonempty child
challenge grammars and later application stages remain unfinished.

The version-four Goldilocks Brakedown fresh-input group completed and passed
independent terminal/binary/log/header and FHE/key/statement checks against
the optimized field control. Evidence is
`zerocheck-fresh21/goldilocks-brakedown-control-compatibility.json`; that
separate schedule is now 126/210 audited, with Goldilocks PolyFRIM running.
Version-five fresh-input validation remains 21/210 audited.

Implemented first nonempty fragmented-child projection query interpretation
for ordinary/virtual variants. Parent seed producers are checked in the child
view, but parent receipts are resolved in the parent's own frozen first-query
view. Late receipts available only in the child cannot repair the parent.
Known empty-identity producers are required; exact typed basis/count/label
checks precede interpretation. Independent raw coefficient sampling, extension
vector order, receipt and continuation match production. Eight projection
cases and the full 20-case prefix baseline pass in
`classical-first-fragment-projection-prefix-tests.log`; evidence is
`opening-inventory/classical-first-fragment-projection-audit.json`. Bridge
rounds, scalar PCS phases and remaining application grammars still need work.

Extended first fragmented-opening interpretation through every degree-two
bridge sumcheck challenge. It checks trusted degree/variable count, derives
the initial rho-compressed claim, replays prior extension receipts and checks
three-value round recurrences. Nonzero fixtures built from independent raw
XOF streams match production's full point, terminal evaluation and continuation.
Invalid sums and missing prior producers reject. Production's deferred-check
timing is unchanged; the interpreter excludes prefixes with no accepting
continuation and does not reduce rejected-trace resource ceilings. Eight
bridge sequences and all 20 prefix baseline cases pass in
`classical-fragment-bridge-round-prefix-tests.log`; evidence is
`opening-inventory/classical-fragment-bridge-round-audit.json`. Scalar PCS
phases and later application stages remain unfinished.

Connected completed fragmented bridge prefixes to ordinary/virtual scalar
gamma query interpretation. It reconstructs trusted scalar geometry/contexts,
checks inherited root/point and adapter/version bindings, parses bounded
fragment claims and checks their Boolean aggregate. The first source fixture
is now nonconstant, exercising aggregation order; real scalar commitments
reproduce the parent root and real scalar proofs verify. Independent gamma
coefficients match production; wrong aggregates reject. The full matrix
adapter accepts those scalar subproofs behind a fabricated bridge and rejects
at the terminal kernel equation. Eight gamma and all 20 baseline cases pass
in `classical-complete-scalar-gamma-prefix-tests.log`; evidence is
`opening-inventory/classical-scalar-gamma-prefix-audit.json`. Rolling/index
and later application grammars remain unfinished.

The earlier optimized version-one fresh-input job completed. Independently
checked the last Goldilocks virtual group and re-audited all ten terminal
groups: 210/210 original-size separate proofs over schedule 1+4+16, with
decoded verification, altered-output rejection, key reuse and per-field
FHE/key/statement compatibility. Evidence is
`optimized-fresh21-complete-audit.json`; older logs retain their actual
optional-header coverage. This is frozen Q1 correctness evidence. Latest
version-five fresh-input validation is still 21/210 audited, and its four-case
matrix remains complete at 40/40; version four is 126/210 audited.

Completed first ordinary/virtual fragmented opening nonempty challenge-input
interpretation through rolling alphas, terminal/index and ordinary consistency
indices. Original roots bind before alpha zero; derived roots bind in strict
layer order after prior alphas. Virtual initial identifiers derive from the
upstream source/gamma. Independent field/index streams and complete scalar
adapter continuations match; wrong layer indices/missing producers reject.
Eight sequences and all 20 baseline cases pass in
`classical-complete-first-fragment-query-prefix-tests.log`. Other openings,
direct/dictionary child phases and later application stages remain unfinished.

Actual frame counting found and corrected one omitted metadata frame per
fragmented call: six fixed frames, plus nu bridge messages and R root/terminal
messages. Protocol bytes and sampling counts were unchanged. All 53 classical
Python tests and 13 oracle-budget tests pass. Revision-five native input/work
inventory recomputes ten factory Q768 scenarios with unchanged hypothetical
offsets/no admission. Evidence is
`opening-inventory/classical-first-fragment-rolling-and-index-audit.json`.

Version-five BabyBear PolyFRIM fresh-input validation finished and passed
independent terminal/binary/log/header and per-case FHE/key/statement checks
against Brakedown. `columns-fresh21/babybear-polyfrim-control-compatibility.json`
brings the latest fresh-input matrix to 42/210 audited; BabyBear dictionary
is running. The original-classical optimized matrix is complete at 210/210;
version four remains 126/210 audited.


Extended the first direct/dictionary opening interpreter through its atomic
consistency-index request. Shared child parsing preserves parent-own frozen
receipt views; normalized lifted claims and trusted geometry bind the complete
ladder, member and consistency statement before sampling. Wrong source roots,
inconsistent ladders, truncated/oversized root counts, missing seeds, late
parent receipts and trailing bytes reject. Eight direct/dictionary sequences
match independent raw SHAKE indices and production transcript continuations;
all 20 baseline combinations pass in the two focused Rust tests. Evidence:
`opening-inventory/classical-direct-first-index-prefix-audit.json` and
`classical-direct-first-index-prefix-tests-final.log`. These use synthetic
adversarial ladders at the challenge boundary, not full direct-adapter proof
replays. Constant geometry, direct projection/rolling phases, later openings,
later application stages, security admission and performance gates remain.


Extended first direct/dictionary query interpretation through the atomic joint
lane-projection request. Trusted layer/width/basis counts and the complete
ladder bind the task before projection coins. Independent prime rejection,
extension coefficient ordering, receipt and continuation match production.
An actual joint-kernel verifier consumes the same consistency-index phase
before its expected pair-authentication rejection on a malformed packet;
its post-index continuation matches raw replay. Earlier inline index bytes
do not change the fixed projection task, and interpretation does not query
an unknown prior oracle input. Eight direct/dictionary sequences and the
20-case baseline pass in `classical-direct-projection-prefix-tests-final.log`;
evidence is `opening-inventory/classical-direct-projection-prefix-audit.json`.
These remain synthetic boundary fixtures. Full accepted adapter replay,
constant geometry, direct rolling phases, later openings/application stages,
security admission and performance qualification remain unfinished.


First direct/dictionary sampling-prefix interpretation now extends through
every rolling alpha, terminal and final atomic index request. Virtual original
identifiers derive from the complete ladder and recovered projection rows;
trusted FRI context/mode and sequential derived-root indices are checked.
Missing receipt producers and wrong derived-layer indices reject. All alphas,
index draws and final continuation match independent SHAKE/production transcript
replay. Actual frame counting confirms 6+R for one opening/context, matching
(4+R)*A+2*C without changing resource envelopes. Eight direct/dictionary
sequences and all 20 baseline combinations pass in
`classical-direct-complete-rolling-prefix-tests.log`; evidence is
`opening-inventory/classical-direct-complete-rolling-prefix-audit.json`.
These synthetic boundary fixtures do not prove a fully accepted adapter
certificate, constant/native geometry coverage, later openings or application
stages. Full security admission and performance qualification remain open.


Generalized the primary relation's inherited seed/typed-child task origin
from factor zero to every ordered factor for the four child-based backends.
Evaluation/key role selection, normalized query/value and source context/root
are checked. Earlier completion bytes cannot alter the next fixed task;
out-of-range indices, wrong sources, trailing bytes and truncated finishes
reject. Every child resolves parent receipts in the parent's own frozen view;
missing seeds and late parent receipts reject at every index. Sixteen complete
factor chains match production seed/init/probe/finish and final parent
continuations. Both focused tests and all 20 baseline combinations pass in
`classical-ordered-factor-seed-and-child-prefix-tests.log`; evidence is
`opening-inventory/classical-ordered-factor-seed-and-child-prefix-audit.json`.
These fixtures exercise linked transcript continuations without asserting
acceptance of earlier fabricated PCS bodies. Later-factor backend sampling,
Brakedown continuation, later application stages, security admission and
performance qualification remain unfinished. Native jobs remain live at
42/210 (version five) and 126/210 (version four) audited.


Direct/dictionary consistency, projection, rolling-alpha and final-index
interpreters now take an explicit primary factor index. Every factor uses
its inherited root/value and evaluation/key normalization; primary geometry
remains role zero, as in the production factory. All direct/dictionary factors
are driven through every sampling phase within their actual linked-child
chains. Independent raw SHAKE rejection/indices, missing prior receipt checks,
child probes/finishes and final parent continuations pass. Later seed inputs
now include complete earlier sampling continuations. Eight full direct/
dictionary chains, all sixteen child-backend seed chains and the 20-case
baseline pass in `classical-all-primary-direct-factor-sampling-tests.log`.
Evidence: `opening-inventory/classical-all-primary-direct-factor-sampling-audit.json`.
The ladders/derived roots/terminal are synthetic adversarial boundary values;
accepted PCS certificates are not asserted. Later fragmented-factor sampling,
Brakedown continuation, zero-variable/native geometry coverage, later
application stages, security admission and performance gates remain open.


Version-five BabyBear dictionary fresh-input validation completed and passed
independent terminal metadata, binary/log fingerprints, strict profile header,
21 decoded records and per-case FHE/key/statement compatibility checks against
its Brakedown control. Evidence is
`columns-fresh21/babybear-dictionary-control-compatibility.json`. The latest
fresh-input matrix is now 63/210 audited; BabyBear fragmented is running.
Version-four Goldilocks PolyFRIM remains live at 126/210 audited overall.
These frozen Q1 jobs establish correctness only, not selected security queries
or matched performance qualification.


Extended fragmented ordinary/virtual sampling interpretation to every primary
factor. The factor index is now derived from the trusted ordered parent seed
grammar and carried through bridge claim, scalar-root binding and virtual
identifier derivation; explicit-index callers also require an index match.
Every factor's projection, all bridge rounds, scalar gamma, rolling alphas,
terminal and indices match independent raw sampling. Bridge points/evaluations
also match the actual MLSumcheck verifier. Missing prior producers reject.
Complete sampling/probe/finish states feed later factor seeds and the final
parent continuation. All sixteen child-backend sampling chains and the 20-case
baseline pass in `classical-all-primary-fragment-factor-sampling-tests.log`;
evidence is `opening-inventory/classical-all-primary-fragment-factor-sampling-audit.json`.
Later scalar claims/roots/terminal remain synthetic boundary fixtures, not
fully accepted PCS certificates. Brakedown continuation, zero-variable/all
native geometries, later application stages, security admission and matched
performance qualification remain unfinished. Latest native fresh-input
validation remains 63/210 audited (version five), 126/210 (version four).


Extended version-five Brakedown sampling-prefix interpretation to every primary
factor. The parser checks bounded earlier row/response/atomic-column framing,
selects the fixed next source/claim, strictly consumes current row queries,
and recovers current row coins for current column tasks. Wrong source/order
bounds, trailing bytes, missing current producers, truncated earlier outputs
and oversized response counts reject. Earlier opaque output changes preserve
the next task. Independent row rejection/receipts/index draws and the final
parent continuation match production transcript sampling. Both focused tests
pass in `classical-all-primary-brakedown-factor-sampling-tests-final.log`,
retaining all sixteen child-backend sampling chains and the 20-case baseline.
Evidence is `opening-inventory/classical-all-primary-brakedown-factor-sampling-audit.json`.
Synthetic responses do not assert accepted authenticated PCS certificates.
Version-four Brakedown remains compatibility-only; zero-variable/all native
geometries, later NTT/decomposition/lookup/accumulator/final stages, full
security admission and performance qualification remain unfinished. Native
fresh-input matrices remain 63/210 (version five), 126/210 (version four)
audited, with their current jobs live.


Connected completed primary opening sequences to the first NTT row-query task.
The parser recovers advertised coefficient/evaluation handles from the outer
statement and checks trusted field/context/transform geometry and the atomic
width*row_variables request. All primary completions are consumed; Brakedown
reuses shared bounded response/output parsing. Altered roots, malformed
counts, trailing bytes and missing earlier receipts reject. The actual NTT
verifier consumes this row phase and binds empty folded polynomials before
its expected dimension rejection; independent raw receipt/state replay matches
its continuation in all 18 eligible backend/field/schedule cases. Both focused
tests pass with all prior primary sampling checks and the 20-case baseline in
`classical-first-ntt-row-prefix-tests.log`; evidence is
`opening-inventory/classical-first-ntt-row-prefix-audit.json`. Dummy owned PCS
packets are unused because the verifier rejects before opening authentication.
Accepted NTT certificates, compression/batch-opening tasks, later NTT and
application stages, full native geometry coverage, security admission and
matched performance qualification remain unfinished.


Extended the first NTT interpreter through every coefficient-compression
challenge. Both folded-array dimensions are bounded before allocation; the
native transform identity and backend value contract are checked. Row points
and preceding compression matrices recover from frozen receipts. Nonzero
positive folded arrays, false transforms, oversized nested counts, missing
producers and trailing bytes are tested. The production NTT fixture now uses
valid folded arrays and reaches its first coefficient-PCS error, replacing the
earlier empty-folded dimension-error path. Independently reconstructed queries,
compressed values, raw receipts and post-error state match all 18 cases;
Brakedown/fragmented parent metadata or seed exposes the opening statement in
10 cases, while direct/dictionary rejects at packet-count preflight in 8.
Both focused tests and the 20-case baseline pass in
`classical-first-ntt-compression-prefix-tests.log`; evidence is
`opening-inventory/classical-first-ntt-compression-prefix-audit.json`.
Batch-opening sampling grammars, accepted NTT certificates, later stages,
full native geometry coverage, security admission and performance qualification
remain unfinished.

Version-four Goldilocks PolyFRIM fresh-input validation completed and passed
independent terminal/binary/log/header/21-record and field-control identity
checks. `zerocheck-fresh21/goldilocks-polyfrim-control-compatibility.json`
brings that matrix to 147/210 audited; Goldilocks dictionary is live. Version
five remains 63/210 audited with BabyBear fragmented live. These are frozen
Q1 correctness checks, not security or performance qualification.


Added executable first-NTT inherited batch-task interpretation: the final
compression receipt fixes complete ordered queries and separately compressed
coefficient/evaluation values. Child seed bindings apply direct/dictionary
normalization and preserve the full statement; version-five Brakedown binds
its batch and exact row-request geometry. Missing final producers, trailing
and malformed requests reject. Correctly shaped dummy packets for a different
source root now drive the production verifier into a bound opening query for
all 18 cases, replacing the earlier eight direct/dictionary count-preflight
stops. Independent parent replay includes child seeds or Brakedown row,
response and column phases and matches the final state. Both focused tests
and all 20 baseline combinations pass in
`classical-first-ntt-batch-opening-task-tests.log`; evidence is
`opening-inventory/classical-first-ntt-batch-opening-task-audit.json`.
Accepted NTT certificates, subsequent batch child/column task grammars,
evaluation opening, later components/stages, full native geometry coverage,
security admission and performance qualification remain unfinished.


Extended first-NTT Brakedown interpretation through the atomic column query.
Current row coins recover from frozen receipts; response groups derive from
left-prefix matrix equality, with both response counts bounded before
allocation. A controlled same-left/different-right query fixture yields one
group and rejects two evaluations. Missing current producers, oversized
counts and trailing bytes reject. Shared typed-header/label parsing now also
reconstructs NTT child origins through each parent's own first-query view;
missing seeds/identity producers, late parent receipts, wrong labels and
primary-family reinterpretation reject. Both focused tests pass, retaining
all 20 baseline combinations, in
`classical-first-ntt-column-and-child-task-tests-final.log`; evidence is
`opening-inventory/classical-first-ntt-column-and-child-task-audit.json`.
Controlled grouping uses proposed frozen receipts; NTT child headers are
structural fixtures, not full child sampling or accepted NTT certificates.
Batch child sampling, evaluation opening, later components/stages, complete
native geometry coverage, security admission and performance gates remain.


Extended first-NTT fragmented child interpretation through batch projection
and all bridge query inputs. The projection requests queries*width extension
weights and compresses claims in query-major/lane-minor order; bridge variable
count remains source_vars+log2(width). Trusted degree/message dimensions,
recurrences and preceding frozen receipts are checked. Sixteen ordinary/
virtual zero/nonzero sequences match independent raw rejection and the public
classical primitive's receipt/continuation; missing producers, malformed
counts and trailing bytes reject. Parent snapshots precede child-only seed/
identity additions. Both focused tests pass with all 20 baseline combinations
in `classical-first-ntt-fragment-bridge-task-tests-final.log`; evidence is
`opening-inventory/classical-first-ntt-fragment-bridge-task-audit.json`.
The nonzero prefix uses proposed frozen receipts, and these are primitive/
prefix checks rather than a complete production NTT bridge or accepted
certificate. Subsequent scalar PCS, direct/dictionary batch-child sampling,
evaluation opening, later stages, full native geometry coverage, security
admission and performance qualification remain unfinished.


Connected first-NTT fragmented batch bridges to scalar gamma task
interpretation. The final receipt completes the bridge point/expected value;
trusted scalar mode/context, inherited root and point, bounded fragment claims
and their Boolean aggregate precede gamma. Nonconstant fragment claims use
an independent Boolean-basis evaluation; adding one to every fragment while
retaining the value rejects. Oversized counts, missing last producers and
trailing bytes reject. Gamma coefficients, raw receipts and the public
classical primitive continuation match all sixteen zero/nonzero ordinary/
virtual sequences. Both focused tests and the 20-case baseline pass in
`classical-first-ntt-scalar-gamma-task-tests.log`; evidence is
`opening-inventory/classical-first-ntt-scalar-gamma-task-audit.json`.
These remain synthetic task-boundary/proposed-receipt prefixes. Rolling
sampling/authentication, accepted scalar/NTT certificates, direct/dictionary
batch child sampling, evaluation openings, later components/stages, native
geometry coverage, security admission and performance qualification remain.


Extended first-NTT fragmented scalar interpretation through every rolling
alpha, terminal, atomic rolling indices and ordinary consistency indices.
Shared rolling-data parsing now serves primary and NTT origins. It checks
original ladders/FRI context before alpha zero, virtual identifiers from the
inherited source/point/gamma, earlier receipts and sequential derived roots.
Missing producers, wrong derived-layer indices and trailing index bytes
reject. All alpha coefficients, every pre-dedup index draw and the public
primitive's final continuation match independent raw replay in sixteen zero/
nonzero ordinary/virtual sequences. Both focused tests retain all 20 baseline
combinations and pass in `classical-first-ntt-fragment-rolling-task-tests.log`;
evidence is `opening-inventory/classical-first-ntt-fragment-rolling-task-audit.json`.
These remain synthetic task-boundary/proposed-receipt fixtures, not complete
accepted scalar/NTT certificates. Direct/dictionary batch-child sampling,
evaluation openings, later components/stages, native geometry coverage,
security admission and performance qualification remain unfinished.


Extended first-NTT direct/dictionary interpretation through every ordered
consistency-index request and the atomic joint-projection request. Trusted
query/round counts bound the complete ladder matrix, whose rows begin at the
inherited coefficient root. Normalized statements lift into E; member bindings
must match before exact index draws, then projection rebinds all ladders and
requests rounds*queries*width extension weights. Core geometry and projection
framing are shared with primary openings. Sixteen zero/nonzero sequences match
all raw index draws, projection coefficients/receipt and public-primitive
continuation. Member order, out-of-range indices, trailing bytes, missing seeds
and malformed projection counts reject. Both focused tests and all 20 baseline
combinations pass in `classical-first-ntt-direct-batch-projection-tests-final.log`;
evidence is `opening-inventory/classical-first-ntt-direct-batch-projection-audit.json`.
These use synthetic ladders and proposed nonzero parent receipts, not accepted
NTT certificates. Direct rolling, evaluation openings, later stages, complete
native geometry coverage, security admission and performance gates remain.


Extended first-NTT direct/dictionary batch interpretation through all rolling
alphas, terminal and final atomic index request. The rolling-data parser is
shared with primary one-query openings. It derives each virtual original from
the complete ladder matrix and layer/query/lane projection rows, checks the
trusted FRI binding, earlier receipts and sequential derived-root indices.
Missing producers, wrong layers and trailing index bytes reject. Sixteen zero/
nonzero sequences match every raw alpha/index draw and the public primitive's
final continuation. Both focused tests and all 20 baseline combinations pass
in `classical-first-ntt-direct-batch-rolling-tests.log`; evidence is
`opening-inventory/classical-first-ntt-direct-batch-rolling-audit.json`.
Synthetic roots/terminal and proposed nonzero prefixes do not assert accepted
NTT certificates. Evaluation openings, later NTT/components/stages, complete
native geometry coverage, security admission and performance gates remain
unfinished. Native fresh-input validation remains 63/210 (version five) and
147/210 (version four) independently audited, with their current groups live.


The first-NTT child-opening interpreter now selects the evaluation source after
consuming the ordered coefficient child seed and fixed-length finish frame.
Selection carries the evaluation root, compressed values and normalization
parameters through direct/dictionary consistency, projection and rolling, and
fragmented/virtual bridge, scalar and rolling interpretation. Earlier completion
bytes are checked for bounded framing only; they do not certify acceptance of
the preceding opening. Both field fixtures exercise the evaluation continuation
for all four child backends and both profile versions, including missing/short
finish frames and trailing-byte rejection. These synthetic continuations do not
establish complete NTT acceptance. Brakedown evaluation continuation, later NTT
components/application stages, native geometry coverage, complete security
admission and matched performance qualification remain unfinished.

Validation: `cargo test -p snarks outer_prefix_interpretation --lib` passed
both field tests (20 baseline combinations, 16 evaluation child continuations)
in 182.88s. Evidence: `classical-ntt-evaluation-prefix-tests.log` and
`opening-inventory/classical-ntt-evaluation-child-prefix-audit.json`. The
version-5 BabyBear fragmented fresh-proof group also independently passed its
21-proof control comparison, bringing audited version-5 coverage to 84/210.


Extended the first-NTT Brakedown v5 interpreter to the evaluation opening.
Advancing past the coefficient opening requires an 80-byte row receipt,
canonical response arrays bounded by trusted geometry and left-prefix query
grouping, the exact atomic column request, and its 8*Q-byte output. The next
binding must select the inherited evaluation root and compressed values. Its
row receipt is independently replayed before column selection; missing current
producers and trailing input fail. Earlier completion frames establish source
ordering only, not acceptance of their responses or authentication paths.
Both field tests passed on the final revision (20 baseline combinations, two
new Brakedown evaluation sequences) in 190.77s; rustfmt check passed. Evidence:
`classical-ntt-brakedown-evaluation-prefix-final-tests.log` and
`opening-inventory/classical-ntt-brakedown-evaluation-prefix-audit.json`.
All five backend families now have first-component evaluation sampling
interpretation. Remaining NTT components, later application stages, complete
accepted-certificate/native geometry coverage, security admission and matched
performance qualification remain unfinished.


Extended the NTT sampling/source-origin interpreter across every configured
component in the canonical verifier's ordered 2*d+1 loop. It recovers the trusted
component count and source arrays from the outer statement, requires the exact
coefficient/evaluation pair at each task, and advances only after both earlier
opening completions have bounded framing. Compression and batch construction
are shared helpers, so traversal does not recursively re-enter the outer parser.
Coefficient fixture roots are now distinct by component (evaluation roots were
already distinct); substituting component zero's coefficient or evaluation root
for any later source fails. Every component exercises atomic row points,
compression rounds and both child-seed or Brakedown row/column boundaries.
Both focused field tests passed in 215.36s, retaining 20 baseline combinations
and exercising 18 full ordered-component chains (v4 Brakedown remains the retry
compatibility case). Rustfmt check passed. Evidence:
`classical-ordered-ntt-distinct-components-tests.log` and
`opening-inventory/classical-ordered-ntt-components-audit.json`.
These are synthetic sampling/source-origin fixtures. Earlier child finishes and
Brakedown completion responses do not certify prior PCS acceptance; no complete
NTT certificate, all-native-geometry coverage or full adaptive knowledge theorem
is asserted. Later application-stage coupling, complete security admission and
matched performance qualification remain unfinished.


Extended the executable prefix interpreter from complete ordered NTT framing
into the first shared radix decomposition. The transition requires the trusted
last NTT component and both completed openings. The stage binds input[0], the
first configured coefficient digit slice, borrow/helper contexts and exactly
d+1 bounded borrow roots. Reconstruction and zero endpoint relations are derived
from the trusted radix, normalized in the original input context, then bound
with the full source registry before every linear matrix challenge. Previous
round receipts are independently replayed; missing producers and trailing bytes
fail. An isolated invocation of the actual shared decomposition verifier reaches
its post-linear dimension rejection and matches the independent raw transcript
continuation after all challenge rounds. Both field tests passed in 233.20s
(20 baseline combinations, 18 new stage sequences); rustfmt check passed.
Evidence: `classical-decomposition-linear-prefix-tests.log` and
`opening-inventory/classical-decomposition-linear-prefix-audit.json`.
The outer NTT completions are synthetic framing fixtures. This does not assert
accepted earlier openings or a complete decomposition certificate. First-stage
PCS/lookup coupling, second decomposition, accumulator/monomial/final-stage
coupling, full native geometry coverage, security admission and matched
performance qualification remain unfinished.


Extended first-decomposition linear interpretation across every ordered PCS
source handoff: original input, configured digit slice, then borrow roots.
The complete common matrix query is recovered before claim metadata, and
parameter selection follows the source role. Each metadata claim has a bounded
width, expected root/context and normalized query/value representation. Brakedown
v5 row requests and all four child-backend seed requests are interpreted for
every source. Typed children recover the task from their own frozen parent view;
wrong roots, missing seed producers, trailing bytes and reinterpretation as a
primary-relation child fail. Synthetic zero claim vectors satisfy all three
linear relations; earlier finish/response bytes establish bounded order only.
Both field tests passed in 262.40s (20 baseline combinations, 18 stage sequences)
and rustfmt check passed. Evidence:
`classical-decomposition-opening-origin-tests.log` and
`opening-inventory/classical-decomposition-opening-origin-audit.json`.
These checks do not establish accepted earlier PCS openings or complete backend
sampling for decomposition. Those sampling phases, lookup coupling, the second
decomposition and later stages, native geometry coverage, full security admission
and matched performance qualification remain unfinished.


Extended direct/dictionary sampling interpretation to every first-decomposition
linear source. Opening tasks now carry an explicit primary/decomposition family;
parameter selection uses the verified origin and registry position. The shared
direct entry accepts either separately interpreted origin, while the primary-only
child entry remains separate. The same sampler and fixture cover consistency
indices, atomic joint projections, all rolling challenges, terminal binding and
final indices. Existing primary fixtures retain the production Transcript;
synthetic decomposition children use a test-only public-ClassicalTranscript
adapter, whose final continuation matches independent raw replay. Both field
tests passed in 422.01s (20 baseline combinations, eight new direct/dictionary
stage chains, every input/digit/borrow source) and rustfmt check passed. Evidence:
`classical-decomposition-direct-sampling-tests.log` and
`opening-inventory/classical-decomposition-direct-sampling-audit.json`.
The ladders and terminal are synthetic sampling fixtures, not accepted complete
PCS certificates. Fragmented/virtual decomposition sampling, Brakedown column
sampling, lookup and later-stage coupling, native geometry coverage, full
security admission and matched performance qualification remain unfinished.
The native version-4 Goldilocks dictionary group also passed its independent
21-proof control comparison, bringing audited version-4 fresh coverage to
168/210; Goldilocks fragmented is running. These remain correctness-only runs.


Extended shared fragmented/virtual sampling interpretation to every first-
decomposition linear source. The common child entry retains the explicit
primary/decomposition task family, then the existing sampler and fixture cover
lane projections, every degree-two bridge coin, scalar gamma, all rolling
alphas, terminal binding, rolling indices and ordinary consistency indices.
Synthetic child replay uses the public ClassicalTranscript primitive and
bounded canonical decoding of each three-evaluation round before independent
quadratic recurrence checks. Existing primary fixtures still call the actual
production MLSumcheck verifier. Decomposition claims now use nonzero sources,
digits and interior borrows while preserving reconstruction and both zero
borrow endpoints; retained direct/dictionary chains exercise those claims too.
Both field tests passed in 708.88s (20 baseline combinations, eight fragmented/
virtual and eight direct/dictionary stage chains, all registered sources), and
rustfmt check passed. Evidence:
`classical-decomposition-fragment-sampling-final-tests.log` and
`opening-inventory/classical-decomposition-fragment-sampling-audit.json`.
These are synthetic source/sampling fixtures with proposed scalar ladders and
terminal values, not complete accepted PCS certificates. Brakedown decomposition
column sampling, lookup and later-stage coupling, native geometry coverage,
full security admission and matched performance qualification remain unfinished.


Extended first-decomposition Brakedown v5 sampling interpretation through the
atomic column request for every input/digit/borrow source. The source walker
retains a pending row boundary; the column interpreter independently replays
its current receipt, decodes both response vectors under trusted dimensions,
and requires the exact index domain and 8*Q-byte request. Fixtures use nonzero
response vectors and raw-SHAKE column outputs for subsequent framing. Wrong
roots, missing current producers, oversized response counts, changed request
descriptors and trailing input fail. The existing profile factory is shared by
two focused field tests; both passed in 15.09s and rustfmt check passed. The full
all-backend outer-prefix suite was not rerun for this Brakedown-specific change.
Evidence: `classical-decomposition-brakedown-columns-tests.log` and
`opening-inventory/classical-decomposition-brakedown-columns-audit.json`.
All five backend families now have first-decomposition sampling interpretation,
with v4 Brakedown still a separate retry-compatibility case. These are synthetic
source/sampling fixtures, not accepted authenticated opening certificates.
Lookup and later-stage coupling, native geometry coverage, full security
admission and matched performance qualification remain unfinished.


Extended the first-decomposition interpreter through completed linear openings
into shared lookup registry binding, the multiplicity-bound child seed and its
first tuple-hash challenge. Completed mode checks every reconstruction/zero-
endpoint relation before exposing the digit-then-borrow registry. Comparison
requests and limb slots come from the trusted radix configuration; normalized
tables, helper context and all registry roots bind before bounded grouped
multiplicities and their exact flat view. The typed child recovers its seed task
from the parent's own frozen producer view. Its first hash coefficients and
continuation match public-primitive and independent raw replay. An isolated
actual lookup verifier confirms preflight/registry framing, stopping at absent
helper packets before the child seed; no full production lookup acceptance is
asserted. Oversized multiplicities, missing seed producers and trailing child
input fail. The full focused field tests passed in 726.27s (20 baseline
combinations, 18 lookup-entry sequences), and rustfmt check passed. Evidence:
`classical-decomposition-lookup-entry-tests.log` and
`opening-inventory/classical-decomposition-lookup-entry-audit.json`.
The earlier PCS completions and lookup multiplicities are synthetic fixtures.
Reciprocal rejection/retries, later request/repetition challenges, helper roots,
equality points, batch algebra and lookup authentication, the second
decomposition and later stages, native geometry coverage, full security admission
and matched performance qualification remain unfinished.


Extended first-decomposition lookup interpretation across every ordered request
and repetition's hash/reciprocal schedule. The walker recovers each hash receipt,
derives its compressed public table, rejects r=0 and every public-table pole,
and remains in the same reciprocal phase until an admissible candidate appears.
Each retry consumes input; there is no arbitrary retry/attacker-query cutoff.
It distinguishes pending hash, pending reciprocal and completed schedules,
retaining prior accepted pairs for subsequent helper/equality tasks. Natural
hashes/reciprocals and final continuations match public-primitive/raw replay for
all 18 inherited stage sequences. Two focused field tests additionally use two
requests with two repetitions each and proposed receipts forcing zero and table
poles before acceptance; these proposed draws are not actual SHAKE outcomes.
Those two tests passed in 0.01s, and both full field tests passed in 751.61s
(retaining all 20 baseline combinations); rustfmt check passed. Evidence:
`classical-lookup-reciprocal-retry-tests.log`,
`classical-decomposition-lookup-compression-tests.log`, and
`opening-inventory/classical-decomposition-lookup-compression-audit.json`.
The reference-game note now states the exact admissible-domain uniformity and
geometric retry law, explicitly separated from adaptive Fiat-Shamir lifting.
No complete accepted lookup certificate or security admission is asserted.
Helper roots, equality points, batch algebra and lookup authentication, later
application stages, native geometry coverage and matched performance
qualification remain unfinished.
Two native version-5 groups also passed independent audits: BabyBear virtual
against its field control, completing all five BabyBear groups; and Goldilocks
Brakedown against its frozen version-4 control, including both binaries/logs and
all 21 case identities. Audited version-5 fresh coverage is now 126/210.
Goldilocks PolyFRIM (v5) and fragmented (v4) are running; these are correctness
runs only, with no security/performance qualification.


Extended first-decomposition lookup interpretation through the full helper-root
array, every equality-point vector and every shared scalar sumcheck round.
Helper counts come from the accepted request/repetition schedule; root decoding
is bounded before allocation and binds all roots before any equality draw.
Helper context/geometry and prior equality receipts are recovered explicitly.
Rational public sums and full/padded equation degrees are derived from trusted
requests and multiplicities; serialized metadata is compared against a test-only
observer of the actual private production inverse/sum/degree helpers. This check
preserves Goldilocks scalar multiplication and individual-inverse operation
order rather than substituting algebraically equivalent lazy representations.
Every individual recurrence is checked before the common challenge; fixtures
include nonzero higher-degree terms. Independent raw/public-primitive replay
matches all points and the full continuation. An isolated actual batch verifier
also matches the generated points, terminal subclaims and transcript state.
Oversized root counts, missing earlier receipts and a bad individual recurrence
fail. Both full field tests passed in 804.34s (20 baseline combinations, 18 lookup
stage sequences); both retry regression tests passed in 0.01s; rustfmt checks
passed for both changed audit files. Evidence:
`classical-decomposition-lookup-equality-batch-final-tests.log`,
`classical-lookup-equality-batch-retry-regression.log`, and
`opening-inventory/classical-decomposition-lookup-equality-batch-audit.json`.
The fixtures do not assert complete accepted lookup certificates or padded-
degree-four/native-geometry coverage. Terminal source/helper consistency,
helper/source PCS authentication, later application stages, full security
admission and matched performance qualification remain unfinished.
The native version-4 Goldilocks fragmented group independently passed all 21
fresh-proof control comparisons, increasing audited version-4 coverage to
189/210. Goldilocks virtual (v4) and PolyFRIM (v5) remain live correctness jobs.


Extended first-decomposition lookup interpretation through terminal consistency
and the linked parent handoff. The last scalar receipt completes the shared
point and all terminal subclaims. Source/helper arrays are decoded under trusted
counts and widths; source parameter validation and canonical helper scalars are
checked before every sum/helper and reciprocal-identity predicate. Scalar source
pullback, coefficient-helper queries and normalized helper claims are derived
from the recovered common point. Constructed terminal claims satisfy the reduced
algebra, and a test-only observer of the actual production terminal checker
agrees; changing a source or helper claim and oversized metadata fail. These
claims are not asserted to authenticate against the earlier committed words.
The finish fingerprint matches public-primitive/raw replay. Returning to the
parent requires the exact seed input, matching seed/finish digests, matching
child origin and the child's own frozen finish view. Missing finish producers,
missing frozen views and altered digests fail. Both focused Brakedown field tests
passed in 29.04s; both full field tests passed in 800.18s (20 baseline combinations,
18 lookup stage sequences); rustfmt checks passed for both changed audit files.
Evidence: `classical-decomposition-lookup-terminal-focused-tests.log`,
`classical-decomposition-lookup-terminal-tests.log`, and
`opening-inventory/classical-decomposition-lookup-terminal-audit.json`.
The positive terminal fixtures use full logical domains and one repetition per
request. Padded/multiple-repetition terminal witnesses and full native geometry
are not covered. Helper/source PCS authentication, the second decomposition and
later stages, full adaptive security admission and matched performance
qualification remain unfinished; no complete accepted lookup certificate is
asserted.


Extended the closed first-decomposition lookup into every ordered helper PCS
handoff. An explicit LookupHelper task family selects the trusted helper
parameters and role-one geometry. Helper roots, coefficient query and normalized
claims come from the checked lookup terminal/finish; helper context equality is
required. All child-backend seed requests and typed origins are interpreted.
Their own frozen parent views must retain the ancestor lookup finish producer;
a producer available only in the later child view cannot repair its absence.
Missing seeds and reinterpretation as a decomposition-linear child fail.
Brakedown row/column framing now has explicit role-based geometry, while existing
source callers retain role zero. Helper row receipts and nonzero responses are
replayed; using main-source row counts or response dimensions fails. Every
helper completion has bounded ordered framing, without asserting earlier PCS
acceptance. Both full field tests passed without warnings in 871.63s (20 baseline
combinations, 18 helper-stage sequences); rustfmt check passed. Evidence:
`classical-lookup-helper-role-tests.log` and
`opening-inventory/classical-lookup-helper-role-audit.json`.
Direct/dictionary and fragmented/virtual helper-body sampling, original-source
PCS authentication, later stages, native geometry coverage, full security
admission and matched performance qualification remain unfinished.
The native version-4 fresh matrix is independently complete: 210/210 proofs in
ten groups, driver terminal exit 0 (session 95581). Every log, metadata and frozen
binary fingerprint, v4 descriptor/header, original n=1024/LWE=728/output=728
geometry, 1+4+16 fresh single-proof schedule, decoded verification, altered-output
rejection, key/setup reuse and field-control identities were re-audited. Evidence:
`classical-native-validation/zerocheck-fresh21-complete-audit.json`. All profiles
use Q=1 correctness settings; no security/performance qualification follows.


Lookup-helper sampling extension is under validation. Direct/dictionary helper
children select helper-role consistency, projection and rolling geometry. The
fragmented and virtual helper paths now derive lane requests, bridge dimensions,
scalar contexts, rolling roots and index blocks from the authenticated helper
origin and role, retaining the existing source-role wrappers for NTT callers.
Every helper is replayed against independent raw SHAKE and the public transcript
primitive. Focused field fixtures reject substitution of source-role bridge
dimensions; missing-receipt and frozen-parent-view checks remain enabled.
`cargo check -p snarks --lib --tests` passed for the role-aware parser, and the
final focused test revision compiled without warnings. Runtime tests remain
pending in `classical-lookup-helper-direct-sampling-tests.log` and
`classical-lookup-helper-fragment-tests-final.log`. Frozen source/binary captures
and running metadata are under `opening-inventory/lookup-helper-*-sampling-*`.
The initial fragmented test compilation was interrupted after correcting a
negative test that assumed unequal lane widths; it is not passing evidence.
These are synthetic prefix fixtures for BabyBear extension degree 6 and
Goldilocks degree 3, not complete accepted native lookup certificates, full
field/geometry coverage, security admission or performance qualification.


The native version-5 Goldilocks PolyFRIM fresh group completed 21/21 with terminal
exit 0. An independent re-audit checked the actual frozen binary hash, log and
metadata fingerprints, v5 descriptor with all role queries equal to one,
original FHE geometry, decoded/output-rejection/key-reuse flags, complete
1+4+16 schedule and all field-control identities against Goldilocks Brakedown.
The version-5 audited total is 147/210; Goldilocks dictionary is running and
fragmented/virtual remain queued. Evidence:
`classical-native-validation/columns-fresh21/goldilocks-polyfrim-control-compatibility.json`.
This is correctness evidence only; security and performance remain unqualified.


Both fragmented helper field tests passed without warnings in 685.32s (four v5
field/backend combinations). All ordered helper lane, degree-two bridge, scalar
compression, rolling fold and index requests use helper-role geometry and
replay against raw SHAKE and the public transcript primitive. Source-role bridge
dimension substitution and missing phase receipts fail; own-parent-view origin
checks remain enabled. Frozen source and binary hashes bind this result to its
pre-source-obligation revision. Evidence:
`classical-lookup-helper-fragment-tests-final.log` and
`opening-inventory/classical-lookup-helper-fragment-sampling-audit.json`.

The next parent boundary derives original-source used slots, trusted parameter
contexts, alias consistency, normalized claim order and the final count seal
after all helper handoffs. Its initial focused Brakedown field tests passed
without warnings in 46.05s; independent raw bytes match the actual production
source-claim registration on an isolated public transcript. Duplicate claim
blocks and altered count seals fail. Evidence:
`classical-lookup-source-obligations-focused-tests.log` and
`opening-inventory/classical-lookup-source-obligations-initial-audit.json`.
Explicit consistent/conflicting alias fixtures and context-substitution checks
are under validation on a later revision. These tests do not authenticate source
or helper words and do not establish complete lookup acceptance, native geometry
coverage, security admission or performance qualification.


Both full direct/dictionary helper-sampling field audits passed without warnings
in 1399.14s (20 baseline combinations, 18 helper-stage sequences, eight
direct/dictionary helper combinations across v4/v5). Consistency indices, joint
projection weights, rolling folds and final indices use the helper role. Frozen
source/binary evidence: `classical-lookup-helper-direct-sampling-tests.log` and
`opening-inventory/classical-lookup-helper-direct-sampling-audit.json`.

The final focused source-obligation field tests passed without warnings in
44.84s. Consistent aliases suppress later slots in original registry order, and
both ordinary and aliased claim bytes match actual production registration.
Conflicting alias values are rejected independently and by production; trusted
context substitution, duplicate claim blocks and altered count seals fail.
Evidence: `classical-lookup-source-obligations-final-focused-tests.log` and
`opening-inventory/classical-lookup-source-obligations-focused-audit.json`.
The combined revision's two full field regression tests are running in
`classical-lookup-source-obligations-full-tests.log` (session 67225); source
snapshots and hashes are preserved under `opening-inventory/lookup-source-obligations-*`.
Its full result is pending. Helper/source word authentication, complete native
geometry coverage, second-decomposition/later-stage coupling, security admission
and matched performance qualification remain unfinished.


Extended original-source claim registration into every ordered PCS handoff after
the first lookup. A LookupSource task retains the original registry slot and
trusted digit count, selecting coefficient/borrow parameters by slot. Sources,
normalized queries and values come from the closed lookup and alias-checked
claim sequence. Direct/dictionary and fragmented/virtual typed children require
their own frozen parent views and matching seed/label/context, and route through
the existing source-role samplers. Source roots cannot be replaced; missing
seeds or an ancestor finish producer absent from the original parent view are
rejected by the fixtures. Their runtime results are still pending.
Brakedown uses the production batch grammar even for its one claim per source:
batched metadata, batch row request/receipt, one bounded evaluation row, and
atomic columns. Substituting single-opening metadata, flat evaluation responses
or removing the current row receipt fails. Both focused Brakedown field tests
passed without warnings in 137.90s. Evidence:
`classical-lookup-source-openings-focused-tests.log` and
`opening-inventory/classical-lookup-source-openings-focused-audit.json`.
The new two-field full regression is running in
`classical-lookup-source-openings-tests.log` (session 25080, captured PID 2759321).
Both source snapshots and the live binary fingerprint are preserved under
`opening-inventory/lookup-source-openings-*`. The earlier source-obligation
revision continues its separate full regression (session 67225, PID 2758529);
it is not restarted or treated as evidence for the later opening implementation.
These tests do not establish helper/source word authentication or complete
accepted lookup certificates. Later protocol stages, native geometry coverage,
security admission and matched performance qualification remain open.


Extended the ordered prefix past the first lookup's complete source-opening
framing into the second decomposition. Shared binding/body helpers preserve
the original first-half bytes and derive the second half only at its fixed
parent position. The second task uses input[1], coefficient roots[d..2d], the
trusted borrow/helper contexts and all three normalized linear relations.
Every independent linear challenge round replays prior canonical receipts.
First-half binding substitution, duplicate stage bindings and missing earlier
receipts fail. Both focused Brakedown v5 field fixtures passed without warnings
in 179.33s. The isolated actual production decomposition verifier reaches the
same post-linear transcript continuation for both halves; its absent PCS proof
is deliberately rejected and is not acceptance evidence. Evidence:
`classical-second-decomposition-linear-focused-tests.log` and
`opening-inventory/classical-second-decomposition-linear-focused-audit.json`.
The combined revision's full all-backend/v4-v5 regression is running in
`classical-second-decomposition-linear-full-tests.log` (session 18787,
PID 2759975). Frozen sources and the live binary hash are preserved under
`opening-inventory/second-decomposition-linear-*`.
The earlier source-obligation and source-opening regressions remain separately
active on their frozen revisions (sessions 67225 and 25080). The first lookup's
helper/source word authentication, second-decomposition PCS/lookup phases,
accumulator/monomial/final-stage coupling, complete native geometry coverage,
full security admission and matched performance qualification remain open.


The second decomposition now shares the ordered PCS body parser with the first,
while retaining a distinct SecondDecomposition task family. Its fixed linear
origin selects input 1 and the second coefficient range; every source opening
uses the trusted input/coefficient/borrow parameters. Brakedown response/index
parsing is shared after the separate fixed origins. Direct/dictionary and
fragmented/virtual sampler dispatchers retain the second-stage family and
selected source index. The generalized fixture preserves ancestor views for
second-stage children, tests changed roots and missing seeds/receipts, and
requires all three linear relations at completed opening framing. Compilation
and rustfmt/diff checks pass; runtime results remain pending in
`classical-second-decomposition-pcs-focused-tests.log` and
`classical-second-decomposition-pcs-full-tests.log` (full session 79243,
PID 2760751). Frozen sources and the binary fingerprint are under
`opening-inventory/second-decomposition-pcs-*`.
The native stage inventory already includes both halves through
`2*(2*d+2)` linear calls and at most `2*(2*d+1)` lookup-source calls; no count
correction was needed. These are conditional source/sampling fixtures, not
accepted PCS or decomposition certificates. Second-stage lookup, word
authentication, later stages, native coverage, security admission and matched
performance qualification remain open.


Both focused second-decomposition PCS field tests passed without warnings in
349.33s on their preserved revision. Every ordered source handoff is tied to the
second linear origin and its parameter role, query, value and root. Brakedown
row receipts, nonzero responses and column requests are replayed; changed roots,
missing receipts, malformed/trailing requests and oversized responses fail.
Completed opening framing checks all three linear relations. Evidence:
`classical-second-decomposition-pcs-focused-tests.log` and
`opening-inventory/classical-second-decomposition-pcs-focused-audit.json`.
The child-backend/full regression remains active and is not claimed complete.

Added a separate second-lookup seed/child/challenge compiler anchored after
completed second-decomposition PCS framing. Both stages share bounded
multiplicity/metadata parsing, while their child origins remain separate.
The new fixture checks every request/repetition tuple hash and naturally
accepted reciprocal draw against raw SHAKE/public-primitive replay without a
retry cutoff. It also checks changed registry roots, oversized multiplicity
counts, missing seeds, first-stage child reinterpretation and ancestor-producer
absence in the child's own frozen parent view. Compilation/runtime validation
is pending in `classical-second-decomposition-lookup-compression-focused-tests.log`.
This does not establish second-lookup equality/batch/terminal/PCS verification,
word authentication, native coverage, security admission or performance gates.


Both focused second-lookup compression field tests passed without warnings in
345.64s on the preserved compression revision. They bind the registry to the
completed second decomposition, check bounded multiplicities and every hash and
naturally accepted reciprocal request against raw SHAKE/public primitive replay,
and reject changed roots, oversized counts, missing seeds, first-stage child
reinterpretation and absent ancestor producers in the child's own parent view.
No retry cutoff was added. Forced zero/pole retries are covered by the existing
shared walker tests, not by a new forced second-stage fixture. Evidence:
`classical-second-decomposition-lookup-compression-focused-tests.log` and
`opening-inventory/classical-second-lookup-compression-focused-audit.json`.

Factored the existing complete lookup algebra fixture so both strictly anchored
lookup children share equality, batch-sumcheck and terminal checks. The existing
first-stage algebra checks are retained. The second stage now runs those same
raw-replay and production-observer checks, including bounded helper roots and
points, all message degrees/recurrences, terminal identities, source/helper
mutations and oversized packets. A shared parent-finish parser checks seed and
finish hashes, exact child origin and the child's own frozen finish view. The
second parent entry remains fixed after second-stage PCS/lookup metadata; missing
finish producers/views and altered digests are rejected by the new fixture.
The combined revision compiled without warnings in 59.57s and passes rustfmt and
diff checks. Runtime results remain pending in
`classical-second-decomposition-lookup-terminal-focused-tests.log` (session
68192, PID 2762556) and `classical-second-decomposition-lookup-terminal-full-tests.log`
(session 65896, PID 2762678). Frozen sources and the live executable fingerprint
are under `opening-inventory/second-lookup-terminal-*`.

Full runs 25080, 18787, 79243 and 35726 were intentionally superseded by that
combined full regression. Their exact process/binary identities were verified
before SIGTERM; terminal logs and Cargo exit 101 were recorded in the respective
`*-full-cancelled.json` artifacts. They are cancellations, not assertion-failure
or passing evidence. The intermediate algebra-only compilation was interrupted
with exit 130 before validating the final finish-parser revision. The original
source-obligation baseline remains active (67225/PID 2758529; BabyBear passed,
Goldilocks pending), and the native driver continues independently. Second-lookup
helper/source PCS, all word authentication, later stages, native geometry
coverage, full security admission and matched performance qualification remain
open. Terminal fixtures still use full logical domains and one repetition; no
complete accepted lookup certificate is asserted.


The frozen source-obligation full audit completed both fields without warnings
in 2331.39s (20 backend/schedule baselines, 18 later-stage sequences; v4 Brakedown
later stages excluded). This covers all four first-lookup child helper sampler
families and source claim/alias/seal interpretation across the tested schedules.
Evidence: `classical-lookup-source-obligations-full-tests.log` and
`opening-inventory/classical-lookup-source-obligations-full-audit.json`.
It does not assert original-source PCS sampling or word authentication.

Both focused second-lookup algebra/finish field tests passed without warnings
in 461.74s. The shared algebra fixture checks helper roots/equality points,
all scalar-batch rounds and recurrences, terminal identities against the actual
production observer, source/helper mutations and oversized metadata. The second
parent return checks the finish hash, exact origin and own frozen finish view;
missing producer/view and altered digest cases fail. Evidence:
`classical-second-decomposition-lookup-terminal-focused-tests.log` and
`opening-inventory/classical-second-lookup-terminal-focused-audit.json`.

Extended both lookups' PCS compilers through fixed stage selectors. Distinct
SecondLookupHelper and SecondLookupSource families preserve the second parent
origin; helpers select role one, and source tasks preserve original slots and
coefficient/borrow parameters under role zero. The two stages share bounded
helper completion, alias-checked source claims/seals, Brakedown batch geometry
and child-source sampler bodies. The generalized fixtures retain all ancestor
views, reject first-stage reinterpretation of second-stage children and run
through all ordered helper/source openings. The second source sequence ends
without recursively entering another decomposition. Five unused compatibility
wrappers were removed after a warned intermediate compilation was interrupted
with exit 130. The cleaned revision compiled without warnings in 1m00s and
passes rustfmt/diff checks. Runtime results remain pending in
`classical-second-lookup-pcs-final-focused-tests.log` (session 26528,
PID 2763636) and `classical-second-lookup-pcs-full-tests.log` (session 82036,
PID 2763769). Frozen source and executable fingerprints are under
`opening-inventory/second-lookup-pcs-*`.
The superseded terminal-only full run 65896 was intentionally stopped with
SIGTERM/Cargo 101 and recorded in `second-lookup-terminal-full-cancelled.json`;
its focused passing evidence remains independently recorded. Native validation
continues separately. These n=32/LWE=21 prefixes use two selected extensions and
are not accepted lookup/decomposition certificates or complete native coverage.
Word authentication, accumulator/monomial/final-stage coupling, security
admission and matched performance qualification remain open.


Both focused lookup helper/source PCS field tests passed without warnings in
1608.74s on their frozen revision. They cover both stages' ordered helper and
original-source handoffs, Brakedown row/column sampling, source role/slot
selection, production-matched alias/seal bytes, first-stage reinterpretation,
changed roots, missing receipts and late ancestor-repair rejection. Evidence:
`classical-second-lookup-pcs-final-focused-tests.log` and
`opening-inventory/classical-second-lookup-pcs-focused-audit.json`.
Child-backend runtime coverage and word authentication remain unestablished.

Added the accumulator's fixed source binding after the completed second-lookup
source sequence: four accumulator roots, co[2*d], then input[0]/input[1]. The
public initial accumulator is derived from the original normalized statement;
the final endpoint comes from the outer binding. Geometry, all source contexts
and the exact accumulator domain are checked before independent lane phases.
Every base round replays earlier receipts. Query maps independently derive the
initial/final row selectors, disjoint increment/carry/wrap branches with ordered
noncommuting products, duplicated halves and all seven trusted query counts.
The isolated production observer agrees byte-for-byte on challenges and maps.
Ordered-prefix fixtures reject swapped input roots, altered endpoints, malformed
requests and missing receipts; their runtime result is pending.

The isolated geometry suite passed both field tests in 8.83s; an independent
record audit verified the entire expected Cartesian set: 300 valid profiles
(150 n=32/LWE=21, 150 n=1024/LWE=728) and 20 expected Goldilocks-degree-5/width-4
packing rejections. This covers all eight extensions, planned packing widths,
five backends and v4/v5, with fixed blowup 2, fragment cap 8 and Q=8. These are
synthetic endpoint/root query-map checks, not accepted native proofs or complete
native protocol coverage. Evidence:
`classical-accumulator-query-geometries-final-tests.log` and
`opening-inventory/classical-accumulator-query-geometries-audit.json`.
An initial build used two nonexistent extension alias names; they were corrected
to the repository's existing aliases before the passing build.

Repeated prefix replay now memoizes only pure lookup-equation outputs, keyed by
both field types, variable count, complete requests/multiplicities and accepted
hash/reciprocal tuples. Every history, source, producer, receipt and acceptance
check still executes. The thread-local cache retains at most 64 entries and
clears on overflow; this changes work only and adds no attacker-query cutoff.
The original uncached calculation remains the reference. Its all-eight-field
mutation/eviction test passed without warnings (1 test, 0.03s), covering changed
multiplicity, hash, reciprocal, request configuration and variable count, plus
70 distinct entries per field. The cached revision re-passed the same 320
geometry records. Evidence: `classical-lookup-equation-cache-tests.log`,
`opening-inventory/classical-lookup-equation-cache-audit.json`, and
`opening-inventory/classical-accumulator-query-geometries-cached-audit.json`.
No production code or production-performance qualification changed.

The latest accumulator-entry focused/full tests are active in
`classical-accumulator-entry-cached-focused-tests.log` (18650/PID 2766341) and
`classical-accumulator-entry-full-tests.log` (10526/PID 2766385). Frozen three-file
sources and the executable hash are under `opening-inventory/accumulator-cached-*`.
The superseded full lookup-PCS run 82036 and uncached focused accumulator run
98311 were intentionally cancelled with SIGTERM/Cargo 101; cancellation evidence
is recorded in their `*-superseded-cancelled.json` files. An initial accumulator
entry run 76156 was also superseded before completion; none is passing evidence.
Native validation remains 147/210 independently audited proofs; the live
Goldilocks dictionary partial group is excluded until completion. Accumulator
arithmetic and PCS, monomial/final-stage coupling, all word authentication,
complete native coverage, security admission and matched performance gates
remain open.

### Accumulator opening collector validation

The current source snapshot is recorded in
`target/performance/opening-inventory/accumulator-openings-source-manifest.json`.
The isolated arithmetic rerun matches all 320 geometry records from the previous
arithmetic revision: 300 valid configurations and 20 expected packing rejections.
`classical-accumulator-openings-arithmetic-audit.json` binds this result to the
current three source hashes and log hash. The independently completed entry
regression took 1887.93 seconds and passed both fields on its older frozen
revision; it does not establish success for the newer opening collector.

The collector compiles exact ordered source/query/value metadata and accepts
completion only after all seven claim groups satisfy the independent arithmetic
predicate. Earlier PCS completion bodies remain conditional obligations.
Current focused/full process identities and executable hash are recorded in
`accumulator-openings-tests-running.json`; this is a running-state capture,
not a passing result. The superseded entry full run has a terminal SIGTERM
record in `accumulator-entry-full-cancelled.json` and is not counted as passed.

The v5 Goldilocks dictionary fresh group independently passes all 21 native
proof records, descriptor v5/Q1 checks, frozen executable/log fingerprints, and
field-control statement/key/parameter identities. The audited v5 total is now
168/210; fragmented and virtual groups remain outstanding.

### Accumulator direct consistency implementation

The next revision extracts the role-zero direct/dictionary batch consistency
grammar from the NTT audit and reuses it for accumulator child tasks recovered
from their own frozen parent views. Its fixtures cover every ordered claim
in all seven source groups, changed consistency values and out-of-range member
indices. Compilation succeeds without warnings; the full ordered-prefix and
isolated arithmetic regressions have started. No passing runtime result for
this revision is asserted.
Source snapshots are recorded by `accumulator-direct-source-manifest.json`.
Projection/rolling phases and committed-word authentication remain unfinished.
Earlier collector regressions continue on their original frozen executable.

The direct-consistency revision also passes the isolated accumulator arithmetic
regression (2 tests, 300 valid geometries and 20 expected packing rejections).
This checks the arithmetic/map code only; the new child parser remains under
full ordered-prefix runtime validation.

### Accumulator projection and rolling implementation

The next revision shares the direct batch projection suffix with the NTT audit
and binds accumulator projection cardinality to the selected source's actual
query group. It reuses the role-zero rolling parser for projection receipts,
virtual layer identities, fold challenges and derived-root framing, and adds
terminal scalar/final index-request parsing. Per-source fixtures check all
folds, missing receipts, changed request framing and exact end of input.
Compilation passes without warnings and full runtime validation has started.
This is sampler interpretation;
earlier completions remain conditional and committed-word acceptance is open.
The snapshot is `accumulator-rolling-source-manifest.json`.

### Accumulator fragmented bridge implementation

The next source revision shares a bounded multi-claim bridge kernel with the
NTT audit. Each accumulator fragmented/virtual child derives its projection
count from the exact selected source query group times packing width, replays
all extension coefficients, and checks every quadratic sumcheck round against
the projected claim. Fixtures cover all seven sources, nonzero claim groups,
missing producers, changed round messages, invalid round numbers and trailing
input. Compilation passes without warnings; full ordered-prefix runtime validation
has started. Scalar PCS contexts, scalar
rolling/source-query phases and word authentication remain unfinished.
The snapshot is `accumulator-fragment-bridge-source-manifest.json`.

### Accumulator scalar PCS gamma implementation

The next revision shares scalar mode/source/point binding and bounded fragment
parsing with the NTT sampler audit. Accumulator fragmented/virtual tasks replay
the final bridge challenge from its recorded producer and check fragment
evaluation at the full bridge point before the gamma request. Fixtures compare
with a Boolean-basis evaluation and reject changed source roots, inconsistent
fragments, oversized fragment counts, missing receipts and trailing input.
Compilation passes without warnings; full runtime validation has started.
Scalar rolling/source-query phases,
the final bridge-to-word identity and committed-word authentication remain
unfinished. Snapshot: `accumulator-scalar-gamma-source-manifest.json`.

### Accumulator scalar rolling implementation

The next revision binds accumulator scalar tasks to the existing independent
rolling-data parser, including gamma receipt, public fold ladders, the
source/point/gamma-derived virtual initial identity, all fold challenges and
numbered derived roots. It parses the canonical terminal scalar and final
rolling/source-consistency index requests. Per-source fixtures check replayed
indices, missing receipts, wrong layer numbers, changed requests and trailing
input. Compilation passes without warnings; full runtime validation has started.
These are sampler obligations;
source-word authentication and the final bridge-to-word identity are open.
Snapshot: `accumulator-scalar-rolling-source-manifest.json`.

### Accumulator terminal kernel implementation

A separate necessary terminal predicate now compares the bridge expectation
with the scalar PCS value times the public matrix kernel. It evaluates the
kernel by forward matrix/column products, independently of production's reverse
row multiplication. The predicate remains separate from earlier gamma request
interpretation, because the production verifier checks it after scalar PCS
verification. Accumulator fixtures exercise the equation with consistent and
changed scalar values, separately from fragment parsing. A focused test uses
explicit Boolean row/lane enumeration, noncommuting matrices, full extension
coefficients and malformed dimensions across all eight extension fields.
The focused exhaustive kernel test passes across all eight extensions, with
warning-free compilation. Full ordered-prefix validation has started.
Authentication of the scalar PCS
word and coupling the predicate to completed accepted openings remain open.
Snapshot: `accumulator-terminal-kernel-source-manifest.json`.

### Accumulator assigned-word coupling

The accumulator audit now evaluates every source query map against a supplied
word assignment keyed by exact context/root identity. It rejects missing words,
wrong context and wrong table geometry, and uses each source's normalization.
A nonzero active-round recurrence fixture constructs all seven source tables
under the existing initial/final endpoints and compares the resulting values
with both independent and production arithmetic checks. Missing assignments,
malformed tables and a changed input word are negative cases. This runs on the
toy half of the existing geometry matrix; native map/arithmetic coverage remains
separate. The geometry suite passes both tests, including 150 toy assigned-word
cases and 150 native map/arithmetic cases, plus 20 expected packing rejections.
This compiler consumes assignments: it does
not authenticate them or complete a Merkle decoder. Snapshot:
`accumulator-assigned-words-source-manifest.json`.

The final assigned-word source revision also passes the exhaustive terminal
kernel test across all eight extension fields. Its executable fingerprint is
identical to the passing assigned-word geometry run, so both results bind the
same binary. Companion evidence:
`classical-accumulator-assigned-words-terminal-audit.json`. The initial observer
call/import compilation errors are recorded separately and are not counted as
test results. Earlier ordered-prefix regressions continue on their frozen
revisions; no passing result for those jobs is asserted here.

### Shared frozen-word decoding support

The Brakedown, direct PolyFRIM and fragmented word-assignment routines have
been moved without changing their decoding rules into
`pcs/tests/support/classical_assignment.rs`. The existing all-field word-history
test consumes this shared implementation. Its Brakedown completion now accepts
an explicit frozen preimage map, verifies every available internal/leaf
preimage against SHA-512 and parses canonical whole-column leaves with trusted
geometry; missing/malformed/hash-inconsistent paths receive the fixed zero
column. First-declaration timing remains the caller's responsibility. A new
negative case tampers with a frozen root preimage. The all-field history suite
passes with warning-free compilation, including both Brakedown fields and all
eight extension configurations for direct/fragmented assignments. Evidence:
`classical-shared-frozen-word-audit.json`. Accumulator consumption of this shared decoder is the next coupling
step; no full authentication or security admission is claimed. Snapshot:
`shared-frozen-word-source-manifest.json`.

### Accumulator frozen Brakedown word consumption

The accumulator audit now consumes explicit frozen preimage views under each
expected context/root identity. Trusted profile geometry determines canonical
whole-column completion and joint RS assignment, then the existing assignment
evaluator computes all seven source query groups. A focused fixture reconstructs
production Brakedown commitment roots from independently encoded leaves and
parent preimages, decodes a nonzero accumulator recurrence and checks its
arithmetic. It covers both base fields and v4/v5 schedules, with missing-view
and corrupted-root negative cases. The focused test passes all four field/
schedule cases with warning-free compilation. Evidence:
`classical-accumulator-frozen-brakedown-audit.json`.
The caller still supplies first-declaration snapshots; nearness promises and
fixed zero completions do not imply whole-protocol authentication. Direct and
fragmented decoder consumption remain open. Snapshot:
`accumulator-frozen-brakedown-final-source-manifest.json`.

### Frozen decoder trusted-geometry preflight

The Brakedown accumulator consumer now reconstructs the complete expected
parameter context from the trusted profile, rather than only comparing source
contexts with caller-supplied parameters. It checks all seven contexts and
query-map dimensions before requesting any frozen word view. Regression cases
change row split, block width, actual code domain, query count and variable
count, plus a final-source context, source count and base dimension. Every
mismatch must reject with zero view callbacks. Nominal blowups that produce
the same minimum-32 RS domain are not distinct word geometries; the domain
substitution case uses a factor that actually changes the code domain.
The focused test passes four field/schedule cases and all 32 preflight
mutations, each with zero view callbacks. Evidence:
`classical-accumulator-frozen-geometry-audit.json`. This is an analysis-audit trust-boundary fix,
with no production/default/wire change or security admission. Snapshot:
`accumulator-frozen-geometry-source-manifest.json`.

### Frozen direct/dictionary word consumption

Shared completion now verifies direct PolyFRIM source leaves against the frozen
Merkle view and the exact parameters, layer zero, index and canonical pair
width, preserving +/- pair order. The all-field history suite passes across
all eight extension fields, including logical-variable zero and three cases,
wrong-parameter/hash-inconsistent zero completion and malformed domains.
Evidence: `classical-frozen-polyfrim-symbol-audit.json`.

The accumulator direct/dictionary consumer reconstructs trusted role contexts,
preflights all seven sources, derives the coset points and joint-nearness
radius from profile geometry, and feeds decoded words into exact query-map
evaluation. New fixtures compare independently rebuilt Merkle roots with
production commitments and check a nonzero recurrence, missing views and a
corrupted root across both fields, schedules and backends. The focused test
passes all eight field/schedule/backend cases, including 56 production-root
comparisons, with warning-free compilation. Evidence:
`classical-accumulator-frozen-polyfrim-audit.json`. Snapshot: `accumulator-frozen-polyfrim-canonical-source-manifest.json`.
First-declaration timing and the full authentication/reduction remain open.

The initial independent PolyFRIM root fixture failed because raw Horner results
were serialized before field canonicalization. Production already canonicalizes
encoded values before hashing leaves. The corrected fixture canonicalizes its
independent evaluations; its focused validation passes all eight cases. The failed run is retained
separately in `accumulator-frozen-polyfrim-initial-fixture-failure.json`.

### Frozen source-alias assignment stability

Brakedown and direct/dictionary accumulator consumers now request a word view
and decode it once per exact context/root identity within one invocation.
Repeated source slots reuse that assignment and nearness result while retaining
each slot's ordered query maps and output values. They cannot overwrite the
assignment by triggering a later callback for the same alias. Both small
production-root fixtures contain real aliases and now fail on a repeated view
lookup; promise vectors must still contain all seven slots. Both focused tests
pass all 12 field/schedule/backend cases with warning-free compilation. Evidence:
`classical-accumulator-frozen-alias-audit.json`. This does not bind snapshots across separate consumer invocations or
complete first-declaration history coupling. Snapshot:
`accumulator-frozen-alias-source-manifest.json`.

### Frozen fragmented packed-source consumption

The shared parser now verifies packed-fragment leaves against the actual
source root, scalar parameter context, pair index and canonical fragment
count, preserving +/- symbols. The all-field history suite passes both source
configurations across all eight extensions, including context substitution,
corrupted preimages and malformed geometry. Evidence:
`classical-frozen-fragment-symbol-audit.json`. Virtual protocol identifiers
remain distinct from these actual source roots.

The accumulator ordinary/virtual fragmented consumer reconstructs expected
role contexts, preflights all seven sources, decodes frozen packed words and
reuses exact source aliases before query evaluation. Small fixtures record
production SHA-512 preimages (including Rayon parent hashes), compare recorder
roots with standard commitments and test nonzero recurrence, missing views and
corrupted roots. The focused test passes all eight fragmented cases, and the
combined three-test run passes all 20 field/schedule/backend cases across all
five families, with warning-free compilation. Evidence:
`classical-accumulator-frozen-fragment-audit.json` and
`classical-accumulator-frozen-all-backends-audit.json`. Snapshot:
`accumulator-frozen-fragment-source-manifest.json`. Global first-declaration
history binding and the authentication/reduction argument remain open.

The older accumulator opening-collector focused regression has independently
completed both fields in 3335.18 seconds. It is bound to its earlier frozen
source/executable in `classical-accumulator-openings-focused-audit.json`; it
does not establish success of newer decoder revisions or word authentication.

### All-decoder trusted-profile substitution regression

The direct/dictionary and ordinary/virtual fragmented accumulator fixtures now
exercise substituted query counts, blowup, variable counts, packing widths and
backend families. Each must reject before any frozen-view callback, rather than
merely returning failure after attempting a lookup. Together with the existing
Brakedown preflight cases, the combined run covers all five consumer families.
The combined three-test run passes all 20 field/schedule/backend cases and
112 preflight mutations with warning-free compilation. Evidence:
`classical-accumulator-all-decoder-preflight-audit.json`. Snapshot:
`accumulator-all-decoder-preflight-source-manifest.json`. This tests private
analysis consumers and does not complete global first-declaration history
binding, native geometry coverage, security admission or performance gates.

### Shared first-declaration registry and accumulator invocation binding

The existing analysis history has moved to shared test support with private
state, read-only diagnostics and immutable `view(root)` access. It retains
pre-answer SHA/XOF input-window declaration and first-snapshot semantics; input
length filters remain selectors, never attacker-query cutoffs. The original
word-history test now checks pointer identity and absent late preimages through
this interface.

All accumulator word-consumer fixtures now obtain positive views from this
registry after topological replay of their real Merkle graphs. New cases
declare source roots before graph exposure, decode once, expose the graphs,
redeclare and decode again. Values and snapshot identities must remain fixed,
late exposure must register availability hits, and the resulting zero completion
must not satisfy the nonzero public endpoint recurrence. The all-field PCS
history test and all three accumulator consumer tests pass, covering 20
field/schedule/backend cases, with warning-free compilation. Evidence:
`classical-shared-first-declaration-history-audit.json` and
`classical-accumulator-first-declaration-history-audit.json`.
These are synthetic legal oracle histories, not full production verifier event
traces or a complete adaptive reduction. Snapshot:
`accumulator-first-declaration-source-manifest.json`.

### Opt-in production SHAKE-input observation

The helper `transcript-audit` feature now records exact absorbed input bytes
and reports each SHAKE request before creating its output reader. It includes
field-receipt fingerprints, parent checkpoints and child transcripts. Thread-local
registration attaches an observer to roots created in its scope; child states
and field-receipt hashes inherit it across worker moves. Guards stay on their
registering thread and disable future observations from retained descendants
on drop. Input tracking and callbacks are compiled out
without the feature; the snarks feature forwards it explicitly.

The observer integration test passes an independent SHAKE-output check and
compares parent/child/prime/extension/index results with observation on and off.
All 32 helper unit tests pass with the feature disabled and enabled. This is
production-path observation plumbing, not full verifier event capture or a
security theorem. The snarks opt-in library build check also passes without
warnings. Evidence: `classical-transcript-observer-audit.json`. Snapshot:
`classical-transcript-observer-source-manifest.json`.

### Production accumulator Hash/XOF event capture

A feature-gated fixture now sends generic PCS SHA-512 inputs/results and
pre-answer transcript SHAKE inputs to one ordered history during actual
commitment, proving and production accumulator verification. It records verifier
phase boundaries, replays the complete captured log into a second registry and
compares source snapshots, counters and decoded claims with the accepted proof.
It also verifies the proof with observation disabled and compares transcript
continuations. Planned coverage is both representative fields, v4/v5 and all
five backend families at small dimensions. The focused test passes all 20
cases with warning-free compilation, zero availability hits in these honest
fixtures, matching replayed source views/proof claims and matching unobserved
verifier continuations. Evidence:
`classical-production-accumulator-event-audit.json`.

This captures the production accumulator stage's generic PCS and transcript
oracle interfaces; it does not capture a complete encrypted PBS execution or
claim that every direct SHA-512 call outside these interfaces has been observed.
Snapshot: `production-accumulator-event-source-manifest.json`.

The v5 Goldilocks fragmented fresh group independently passes all 21 native
records, v5/Q1 descriptors, frozen binary/log fingerprints and field-control
key/parameter/statement identities. The audited v5 total is 189/210; the virtual
group remains outstanding. These are correctness profiles, not admission or
performance evidence.

### Observer isolation before complete-PBS capture

The initial process-wide registration could include unrelated concurrent
transcripts. Registration is now local to the creating thread, with an inherited
observer token on root/child states and fresh receipt hashes. Children created
on a worker retain the parent's observer. Dropping the owner-thread guard
disables future calls from existing descendants. Tests cover worker-side forks
and receipts, unrelated roots, independent observers on separate threads, guard
drop and unchanged output bytes. Both 32-test helper suites and the integration
test pass; the actual 20-case accumulator trace is rerunning. Snapshot:
`thread-scoped-transcript-source-manifest.json`.

### Streamed complete-protocol oracle controls

The feature-gated fixture now exercises complete protocol-12 control
certificates with synthetic evaluation keys at n=32/LWE=21. It captures generic
PCS SHA-512 and transcript SHAKE interfaces across setup, proving and strict
complete verification, then decodes the serialized proof and verifies it through
the standard SHA-512/profile facade against independently preprocessed setup.
All input records stream to exclusive versioned binary files, with per-phase
counts, byte totals, maxima and a SHA-512 fingerprint. No full window/history
registry is retained in memory for this run. Direct primitive calls outside
the instrumented interfaces remain outside its capture scope.

`tools/audit_classical_oracle_event_stream.py` independently streams each file,
checks all primitive SHA-512 preimages, framing, monotone phases and the reported
fingerprint. Four parser tests pass, including truncation, corruption and huge
declared lengths without proportional allocation. Initial complete controls
and independent file audits pass; the 20-case run remains live. Snapshot:
`complete-pbs-event-stream-source-manifest.json`. These are not encrypted native
controls, a first-declaration replay of the complete protocol, security admission
or matched performance measurements.

The revised thread-scoped accumulator trace independently passes all 20 cases
and reproduces every prior per-case event summary. Evidence:
`classical-thread-scoped-accumulator-event-audit.json`.

### Complete-protocol stream audit: first ten controls

All ten BabyBear/degree-6 complete-protocol controls (v4 and v5, each across
Brakedown, direct PolyFRIM, dictionary PolyFRIM, fragmented PipFRI and its
virtual variant) have independently audited event files. The streaming auditor
checks every recorded SHA-512 preimage/output pair and whole-file fingerprint;
all six verifier count/length statistics exactly match the emitted control row.
Evidence: `complete-pbs-event-stream-progress-10-controls.json` and the ten
per-trace `.audit.json` files. The complete 20-case process remains live, so
this is partial coverage, not an overall test pass. Goldilocks native v5 virtual
validation also remains live; its first six records have been emitted, but its
21-record group has not passed the terminal compatibility audit. The native
audited total remains 189/210. Full adaptive security admission and matched
performance qualification remain open.

### Reproducible complete-control counter audit

The stream auditor accepts `--control-log LOG --output REPORT` to recompute
all completed control traces and compare all six verifier query/length counters.
It rejects duplicate field/degree/version/backend identities, mismatched counts
and boolean counters, and ignores an unfinished final row in a live log. A report
explicitly does not establish suite completion or security/performance admission.
All five unit tests pass, including mutation of each reported counter and live-log
truncation. Source snapshot: `complete-pbs-control-log-auditor-source-manifest.json`.
The original single-trace audit interface remains available.

The first real control-log recomputation exits successfully for all 10
completed controls, independently processing 3101774 events. Evidence:
`complete-pbs-control-log-recomputed-audit.json`. The underlying suite remains
in progress.

### Independent monomial entry binding (validation pending)

A test-only monomial entry interpreter derives the public rotation plan from the
statement, uses the fixed accumulator source slots 0 and 1 with their trusted
contexts, and reconstructs the exact production binding frame. It also recovers
these source slots from the outer binding without claiming prior-stage
acceptance. The targeted fixture compares a production transcript challenge
with an independent framed-SHAKE reconstruction and checks ordered roots,
root aliasing, source count and malformed public dimensions. It covers both
representative fields, both schedules, all five backends and small/native
geometry (40 cases planned). Compilation/test remains in progress; no passing
result is yet claimed. Snapshot: `classical-monomial-entry-source-manifest.json`.
The later monomial NTT/product/opening interpretation and final key switching
remain required work.

The final monomial-entry source revision passes all 40 cases (one test,
zero failures). Independent production-binder replay and negative checks pass
at n32/LWE21 and n1024/LWE728. Evidence:
`classical-monomial-entry-passed-audit.json`. Prior-stage acceptance and the
remaining monomial/final-stage security obligations remain open.

### Independent public monomial factor (validation pending)

A separate test-only evaluator explicitly computes signed negacyclic monomial
values at every bit-reversed NTT point, retains padded zero rows and both
ciphertext halves, and contracts the matrix queries by dense entry arithmetic
in Boolean-variable order. It uses neither the production transform nor the
closed-form evaluator. The targeted test compares both production paths at
n32/n1024 and widths2/8 for both primes, and tests changed rotations, reversed
noncommuting query order and malformed query/width shapes. Its compile/test
remains live. Snapshot: `classical-monomial-public-factor-source-manifest.json`.
This validates a public factor only; it does not establish accepted source
openings, monomial sumcheck soundness or final-stage admission.

The independent public-factor fixture passes all eight cases (two primes,
n32/n1024, widths2/8), including signed rotations, zero-padded rows, exact
production table/closed-form equality, noncommuting query order and malformed
shape checks. Evidence: `classical-monomial-public-factor-passed-audit.json`.

### Independent monomial terminal identity (validation pending)

The next test-only fixture obtains genuine packed ZeroCheck subclaims for the
monomial product and checks `(input * public_factor - output) * equality ==
expected` lane by lane, using the independent public-factor evaluator. It compares
changed expected/source values with the production terminal check and rejects
malformed source/query/equality dimensions. Both schedules, both primes and
widths2/8 are exercised. Its compile/test remains live; it creates no source
opening authentication and does not establish full security admission. Snapshot:
`classical-monomial-terminal-source-manifest.json`.

The monomial terminal fixture passes all eight cases (both primes, widths2/8,
v4/v5), including genuine sumcheck subclaims and mutation comparisons with the
production terminal check. Evidence: `classical-monomial-terminal-passed-audit.json`.

### Monomial frozen-word consumer (validation pending)

A test-only consumer now decodes the monomial's two evaluation words using the
shared Brakedown, direct/dictionary PolyFRIM and fragmented/virtual source-word
decoders. It validates field/basis, factory-derived context, both source
contexts and query geometry before requesting a frozen view; exact context/root
aliases share one decoded assignment. The existing authenticated-word/history
fixtures exercise distinct and aliased pairs and compare their assigned query
values with the original tables. Their updated three-test/20-case run is live.
Snapshot: `classical-monomial-frozen-word-source-manifest.json`. This consumer
requires caller-supplied first-declaration views; it does not establish accepted
PCS opening coupling, full native coverage or security admission.

The first two Goldilocks v4 controls (Brakedown and direct PolyFRIM) also
pass independent stream audits, including all verifier counters. The total is
12/20 independently audited complete-protocol synthetic controls. Evidence:
`complete-pbs-event-stream-progress-12-controls.json`. The overall process is
still live, and these observations do not qualify native security or performance.

The monomial frozen-word consumer passes all 20 cases (three tests, no
failures), across both representative fields, v4/v5 and all five backends.
Distinct and aliased sources match the original table queries; malformed
contexts/queries/source counts reject before view callbacks. Evidence:
`classical-monomial-frozen-word-passed-audit.json`. Accepted PCS opening coupling
and full security/performance qualification remain open.

### Monomial first-declaration immutability (validation pending)

The same 20-case word fixture now first declares the two monomial roots without
any graph preimages, consumes their frozen assignments, exposes the honest
preimages later and redeclares the roots. It requires identical before/after
assignments and identical frozen-view Arc identities, and contrasts the distinct
honest-word pair with the late zero completion. Aliased roots are also covered.
The revised test is compiling; no passing result is claimed yet. Snapshot:
`classical-monomial-first-declaration-source-manifest.json`. This is a controlled
history experiment, not a full production accepted-prefix reduction.

The monomial first-declaration fixture passes all 20 cases (three tests, no
failures). Late honest preimages and repeated declarations preserve both assigned
query values and the frozen-view Arc identities. Evidence:
`classical-monomial-first-declaration-passed-audit.json`. The next source revision
also reruns this fixture before validating the added NTT sampler audit.

### Monomial NTT row-request replay (validation pending)

The isolated entry fixture now binds both fixed coefficient sources and both
derived evaluation roots before comparing each production NTT row request with
independent framed bytes, exact raw prime-field rejection, its receipt, row
points and following challenge bytes. It covers 80 requests over the same 40
small/native field/backend/schedule cases. The updated word and monomial suites
are queued/running from one frozen revision; no pass is yet claimed. Snapshot:
`classical-monomial-ntt-source-manifest.json`. Prior-prefix acceptance, NTT folded
polynomial/PCS coupling and complete security admission remain open.

The initial NTT replay revision fails compilation because two generic backend
context lookups used Result::unwrap without a Debug error bound. They now use
the fixture's existing Option conversion convention. Failed-run evidence is
preserved in `classical-monomial-ntt-initial-build-failed.json`; that revision
has no passing test claim.

### Monomial entry after the accumulator prefix (validation pending)

The entry interpreter now advances only after collecting all seven accumulator
openings and checking its public arithmetic, requires the exact public-plan and
fixed-source binding, and parses exactly two canonical derived NTT roots. The
ordered-prefix fixture checks this handoff and rejects a changed binding,
wrong root count and truncation. Earlier bounded/opaque PCS completions remain
conditional obligations; this is not a full verifier-prefix theorem. The
corrected frozen revision first runs the word and isolated monomial suites,
then the two focused Brakedown ordered-prefix fixtures. Driver session 96920;
logs `classical-monomial-prefix-{words,protocol,prefix}-tests.log`. Snapshot:
`classical-monomial-prefix-source-manifest.json`. No results for this revision
are yet claimed.

The initial prefix revision also fails compilation: the malformed-root-count
fixture passed a slice to the sized `encoded` helper. Only that fixture now uses
an owned vector. The failed log/fingerprint is preserved in
`classical-monomial-prefix-initial-build-failed.json`. Corrected driver session
16315 uses exclusive `classical-monomial-prefix-corrected-{words,protocol,prefix}-tests.log`
files and snapshot `classical-monomial-prefix-corrected-source-manifest.json`.
No source edits are made while this corrected revision is compiling/testing.

The Goldilocks v4 dictionary and fragmented controls also pass independent
stream audits, including recorded SHA-512 preimages, whole-file fingerprints
and all six verifier counters. Audited total: 14/20. Evidence:
`complete-pbs-event-stream-progress-14-controls.json`. This remains partial
synthetic complete-protocol coverage; no overall test, native security or
performance qualification is inferred.

The corrected component revision passes the three-test word suite (20 cases)
and four-test monomial suite, including all 80 NTT row requests over 40
small/native geometries. Public factors (eight cases), terminal identities
(eight cases), frozen words and late-first-declaration immutability remain
passing on the same frozen revision. Evidence:
`classical-monomial-prefix-corrected-component-audit.json`. The two focused
ordered-prefix tests are live in PID 2818140, driver session 16315, with frozen
binary/source metadata in `classical-monomial-prefix-focused-running.json`.
No ordered-prefix pass or full security/performance qualification is inferred.

### First monomial NTT request after the conditional prefix

The next interpreter derives component 0 from the fixed accumulator source
slots after the collected accumulator/monomial entry. It requires the exact
source/evaluation contexts, root pair, NTT shape and atomic row descriptor. The
ordered fixture checks this request and rejects component substitution, changed
descriptor and truncation. Its request compiler is also compared with the
independent 80-request production replay fixture. The component suite is
compiling (session 34341); the extended ordered fixture has not yet run. The
prior entry-only focused run remains live on its frozen revision, without a
restart. Snapshot: `classical-monomial-ntt-prefix-source-manifest.json`.
Component 1 completion, folded-polynomial and PCS-opening coupling, prior
opaque obligations and final key switching remain required work.

The monomial NTT-prefix component suite passes four tests, including all 80
source-bound request comparisons over 40 geometries, eight independent public
factors and eight terminal cases. This checks the new request compiler against
the production row sampler, not the extended ordered-prefix parser at runtime.
Evidence: `classical-monomial-ntt-prefix-component-audit.json`. The earlier
entry-only focused prefix run remains live on its frozen binary; the extended
first-NTT-request prefix fixture still requires a full runtime run.

### Monomial NTT folded-polynomial/compression replay (validation pending)

The first monomial row interpreter now retains its suffix for the shared NTT
compression parser and requires exact role-0 source/evaluation contexts before
reuse. Its ordered fixture binds nonzero folded coefficient polynomials and
actual NTT transforms, then parses every compression request and receipt.
The isolated fixture compares both components with the real production folded
polynomial check and compression sampler, including every matrix challenge,
missing producer rejection, changed NTT evaluation rejection and following
challenge bytes. Expected coverage is 80 components / 360 compression rounds
over the same 40 geometries. The four-test component suite is compiling in
session 12022. The extended ordered fixture is implemented but has not run;
the older entry-only focused run remains live without restart. Snapshot:
`classical-monomial-ntt-compression-source-manifest.json`. These folded claims
still require accepted PCS openings and a complete prior-prefix argument.

### Mandatory control-row fingerprints

The log auditor now rejects null, empty, malformed and wrong-length trace
fingerprints before invoking the single-file auditor. Previously a null field
could select that API's optional-fingerprint mode and omit the row/file binding.
All five parser tests pass with added negative cases; every currently emitted
control has a valid fingerprint field. This change does not re-audit trace files
or change the existing independently audited totals. Evidence/source snapshots:
`classical-control-fingerprint-validation-audit.json`.

The monomial NTT compression component suite passes all four tests, including
80 component replays / 360 compression rounds over 40 small/native geometries.
Exact challenges, producer receipts, continuation bytes and negative folded
polynomial/producer cases pass. Evidence:
`classical-monomial-ntt-compression-passed-audit.json`. The extended ordered
prefix and accepted source openings remain unvalidated obligations.

The next three Goldilocks traces (v4 virtual, v5 Brakedown and v5 direct PolyFRIM)
also pass independent file/preimage/counter audits. Audited total: 17/20;
evidence `complete-pbs-event-stream-progress-17-controls.json`. The whole
protocol fixture and the final native group remain live and unqualified for
security/performance admission.

### Monomial NTT source-opening obligations (validation pending)

The first-component prefix now consumes the final compression receipt and
compiles the coefficient/evaluation batch query obligations, retaining their
fixed source roles. The isolated component fixture compares all resulting query
matrices and compressed terminal values against the actual production
`source_query` / `compressed_value` functions for both components over 40
geometries. It also checks trusted query counts and dimensions. The component
suite is compiling (session 99311); the extended ordered fixture remains
pending runtime validation. Snapshot:
`classical-monomial-ntt-source-obligations-source-manifest.json`. Compiling an
opening obligation does not establish an accepted PCS opening or source-word
coupling, and final key switching remains unfinished.

The monomial source-obligation suite passes all four tests, covering 80 NTT
components / 360 compression rounds and comparing 160 source groups / 1,280
query claims with the production source-query/terminal-value functions.
Evidence: `classical-monomial-ntt-source-obligations-passed-audit.json`.

### Actual accepted monomial proofs and frozen evaluation words

A feature-gated fixture now creates nonzero signed-rotation coefficient sources
at n32/three actual rounds (one padded row), commits them and runs the actual
monomial prover and complete verifier under recorded SHA-512/SHAKE interfaces.
It decodes the serialized proof for normal SHA-512 verification and compares
continuation bytes. It independently replays recorded history and SHA-512
preimages, decodes both evaluation words from their first-declaration views,
and compares their assigned values with accepted product claims and the
independent public terminal equation. Twenty cases are planned across both
representative fields, v4/v5 and all five backends. The fixture is compiling
in session 53224; no passing result is claimed. Snapshot:
`production-monomial-event-source-manifest.json`. This remains a monomial
component control, not a complete PBS first-declaration reduction, encrypted
native validation, all-trials theorem or security/performance admission.

The Goldilocks v5 dictionary control passes its independent streamed file,
SHA-512 preimage and verifier-counter audit. Audited total: 18/20. Evidence:
`complete-pbs-event-stream-progress-18-controls.json`. The two remaining
fragmented controls and the native final group remain live; no overall suite,
security or performance pass is inferred.

The actual monomial-proof fixture compiles without diagnostics and is live
in PID 2822966 / session 53224. Frozen binary/source metadata:
`classical-production-monomial-event-tests-running.json`. No case or suite
pass is yet claimed.

The first actual monomial control (BabyBear v4 Brakedown) passes strict
verification, decoded normal-SHA512 verification, actual-history replay, both
frozen evaluation-word assignments and the independent terminal equation.
The 20-case run remains live. Partial evidence: `production-monomial-event-progress-1-controls.json`.

### Accepted monomial NTT source words (validation pending)

The next fixture revision reconstructs both NTTs using the production sampler,
folded-polynomial and source-opening functions, verifies each actual batch
opening, finishes the product openings and requires the same final transcript
as the complete monomial verifier. It compares both coefficient and evaluation
claims with first-declaration assignments for all source query vectors. Frozen
word evaluation now supports batches so each source/context alias is decoded
once per invocation. Existing word fixtures check multiple queries, alias reuse
and malformed later-query rejection before any view callback. A focused v5
BabyBear Brakedown accepted-proof control runs first, followed by the 20-case
word suite, from one frozen revision (driver session 58278). Both are currently
compiling/queued. The earlier 20-case evaluation-only proof run continues on its
original frozen binary without restart. Snapshot:
`classical-monomial-accepted-ntt-source-manifest.json`. No full PBS prefix,
adaptive soundness, native security or performance qualification is inferred.

The complete-protocol streamed control suite finishes successfully: one test,
all 20 expected field/degree/schedule/backend cases, zero failures, process exit
0. Frozen source snapshots, original binary fingerprint, exact case matrix and
terminal log result are checked in
`classical-production-complete-pbs-event-tests-passed.json`. A fresh independent
control-log audit is recomputing every trace file with the current auditor;
its complete result is still pending. The synthetic n32/LWE21/Q8 controls do
not establish a complete first-declaration reduction, native encryption,
128-bit admission or matched performance.

The strengthened monomial accepted-NTT focused control and all 20 batched-word
cases pass (four tests total across two commands). Evidence:
`classical-monomial-accepted-ntt-focused-audit.json`. The 20-case strengthened
actual-proof matrix is now live in driver session 58924, with metadata in
`classical-production-monomial-accepted-ntt-events-running.json`. The older
evaluation-only matrix remains live on its own frozen revision.

### Final key-switch public binding (validation pending)

An isolated test-only interpreter reconstructs the shared-comparison marker
and final key-switch binding from the trusted key descriptor, fixed role-2
source contexts, role-3 helper geometry, the complete accumulator endpoint and
original unpadded output ciphertext. It compares the following challenge bytes
with the production binder and tests changed endpoints/source roles and malformed
root counts/dimensions. The 40-case fixture spans both representative fields,
v4/v5, all five backends and n32/LWE21 plus n1024/LWE728. It uses synthetic
trusted roots and does not authenticate switching-key material or establish
accepted monomial-to-key-switch prefix coupling. The fixture is compiling in
session 93385. Snapshot: `classical-final-key-switch-binding-source-manifest.json`.

The complete streamed protocol control audit passes all 20 cases, with exact
matrix coverage, Rust process exit 0 and a fresh full-file audit of 8,551,786
events / 53,485,529,000 trace bytes. Every recorded SHA-512 preimage/output pair,
file fingerprint and verifier counter matches. Evidence:
`classical-production-complete-pbs-event-stream-complete-audit.json`. XOF output
bytes were not recorded; direct primitive calls outside the instrumented
interfaces are outside scope. These remain synthetic n32/LWE21/Q8 controls,
not native security, a full first-declaration theorem or performance evidence.

The isolated final key-switch binding fixture passes all 40 cases. Evidence:
`classical-final-key-switch-binding-passed-audit.json`. It checks source-role
contexts and helper geometry; an explicit helper-role factory-context rejection
is the next preflight extension. Synthetic roots and isolated binding checks
do not authenticate key material or establish an accepted final-stage prefix.

The final-stage interpreter now checks both factory-derived role-2 source and
role-3 helper contexts. Its next regression substitutes a helper with identical
geometry but a changed query descriptor, while retaining all original source
parameters and trusted key; the interpreter must reject this substitution in
each of the 40 cases. The revised fixture is compiling in session 61899.
Snapshot: `classical-final-key-switch-helper-context-source-manifest.json`.
The previous 40-case binding pass is preserved as its separate frozen revision;
no passing result is yet claimed for the helper-context extension.

The final key-switch helper-context extension passes all 40 cases, including
40 same-geometry helper substitutions with changed role-3 query context.
Evidence: `classical-final-key-switch-helper-context-passed-audit.json`.

### Final public-input table and query replay (validation pending)

The fixture now independently constructs the negated first accumulator
polynomial in both ciphertext halves, compares the production public table,
and replays every typed prime challenge and raw receipt following the complete
final-stage binding. It independently contracts the ordered matrix query and
compares its terminal vector with the production public table evaluator. It
also checks that the second accumulator half does not alter this input table
and that changing the first half does. Forty cases / 220 main query phases are
planned across both representative primes, both schedules, all five backends
and small/native geometries. The revised fixture is compiling in session 4697.
Snapshot: `classical-final-key-switch-public-input-source-manifest.json`.
An accepted PCS opening against this public input root, the later final-stage
relations and complete security/performance qualification remain required.

The final public-input fixture passes all 40 cases / 220 main challenge phases,
including native geometry, exact transcript/receipt replay, independent dense
matrix contraction and the accumulator-half dependency checks. All prior
binding/context substitution checks remain passing on this revision. Evidence:
`classical-final-key-switch-public-input-passed-audit.json`. An accepted public
input opening and the rest of final key switching remain required work.

The earlier actual monomial matrix passes all 20 controls, with decoded normal
SHA-512 verification, actual first-declaration evaluation-word assignments,
history replay and the independent terminal equation. Its frozen-revision
evidence is `classical-production-monomial-event-complete-audit.json`; it does
not claim NTT word coupling. The strengthened NTT-word matrix is still live;
its first 14 controls match every corresponding baseline proof byte count,
verifier hash/XOF count and total event count, while also passing coefficient
and evaluation word checks. Partial evidence:
`classical-production-monomial-accepted-ntt-progress-14-controls.json`.

### Final native sample-extraction relation (validation pending)

The fixture now independently derives sparse extraction coordinates from the
original unpadded output dimension, including reversed negacyclic signs and
integer-floor p/8 bias, and compares the production mask, target and packed
relation shape. A valid coefficient word is checked; changing every active
coefficient must fail both the independent coordinate identity and the actual
packed polynomial. Inactive coordinates remain unconstrained by extraction.
Padded output vectors, changed output bias and changed accumulator constant
are checked separately. Forty cases / 15,020 active-coordinate mutations are
planned over small/native geometries, both representative fields, both schedules
and all five backends. The fixture is compiling in session 43102. Snapshot:
`classical-final-key-switch-extraction-source-manifest.json`. An accepted source
opening and complete final-stage/earlier-prefix coupling remain required.

The strengthened actual monomial matrix passes all 20 controls, including 640
NTT source claims and 40 product source claims against their first-declaration
word assignments, decoded normal-SHA512 verification and exact final transcript
replay. All proof byte counts and oracle counters match the prior 20-case
matrix. Evidence: `classical-production-monomial-accepted-ntt-complete-audit.json`.
The independent extraction fixture also passes all 40 cases / 15,020 active
coordinate mutations: `classical-final-key-switch-extraction-passed-audit.json`.

### Actual accepted final key-switch control (validation pending)

A new feature-gated fixture uses nonzero synthetic public switching keys with
constant coefficient polynomials, independently forms their canonical-digit
product, and runs the complete shared final-stage prover/verifier at n16/LWE13.
It decodes for standard SHA512 verification, replays the audit verifier to
extract the actual public-input/extraction queries, compares final transcripts,
and resolves both source words from recorded first-declaration history. Shared
word decoding now takes an explicit main/final source role; a role substitution
must reject before callbacks. The independent native extraction equation is
checked on the assigned extraction value. This is a focused BabyBear v5
Brakedown component control, compiling in session 2282. Snapshot:
`production-final-key-event-source-manifest.json`. It does not establish a
complete PBS prefix, native encryption, all-trials soundness or admission.

The final v5 Goldilocks virtual group passes all 21 original-size records and
independent field-control compatibility, descriptor and fingerprint checks.
The full atomic-columns v5 schedule is independently audited at 210/210, across
ten field/backend groups with the original 1024/728/728 dimensions and 1/4/16
fresh-input groups. Frozen binary SHA256:
`8a4a1ab2db2e1f6cc6aecc2ad9008761c41807e48fbd08bb7c507ea005d228cc`.
Evidence: `columns-fresh21-complete-audit.json` and
`columns-fresh21/goldilocks-virtual-control-compatibility.json` under native
validation. Driver session 49719 exits 0. These Q1 correctness controls do not
establish security admission or performance qualification.

The initial accepted final-key fixture fails compilation on an ambiguous integer
used with ilog2; its trusted geometry tuple now has explicit usize types. Failed
build evidence: `production-final-key-event-initial-build-failed.json`. Corrected
source snapshot: `production-final-key-event-corrected-source-manifest.json`.
Driver session 81809 runs the accepted control, shared 20-case word regression
and 40-case final geometry suite sequentially in exclusive
`classical-production-final-key-corrected-{accepted,words,geometry}-tests.log`
files. No result for the corrected revision is yet claimed.

The initial n16 final-key control fails at runtime because the existing NTT
generator rejects that size. Its supported replacement uses n32/LWE21 and
retains the nonzero key/product control. The failed log/source fingerprint is
preserved in `final-key-unsupported-geometry-failed-audit.json`.

The earlier entry-only focused prefix run terminates with two failures at the
same isolated assignment-fixture assertion: it expected seven distinct roots,
but each task has five context/root identities. Evidence:
`monomial-prefix-source-alias-failed-audit.json`. No prefix pass is claimed.
The correction checks equal words for every repeated identity, keeps all seven
logical query groups, and resolves each generic assignment callback once per
identity. A fast two-field regression explicitly uses seven slots/five identities
and rejects repeated callback replacement. Supported final-key/alias/word/geometry
checks are queued in driver session 59720 with snapshot
`production-final-key-supported-source-manifest.json`; exclusive logs are
`classical-production-final-key-supported-{alias,accepted,words,geometry}-tests.log`.
A new ordered-prefix run is still required after these checks.

The fast assigned-word alias regression passes in both fields (one test,
zero failures), retaining seven logical sources and exactly five immutable
assignments/callbacks. Evidence:
`classical-accumulator-assigned-alias-passed-audit.json`. The supported
nonzero-key accepted control is now running; the expensive corrected prefix
run remains pending.

The supported n32/LWE21 nonzero-key final-stage control passes strict and decoded
normal-SHA512 verification, audit-verifier flags/final transcript comparison,
actual oracle-history replay, role-2 frozen input/extraction assignments and the
independent extraction equation. The alias regression, all 20 shared word cases
and all 40 final geometry cases pass on the same frozen revision. Evidence:
`classical-production-final-key-supported-component-audit.json`. This focused
BabyBear v5 Brakedown component control does not establish a complete PBS prefix,
all-backend final-stage coverage, native security or performance qualification.

The earlier doc's running status for the accepted control is superseded by that
pass. A new default-feature focused ordered-prefix run is now compiling/running
with the alias-aware fixture and callback cache. Evidence/log metadata:
`classical-monomial-prefix-alias-corrected-running.json`; log:
`classical-monomial-prefix-alias-corrected-tests.log`. No prefix pass is yet claimed.

### Accepted final-stage field/backend matrix (validation pending)

The accepted nonzero switching-key fixture now enumerates both representative
fields, v4/v5 and all five backend families (20 cases). Every case retains
strict and decoded verification, transcript/audit replay, role-2 public-input
and extraction word comparisons, wrong-role rejection and the independent
extraction equation at n32/LWE21. The matrix is compiling/queued in session
15211; source snapshot `production-final-key-matrix-source-manifest.json`, log
`classical-production-final-key-matrix-tests.log`, running metadata
`classical-production-final-key-matrix-running.json`. The earlier focused
component pass remains its separate frozen revision. No all-backend final-stage
pass or complete PBS security/performance admission is yet claimed.

### Final-stage NTT source-word coupling (validation pending)

The next feature-gated audit revision records every digit/product NTT source
obligation using the production samplers and strict batch-opening verifiers.
The focused nonzero-key control decodes each coefficient/evaluation pair from
its role-2 first-declaration views and compares all accepted terminal claims.
It retains input/extraction checks and exact final transcript comparison. The
focused BabyBear v5 Brakedown test is compiling in session 30111; source snapshot:
`production-final-key-ntt-words-source-manifest.json`, log:
`classical-production-final-key-ntt-words-tests.log`. The earlier 20-case
input/extraction matrix continues unchanged on its frozen binary, now captured
in `classical-production-final-key-matrix-binary.json`. No passing result or
full PBS security/performance qualification is yet claimed for the NTT extension.

### Final-stage product source-word coupling (validation pending)

The test-only relation verifier now optionally returns its actual zero-check
subclaim after the same strict PCS opening checks. The final-stage audit retains
that product query and compares each digit evaluation, trusted public switching
key factor, and final product evaluation with the word fixed at first declaration.
This extends the nonzero-key focused control beyond its NTT/input/extraction
claims. `cargo check -p snarks --tests --features transcript-audit` passes;
execution remains pending in `classical-production-final-key-product-words-tests.log`.
Frozen sources: `production-final-key-product-words-source-manifest.json`.
The earlier NTT-only focused test, input/extraction matrix and corrected prefix
jobs continue on their own revisions. No complete PBS security or performance
qualification follows from these component controls.

The frozen NTT-only focused control now passes: one test, zero failures,
128 coefficient/evaluation source claims matched at first declaration, alongside
public-input/extraction comparisons and strict decoded verification.
Evidence: `classical-production-final-key-ntt-words-passed-audit.json`.
This is the BabyBear v5 Brakedown n32/LWE21 component revision; it excludes the
later product-factor checks and does not prove a full PBS prefix.

The current product extension additionally checks the terminal equation
`(sum digit_j * key_j - product) * equality = expected` from assigned words,
and explicitly checks NTT claim-vector lengths. The feature-enabled test build
passes `cargo check`; runtime validation of this latest equation remains pending.

### Final-stage decomposition linear source words (validation pending)

The test-only linear verifier now returns each source's actual normalized query
after strict opening verification. Both decomposition audit variants retain
these queries without changing their existing flags-only interfaces. The final
key-switch audit carries them to its accepted control, which compares the input,
every digit and every borrow commitment with its first-declaration word.
This covers the linear source claims, not the later comparison-helper/lookup
source claims. The feature-enabled `cargo check` and whitespace check pass.
Focused execution is queued in
`classical-production-final-key-decomposition-words-tests.log`; frozen sources:
`production-final-key-decomposition-words-source-manifest.json`.
No complete final-stage/PBS security or performance admission is claimed.

### Final-stage shared lookup source/helper words (validation pending)

The shared lookup audit now returns its actual pulled original-source query,
used-slot mask, helper coefficient query and normalized helper values after the
same strict source-batch/helper-opening checks. The shared decomposition audit
carries these obligations to the accepted final-key fixture. The per-limb audit
explicitly returns no shared-lookup obligations; no per-limb coverage is implied.
The fixture compares used digit/borrow source values against role-2 words and
all reciprocal helper values against role-3 words. Role selection is explicit,
and profile/context/query geometry is checked before resolving a word.
`cargo check -p snarks --tests --features transcript-audit` passes. Focused runtime
validation is queued in `classical-production-final-key-lookup-words-tests.log`,
with frozen sources `production-final-key-lookup-words-source-manifest.json`.
These comparisons do not supply the full adaptive classical reduction, native
resource bounds or performance admission. Earlier tests remain on their separate
frozen revisions and do not establish this extension's passing status.

The frozen product-terminal focused control now passes: 128 NTT source claims,
15 product factors, input/extraction word comparisons, and the independent
product terminal equation. Evidence:
`classical-production-final-key-product-terminal-passed-audit.json`, including
the fingerprint of the actual running executable. Decomposition/lookup revisions
remain separate pending validations; no full-stage coverage is inferred.

The analysis history collector now shares an immutable eligible-producer snapshot
across registrations until a new eligible hash answer appears. Registrations
with no new first-declaration windows avoid snapshot allocation. Duplicate hash
answers and ineligible preimages retain the cached eligible snapshot; all oracle
requests still count, and there is no adversary-query cutoff. The new regression
checks sharing, invalidation, unchanged earlier views and exact event counts.
Full `pcs` history tests are running in `classical-history-snapshot-cache-tests.log`;
sources: `classical-history-snapshot-cache-source-manifest.json`.
This is audit-overhead work, not an established PBS speedup.

Both history tests pass (zero failures), including the new snapshot-sharing
regression and existing production-leaf grammar/frozen-word controls. Evidence:
`classical-history-snapshot-cache-passed-audit.json`. This validates the cache
change's focused history semantics, not full PBS security or measured speedup.

The frozen decomposition focused control passes: 128 NTT claims, 15 product
factors and all 16 decomposition linear sources match first-declaration words.
Evidence: `classical-production-final-key-decomposition-words-passed-audit.json`.
The separate lookup revision is still running; its passing status is unproven.

The final-stage source checker has been extracted into `assert_source_words`,
which accepts the actual verifier obligations, expected key, final-stage public
statement and history. This permits reuse from a complete PBS audit without
reconstructing the isolated fixture's public key or transcript. Nonzero-source
assertions remain required for the existing synthetic nonzero-key control;
callers must explicitly select whether that additional fixture condition applies.
Feature-enabled compilation passes. A focused runtime check, including all lookup
comparisons and the history snapshot cache, is queued in
`classical-production-final-key-reusable-words-tests.log`, with frozen sources
`production-final-key-reusable-words-source-manifest.json`. Full PBS integration
and the complete classical reduction remain unfinished.

### Complete-PBS final-stage obligation handoff (validation pending)

The frozen final lookup control passes all source/helper comparisons (15 original
lookup claims and seven helpers), alongside its 128 NTT, 15 product and 16 linear
claims. Evidence: `classical-production-final-key-lookup-words-passed-audit.json`.
This remains the isolated n32/LWE21 BabyBear v5 Brakedown nonzero-key control.

The complete reference audit now returns final-stage verifier obligations after
performing all preceding stage checks; existing report-only callers retain their
interface. The complete-protocol stream control compares every algebraic report
flag and its final challenge/byte continuation with the prover's continuation.
A new focused BabyBear v5 Brakedown full-proof control is running in
`classical-production-complete-final-obligations-tests.log`; frozen sources:
`production-complete-final-obligations-source-manifest.json`. Feature-enabled
compilation passes. The emitted handoff record explicitly sets
`source_words_checked:false`: full-proof source-word interpretation and the
complete classical security argument remain unfinished.

### Complete-PBS final-stage word interpretation (validation pending)

The focused complete-proof obligation handoff passes all stage report flags and
matches the prover's final challenge/byte continuation. The reusable isolated
checker also passes all 128/15/16/15/7 claim groups. Evidence:
`classical-production-complete-final-obligations-passed-audit.json` and
`classical-production-final-key-reusable-words-passed-audit.json`; the former
includes an independent Python audit of every recorded event and stream counter.

A selected-root history projection now processes every H/XOF event, records the
first input-window declaration of each requested root, and freezes its entire
reachable known-preimage closure before answering that event. It never adopts
later producers. The selected-root set is an audit projection, not an adversary
query/length limit or a global availability bound. Stream replay verifies phases,
framing, SHA512 answers and the full file fingerprint. Four PCS history tests pass,
including existing production leaf grammars, immutable snapshot reuse, projected
first-declaration timing and stream-corruption/truncation/fingerprint rejection.
Evidence: `classical-history-projection-stream-passed-audit.json`.

The complete event fixture now projects its actual final coefficient/evaluation,
input, borrow, public-key and lookup-helper roots, then applies the reusable
checker to the obligations from the actual complete audit transcript. It allows
zero keys in this complete synthetic control; the separate nonzero-key fixture
retains its nonzero condition. Compilation passes. Focused execution is queued in
`classical-production-complete-final-source-words-tests.log`; frozen sources:
`production-complete-final-source-words-source-manifest.json`. Earlier full-proof
passes exclude this new word comparison. Other PBS stages still require accepted
word coupling, and no complete classical reduction/native/performance gate is
admitted.

### Complete accepted primary-stage word interpretation (validation pending)

The complete audit now retains actual primary key-product, NTT,
decomposition/lookup, accumulator-linkage and monomial queries, in addition to
final-stage obligations. Existing flags-only audit entry points remain wrappers
around the strict verifiers. The stream fixture selects all original primary,
public-key, borrow, lookup-helper and monomial roots for the same first-declaration
projection, then compares every accepted source value against its assigned word.
Both lookup helper roles are explicit (roles 1 and 3); original source roles are
0 and 2. Query counts, source counts and canonical normalized values are checked.
All stage algebra flags and the complete transcript continuation remain required.

Feature-enabled compilation passes. The first primary-obligation check's
ambiguous PCS geometry method call is preserved in
`classical-complete-primary-obligations-check.log`; the explicit Sha512 PCS type
fix and later complete checker compile successfully. The all-stage focused run
is queued in `classical-production-complete-all-source-words-tests.log`, with
frozen sources `production-complete-all-source-words-source-manifest.json`.
The earlier final-stage-only full-trace projection remains running separately.
No passing all-stage result is claimed. Even a pass of this n32/LWE21 synthetic
control would not establish the adaptive classical reduction, native resource
bounds, 128-bit admission or matched performance gates.

The existing production-leaf controls now also replay selected-root projections
alongside full histories. Frozen Brakedown columns, PolyFRIM vector pair symbols
and fragmented scalar pair symbols agree exactly, and their first-declaration
indices/event counts match. All four history tests pass (zero failures).
Evidence: `classical-history-projection-production-passed-audit.json`.
This validates the three shared physical leaf grammars; it does not imply that
all complete protocol/backend controls have passed. Both full-proof projection
jobs remain active on their separate frozen revisions.

The complete-proof final-stage word control now passes (one test, zero failures).
It replays 12,690 recorded events and matches 128 NTT, 15 product, 16 linear,
15 lookup-source and seven helper claims, alongside public-input/extraction
comparisons. All preceding stage algebra flags and the complete transcript
continuation match. Its emitted `all_pbs_stages_coupled:false` remains accurate:
the separate all-stage interpretation is still running. Evidence:
`classical-production-complete-final-source-words-passed-audit.json`, including
an independent Python event/fingerprint/counter audit and actual binary hash.

The projection reader now streams XOF inputs with a 63-byte overlap instead of
allocating the entire transcript input. All windows crossing chunk boundaries
remain registered before the event is counted. Hash preimages remain retained
for word-closure reconstruction. Four history tests pass, including a root that
straddles the 1 MiB IO boundary; the IO buffer is not an adversary/input limit.
Evidence: `classical-history-projection-streaming-xof-passed-audit.json`.
The live full-proof jobs use their older frozen reader revision; these tests do
not retroactively attribute that change to their binaries.

### Focused complete accepted source-word control passes

The frozen BabyBear/EF6 v5 Brakedown n32/LWE21/Q8 full-proof control passes all
258 primary-stage source claims (including monomial), all 128/15/16/15/7 final
claim groups and public-input/extraction comparisons. Its 12,690-event replay
matches the first-declaration words, all stage arithmetic flags, and the prover's
complete transcript continuation. A separate Python audit verifies the full file
fingerprint, every SHA512 preimage/output and all verifier counters. Evidence:
`classical-production-complete-all-source-words-passed-audit.json`, including the
actual binary fingerprint and frozen sources. This is an accepted synthetic
control, not a proof of adaptive security, native resource bounds or performance.

A new 20-case complete source-word matrix is queued on the latest tested streaming
XOF reader: both representative fields, v4/v5 and all five backend families.
Log: `classical-production-complete-all-source-matrix-tests.log`; sources:
`production-complete-all-source-matrix-source-manifest.json`. This matrix's older
same-named test only checked oracle streams; this new revision additionally
requires full source-word interpretation and complete transcript continuation.
No matrix pass, native security or performance qualification is yet claimed.

### Independent all-stage control-record admission checks

The Python event auditor now supports `--require-source-words` with a control
log. For the current n32/LWE21/width8/radix8-and-5/repetition1 fixture, it requires
complete ordered obligation/primary/final/trace records, matching identities,
all-stage/monomial/transcript flags, exact geometry-derived claim counts and
replayed event counts equal to the independently read stream. Every H preimage,
file fingerprint and verifier counter remains independently checked. This is
validation of Rust control evidence, not a standalone proof of source semantics
or adaptive security. Live partial rows never prove suite completion.

Six auditor tests pass, including missing/reordered records, altered/bool counts,
identity/geometry substitution and disabled stage flags. The new mode passes on
the real focused all-stage proof log and trace. Evidence:
`classical-all-source-control-auditor-passed-audit.json` and
`classical-complete-all-source-record-audit.json`. The 20-case matrix has compiled
and is running; its executable fingerprint is preserved in
`classical-production-complete-all-source-matrix-binary.json`.

### Native verifier interface counters (runtime validation pending)

An optional `classical::oracle_audit` verifier re-decodes the exact ordinary
payload for a SHA512-compatible counting hash and executes the same strict
verifier with the same trusted setup/profile and transcript. Hash clones retain
absorbed lengths; resets clear those lengths, and scoped observers propagate to
synchronous workers and disable on scope exit. It reports PCS Hash-trait SHA512
requests/bytes/maxima and transcript SHAKE requests/bytes/maxima. Direct primitive
calls outside these interfaces remain excluded. A verifier rejection is retained
separately from instrumentation/decode errors, so rejected executions can also
be inspected without turning them into accepted proofs.

The native correctness runner's `transcript-audit` feature enables these counters
for each ordinarily verified decoded proof and emits profile/proof-bound
`HB_CLASSICAL_ORACLE_COUNTS` rows. Default-feature runs retain their existing
behavior. Feature-enabled library and example checks pass; the clone/reset byte
compatibility unit test is compiling/running. No native measured count or complete
resource bound is claimed yet. Sources:
`classical-native-oracle-counter-source-manifest.json`; logs:
`classical-native-oracle-{counter,runner}-check.log` and
`classical-native-oracle-counter-tests.log`.

The counter hash's SHA512 compatibility/clone/reset test passes (one test, zero
failures). Both feature-enabled and default native example checks pass. Evidence:
`classical-native-oracle-counter-component-passed-audit.json`.
An instrumented toy four-proof correctness schedule is compiling/running in
`classical-native-oracle-counter-toy-tests.log`, driver metadata
`classical-native-oracle-counter-toy-running.json`. It checks the new exact-payload
re-decoding verifier and count-row emission before native measurements. This toy
run cannot establish native offsets or complete resource/security admission.

The instrumented toy schedule passes all four NAND inputs using the same public
setup and exact decoded ordinary proofs. A separate count-record auditor checks
every measurement's profile ID, proof digest, ordinal, geometry, positive integer
counts and explicit interface-only scope against the completed correctness
records. Toy geometry requires an explicit `--toy` option; native validation still
defaults to 1024/728. Eleven metadata/profile/count-auditor tests pass. Evidence:
`classical-native-oracle-counter-toy-record-audit.json` and
`classical-native-oracle-count-auditor-passed-audit.json`.

The successful instrumented executable is frozen and fingerprinted in
`classical-native-oracle-counter-runner-binary.json`. Its original-geometry
BabyBear/EF6 v5 Brakedown Q1 four-proof correctness run is now starting in
`classical-native-oracle-counter-native-tests.log`, driver metadata
`classical-native-oracle-counter-native-running.json`. No native count or
resource bound is claimed before completion and independent record validation.
Observed counters exclude direct primitive calls and cannot certify adaptive
soundness, deterministic rejected-path resource bounds or benchmark latency.

The counter scope regression now also passes for parent-state clones moved to a
worker, fresh worker-local hashers, nested-scope rejection, disabled prior-scope
hashers and scope exit. Exact SHA512 outputs and request/length totals match.
Evidence: `classical-native-oracle-counter-workers-passed-audit.json`.
The live native run keeps its earlier frozen executable; this regression does
not substitute a new binary into that run.

The reference joint decoder now first interpolates a fixed prefix using shared
Newton differences, then checks the candidate's whole-column distance against
the complete word. It accepts only within the original unique-decoding radius;
otherwise it runs the existing general error-correction decoder. Duplicate-point,
dimension, padding and whole-column promise checks remain required. Both fields
pass all 36 pairs of two-error positions, including clean/corrupt/mixed prefixes,
and reject disjoint coordinate errors whose union exceeds the radius. Four
production history/leaf-grammar tests also pass. Evidence:
`classical-joint-decoder-prefix-passed-audit.json`. This avoids unnecessary dense
solves in exact-codeword audit controls, without asserting a PBS speedup or
changing the security radius. Live older audits retain their frozen decoder.

### Rejected verifier execution measurements (validation pending)

The feature-enabled native runner now also observes its existing altered-output
rejection through the same strict counting verifier. It requires a rejection,
retains the measured requests made before that failure and emits a separate
profile/proof/ordinal/altered-statement-bound rejection record. Ordinary accepted
proof/count records retain their semantics. The count-log auditor can require one
such execution per completed proof; it permits legitimate zero work before an
early rejection while rejecting boolean/negative counts, inconsistent zero-query
byte totals, missing executions and accepted-result substitutions.

Feature-enabled compilation and all 12 metadata/profile/count tests pass. Revised
toy execution is compiling in `classical-native-oracle-rejection-toy-tests.log`;
frozen sources: `classical-native-oracle-rejections-source-manifest.json`.
The original native measurement continues on its earlier frozen binary without
these additional rejection observations. These are observed sample executions,
not upper bounds on all rejected paths or security/performance admission.

The native instrumented run has completed its first of four proofs. Its entire
correctness record (including proof bytes/hash, public statement/setup and
FHE/key/profile identities) exactly matches the corresponding frozen v5 Brakedown
four-case control. The measured strict verifier records 1,663 PCS hash requests,
1,250 transcript XOF requests, 15,592,367 hash-input bytes and 4,375,545,686 XOF-input
bytes; maximum inputs are 262,170 and 11,285,340 bytes respectively. XOF input-byte
counts include repeated complete absorbed prefixes and are not incremental hash
work or latency. These are actual 1024/728 Q1 sample counts, excluding direct
primitive calls and honest setup/prover work. The remaining three proofs are
running; no complete schedule/resource-bound claim is made. Evidence:
`classical-native-oracle-counter-native-progress-1-proof.json`.

The revised toy instrumentation run passes all four proofs and all four observed
altered-output rejections. Independent count-record validation passes with
`--toy --require-rejections`. Every ordinary correctness record and every accepted
measurement exactly equals the earlier accepted-only toy run, so the additional
observations preserve the subsequent deterministic proofs and counts. Evidence:
`classical-native-oracle-rejection-toy-passed-audit.json` and
`classical-native-oracle-rejection-toy-record-audit.json`. Twelve metadata tests
also pass. These rejected-execution samples do not establish bounds on arbitrary
rejected paths, setup/prover work or direct primitive calls. The earlier frozen
native run remains live on proof 1 after its completed first measurement.

### Reviewed fixed profile-identifier hash addend

The ordinary classical verifier has a direct SHA512 profile-identifier check,
and its selected parent-transcript constructor computes the same identifier once
more. `ClassicalProfile::id` hashes only the immutable trusted descriptor and its
fixed domain prefix; it does not consume statement/proof commitments. These calls
bypass the generic PCS hash counter. The reviewed first native profile has a
356-byte identifier preimage, whose SHA512 output independently matches the bound
profile ID. Its two fixed calls therefore add two requests and 712 input bytes
to the measured PCS Hash-trait sample. This is a source-reviewed analytical
addend, not a retroactive claim that instrumentation observed those calls.
Evidence with frozen call-path sources and exact sample totals:
`classical-native-fixed-profile-hash-inventory.json`. The scalar fragmented
parameter constructor's Sha256 type argument does not hash during `try_setup`;
the direct batch profiling hashes are cfg(test) controls. Setup/prover work and
general rejected-path/resource/adaptive bounds remain separate obligations.

Two native instrumented proofs now complete, and both entire correctness records
exactly match the frozen v5 four-case control. Each has 1,663 measured PCS hash
requests and 1,250 transcript XOF requests. Including the reviewed two fixed
profile-ID requests gives 1,665 SHA512 requests per sample. The current native
Q1 descriptor worksheet supplies conditional ceilings of 1,704 H and 1,265 XOF
requests; both samples fit. This is only a compatibility check: first-retry and
other stopping/admissibility premises have not been independently verified for
these samples, and no general or rejected-path bound follows. Evidence with
frozen resource-model sources: `classical-native-oracle-counter-native-progress-2-proofs.json`.

The 20-case all-stage matrix has completed BabyBear/EF6 v4 Brakedown. Its full
stream, source-word claim counts, stage flags and verifier counters pass the
independent all-stage auditor. Evidence:
`classical-complete-all-source-matrix-progress-1-control.json`. The remaining
19 cases remain pending; this partial report explicitly does not certify suite
completion or native security/performance eligibility.

### Actual lookup retry stopping-condition observations (validation pending)

The optional inherited transcript observer now has a separate resource-event
callback. The real reciprocal sampler emits `LookupReciprocalRejected` only when
it discards a zero/forbidden-denominator candidate. This appends no transcript
bytes, draws no challenges and imposes no retry cutoff. The counting verifier
retains these events separately from H/XOF counts; the feature-enabled native
runner emits the observed retry count for accepted and rejected executions.
The log auditor treats missing data as unknown, can require explicit observations,
and accepts nonzero retry counts while marking that the execution crossed the
conditional worksheet's first-retry stopping condition.

Both helper observer integration tests pass, including descendant workers,
unrelated roots, scope exit and exact byte compatibility. Thirteen metadata tests
pass, and the feature-enabled native example compiles. The deterministic local
sampler fixture constructs a compressed table point equal to minus the first
draw, so the actual rejection branch should emit one event and accept the second
draw. This is a local branch fixture, not a forged complete proof. Its initial
missing enum documentation and concrete-field trait imports are preserved in
failed build logs; the corrected fixture is compiling/running. No forced-branch
pass or native retry observation is yet claimed. Frozen sources:
`classical-lookup-retry-observer-source-manifest.json`.

The instrumented original-geometry BabyBear/EF6 v5 Brakedown Q1 schedule now
passes all four NAND cases. Independent count-record validation passes, and every
entire correctness record exactly equals its frozen v5 control (including all
proof hashes/bytes). Evidence:
`classical-native-oracle-counter-native-passed-audit.json` and
`classical-native-oracle-counter-native-record-audit.json`. This completes one
native measurement schedule, not a multi-backend resource bound or security gate.
Its older binary has no lookup retry event field, so its stopping-condition
observation correctly remains unknown rather than zero.

The actual forced reciprocal-rejection branch test now passes, observing exactly
one event and the unchanged second accepted draw. Both inherited observer scope
checks, all 13 metadata tests and feature/default example checks pass. Evidence:
`classical-lookup-retry-observer-component-passed-audit.json`. The revised toy
four-proof/four-rejection schedule is compiling in
`classical-lookup-retry-observer-toy-tests.log`; this will validate explicit retry
observations end to end. The first missing-docs and trait-import build failures
remain preserved separately and are excluded from passing evidence.

The explicit lookup-retry observer passes its four-proof/four-rejection toy run.
All observed retry counts are zero, while every prior correctness record and
existing measurement field remains equal to the earlier instrumentation run.
Evidence: `classical-lookup-retry-observer-toy-passed-audit.json`. This establishes
that stopping-condition observation for these toy executions; it does not supply
missing observations for older native binaries.

### Field rejection-sampling output observations (toy validation passed)

The optional field-phase observer now records accepted base-field values, total
candidate draws, maximum candidates for one value and consumed field-stream
bytes. The verifier counter aggregates these and reports per-phase output maxima.
No byte framing/challenge changes or candidate limits are introduced. Metadata
validation checks candidate/value/output consistency and marks the analytical
512-candidate threshold as crossed when appropriate, while accepting such valid
measurements rather than rejecting a proof. Missing metrics remain unknown.
Both scope/byte tests and all 14 metadata tests pass; feature/default example
checks pass. A direct sampler test rejects 513 consecutive candidates and accepts
the 514th, confirming no runtime threshold. Evidence:
`classical-field-draw-observer-component-passed-audit.json`.
The forced lookup branch passes with the extended event enum. The end-to-end
toy schedule also passes: four accepted proofs and four altered-output rejections,
with exact prior correctness records and all previous measurement fields unchanged.
The maximum observed candidates per value is five; observed lookup retries are zero.
Evidence: `classical-field-draw-observer-toy-passed-audit.json`.
Frozen sources: `classical-field-draw-observer-source-manifest.json`.
No native output/stop-bound admission follows before native observation and the
remaining complete reduction/resource argument.


### Honest setup/prover activity observation (toy validation passed)

The optional `pcs/hash-audit` observer records standard SHA512 Hash-trait output
calls across workers without replacing the production hash type. It is exclusive
and process-wide; callers must serialize observed activities. Direct primitive
calls and hash input lengths are outside this observer's scope. Its worker,
clone/reset, exclusive-registration and disabled-scope integration test passes.
The native correctness runner now measures setup and each prover invocation,
including inherited transcript input, field sampling and lookup retry activity.
Setup/prover instrumentation compiles with `transcript-audit`; the default path
invokes the same closures without observers. The metadata auditor requires one
setup record and one proof-bound proving record when requested, matching profile,
trusted setup and geometry. Unknown hash input lengths must be absent. Seven
metadata tests pass, including missing-record and substituted-binding negatives.
Frozen sources: `classical-honest-oracle-activity-source-manifest.json`.
Default compilation and the counter regression pass. The instrumented toy schedule
passes four accepted proofs and four altered-output rejections, with one setup
record and four proving records. All correctness records and verifier measurements
exactly equal the previous field-observer run. Setup records 966 standard hash
outputs and zero transcript XOF requests; proving records 5309–5344 standard hash
outputs and 855–861 XOF requests per proof. Evidence:
`classical-honest-oracle-activity-toy-passed-audit.json`. The first invocation failed
before setup because the required 16-thread environment was omitted; its exit
101/log are preserved. The successful invocation uses `RAYON_NUM_THREADS=16`.
The same frozen runner is now measuring native dimensions in
`classical-honest-oracle-activity-native-tests.log`. These observations do not
establish deterministic resource bounds or complete honest random-oracle offsets:
parameter factories outside the measured closures and direct primitive calls
remain outside the reported scope. Security and performance admission stay false.


The frozen alias-corrected broad prefix run has now terminated with two failed
field cases, rather than remaining queued. `classical-monomial-prefix-alias-corrected-failure-audit.json`
records exit 101 and the immutable log digest. The failure is the synthetic
assigned-word assertion for repeated context/root identities in a real prefix
task; the synthetic words differ for that identity. The passing isolated alias
fixture does not cover this case. The broad prefix gate remains failed pending
investigation and a correction that respects one immutable word per source.


The prefix assignment correction keeps the immutable-alias assertion intact and
builds a separately bound synthetic task for interpolated arithmetic words.
Actual prefix source identities can share roots in additional slots, so those
roots cannot be paired with arbitrary interpolated words. Complete PBS event
controls remain responsible for checking actual frozen source words. A focused
regression supplies the conflicting monomial-product/external-input alias at
n32/LWE21 in both fields. Its source snapshot and test are
`accumulator-prefix-assignment-scope-source-manifest.json` and
`classical-accumulator-prefix-assignment-scope-tests.log`; both focused tests pass
(0.21s), covering both fields. Evidence:
`accumulator-prefix-assignment-scope-passed-audit.json`. The corrected frozen test
binary is now rerunning the two broad prefix cases in
`classical-accumulator-prefix-assignment-scope-broad-tests.log`.
The earlier failed broad run remains failed evidence.


### Batched complete-proof primary source-word interpretation (validation pending)

The complete accepted-proof control now groups all primary claims by role,
trusted PCS context and root before decoding. Every query and expected value,
including duplicates and aliased sources, remains compared; the final compared
count must equal the original claim count. Role is retained even when layouts
match. No production prover/verifier code or older live matrix binary changes.
This removes repeated audit-only reconstructions across protocol stages.
Frozen sources: `complete-primary-word-batching-source-manifest.json`.
Focused execution: `classical-complete-primary-word-batching-tests.log`.
The complete continuation checks have passed in this live run; final source-word
comparison remains pending. This optimization supplies no latency benchmark or
adaptive soundness argument.

### XOF reader output consumption (validation pending)

The optional transcript observer now records bytes actually returned by every
SHAKE reader and the cumulative length per reader. This includes field streams,
64-byte field receipts, child seeds/finishes, checkpoints and byte challenges.
The standard reader and default-off path remain unchanged. The counter reports
aggregate output bytes and the maximum cumulative output length for one reader
for verifier, setup and prover scopes. No output byte contents are retained.
Metadata validation requires complete, nonnegative pairs when present, checks
query-count/total/maximum consistency and that field stream plus receipt bytes
are covered. An explicit CLI requirement rejects older missing observations;
without it older logs retain unknown metrics. Eight metadata tests pass.
A first integration-test compile failed on a reference/value mismatch in the
new assertion, retained in `classical-xof-output-observer-scope-tests.log`.
Corrected scope tests, split-read/disabled-observer unit test and feature/default
build checks are running under `classical-xof-output-observer-*-v2-tests.log`.
Frozen sources: `xof-output-observer-source-manifest.json`. Existing native
activity binaries predate this addition and cannot supply these output metrics.
Neither measured output lengths nor passed observer tests establish the missing
deterministic resource coupling or complete classical reduction.

The first runtime output-observer integration test caught an incorrect expected
receipt length: production receipts contain a 16-byte consumed-length prefix
plus a 64-byte digest (80 bytes framed), and consume 64 XOF output bytes. The
observer correctly reported 260 bytes against the test's mistaken 244-byte
expectation. Test and metadata lower-bound checks now use 64 digest bytes;
production framing and outputs were not changed. The v2 failure is preserved.

The v3 reader observer passes both scope/byte-preservation tests, the split-read,
zero-length-read and disabled-scope unit test, eight metadata tests and both
feature/default example checks. Evidence:
`xof-output-observer-v3-component-passed-audit.json`; corrected sources are in
`xof-output-observer-v3-source-manifest.json`. Toy proof-preservation execution
is queued in `classical-xof-output-observer-v3-toy-tests.log`.

The native honest-activity runner has completed one of four proofs. Its entire
correctness record equals the frozen native reference prefix. Setup observes
2502 standard hash outputs and no transcript XOF requests; the first prover
observes 19558 hash outputs and 1250 XOF requests. The accepted verifier observes
1663 hash outputs, 1250 XOF requests, no lookup retry, 3584382 field candidate
draws, maximum six candidates for one value and 14337528 consumed field bytes.
Evidence: `classical-honest-oracle-activity-native-progress-1.json`, with an
immutable log-prefix snapshot. This older frozen runner does not record total
XOF output consumption. Remaining proofs are live; this partial artifact does
not certify suite completion, deterministic bounds or native security.

The v3 XOF-output toy schedule now passes all four accepted proofs, four
altered-output rejections, setup and all proving records. Full correctness
records and every earlier measurement field (including honest activity) equal
the previous frozen runner. Required output counts pass input/output/field-receipt
consistency checks. Evidence: `xof-output-observer-v3-toy-passed-audit.json` and
`xof-output-observer-v3-toy-record-audit.json`. The frozen runner SHA256 is
`99d2fd4eab4fc710df4aeaac9b245dc8067dceff7e7ab088b675cf2ff0c8c8fe`.
Native output measurements are still missing from this revision; its passed toy
controls do not establish native bounds.

Source review separately accounts for fixed profile-ID SHA512 calls in successful
facade closures: one at successful preprocessing return, two in proving (profile
identity and parent transcript), as already counted twice for verification.
For the completed native prefix these add 356 setup input bytes and 712 prover
input bytes, raising sample hash calls from 2502 to 2503 and 19558 to 19560.
Evidence: `classical-native-honest-fixed-profile-hash-inventory.json`. These are
reviewed fixed calls, not observer output; parameter factories outside scopes,
all adversarial/rejected paths and deterministic global bounds remain excluded.

Native XOF-output execution is queued behind completion of the older native
honest-activity run, using its authoritative exit marker. Queue evidence:
`xof-output-observer-v3-native-queued.json`. The queued command uses the frozen
v3 runner and 16 workers, preserving the earlier run rather than restarting it.
Its driver will require four complete proof records, four rejections, all
setup/prover activity, output counts and exact prior proof/measurement equality.
These are debug correctness measurements, not performance trials.

The batched primary-word focused complete-PBS control passes (539.60s debug),
including all 258 primary claims and final 128 NTT/15 product/16 linear/15 lookup
source/seven helper claims. An independent strict source-control audit replays
all 12690 events. All counters and event multisets by phase match the earlier
focused unbatched control, and ordered XOF inputs match. The raw trace digest
differs: hash event ordering differs, so byte-identical traces are not claimed.
Evidence: `complete-primary-word-batching-passed-audit.json` and
`complete-primary-word-batching-record-audit.json`. The actual live binary digest
was captured in `complete-primary-word-batching-binary.json`. This is one
synthetic focused control, not full matrix completion. Debug runtime supplies
no matched production latency claim.


### Measured native resources versus conditional model ceilings

`tools/compare_classical_native_resources.py` joins a complete validated native
correctness/counter log to its exact descriptor's conditional resource model.
It requires accepted and rejected verifier measurements plus observed lookup
and field sampler stopping metrics. It compares hash/XOF counts, total/max input
lengths, field phase/value/draw/output counts and optional total/max XOF output
lengths. Two reviewed direct profile-ID hash calls (already included in the
model) are added to each recorded verifier sample, with exact descriptor-bound
input lengths; these calls are explicitly not marked observed. Honest setup and
prover work are not compared against verifier-invocation ceilings.
The report distinguishes within-ceiling observations, missing measurements and
execution outside the stopped domain. For v4 Brakedown the column stopping
condition remains unknown without its own observer. A sample passes only when
all compared metrics and stopping observations are present and consistent.
The report retains the model's missing protocol arguments and false resource,
security and performance admission flags even when a sample agrees.
Six comparison tests and eight counter-auditor tests pass, including excessive
resources, crossed stops, unknown output/v4 stop observations, binding/completion
failures and separate honest work. Evidence:
`native-resource-comparison-component-passed-audit.json`; frozen sources:
`native-resource-comparison-source-manifest.json`.
Full native-log comparison remains pending completion of the active native
measurement runs. The strict output invocation is:
`python3 tools/compare_classical_native_resources.py LOG --require-xof-output-counts --output NEW_REPORT.json`.
No sample report supplies an a priori bound or proves the full adaptive reduction.


### Sequential column rejection observations

An optional PCS `transcript-audit` feature now emits sequential column sampler
metrics at the actual Brakedown loop: accepted draws before transport dedup,
total candidate draws and the largest candidates for one accepted draw. The
snarks audit feature forwards it; default builds omit all counters/events. The
same original cutoff/modulo loop runs through a factored callback, without a
candidate limit. The v5 atomic-index branch is unchanged and emits no sequential
column event. Scoped verifier and honest-activity records aggregate the new
metrics. Older logs retain unknown metrics, rather than false zeros.
The metadata auditor accepts arbitrary nonnegative consistent counts, validates
that candidate queries and output bytes cover sequential draws, and supports
`--require-column-sampling-counts`. The native resource comparison now resolves
the v4 column stopping condition when these metrics are present, and reports
threshold excess as outside the stopped domain rather than a proof rejection.
Two Rust tests pass: 513 rejected candidates followed by the 514th acceptance,
and production-loop event counts with an independent exact transcript replay.
Nine metadata tests, six comparison tests and feature/default build checks pass.
Evidence: `column-retry-observer-component-passed-audit.json`; frozen sources:
`column-retry-observer-source-manifest.json`. A four-proof v4 toy comparison
against the frozen pre-column-observer runner is active under
`classical-column-retry-observer-{baseline,toy}-tests.log`. It must preserve full
proof/correctness records and all prior measurements. Native observations of
this new metric and the complete resource/security coupling remain unproven.

The native honest-activity schedule has completed successfully: four accepted
proofs and four altered-output rejections, one setup and four proving records.
All ordinary correctness records equal the frozen native reference, and previous
verifier measurement fields are unchanged. Evidence:
`classical-honest-oracle-activity-native-passed-audit.json` and
`classical-honest-oracle-activity-native-record-audit.json`. Earlier one-proof
snapshots remain historical partial evidence. The measured native scopes now
cover setup/proving Hash-trait outputs, transcript inputs, field draws and
lookup retries; they still omit total XOF output consumption and direct calls.
The conditional resource comparison runs successfully on all eight verifier
executions: every recorded metric is within its proposed ceiling and all
recorded stopping conditions hold. Its `all_metrics_recorded` and sample-pass
flags remain false because this frozen runner omitted total XOF outputs.
Evidence: `classical-native-observed-conditional-resources.json`.
The newer native XOF-output runner has now started after that predecessor's
successful exit; PID and command are in
`xof-output-observer-v3-native-running.json`. None of these results establishes
the remaining deterministic/adaptive security argument or performance gate.

The sequential-column observer v4 toy comparison now passes four accepted proofs
and four altered-output rejections. Every proof/correctness record and every
previous verifier/honest-activity measurement equals the frozen v3 runner's
baseline; accepted column draws require a maximum of one candidate in these
samples. The forced 514-candidate test separately verifies no runtime cutoff.
Canonical summary: `column-retry-observer-toy-verified-audit.json`; detailed rows:
`column-retry-observer-toy-record-audit.json`. The initial summary mislabeled
profile descriptor version 4 as `protocol_version`; the verified summary records
descriptor version 4 and wire protocol version 12, as validated in all proof
records, and retains a digest/reference to that earlier summary. The frozen
instrumented executable is `classical-column-retry-observer-runner`.
The complete native-output resource comparison is queued behind the active
native v3 output run (`classical-native-output-conditional-resources-queued.json`).
No native column observation, general coupling proof or performance claim follows
from the toy comparison.


The column metadata auditor now checks observed sampler choice against the
trusted descriptor: v5 and non-Brakedown profiles cannot report sequential
column events. Completed sequential Brakedown verifier/prover executions must
report positive sampling phases and accepted draws when these metrics are
present. Setup and early rejected verifiers may legitimately report zero work;
older missing metrics remain unknown. Ten metadata tests and six comparison
tests pass, including wrong backend/schedule and omitted completed sampling.
The real four-proof/four-rejection v4 toy log passes the stronger audit and its
entire audited report equals the prior report. Evidence:
`column-sampler-profile-binding-passed-audit.json` and
`column-sampler-profile-binding-toy-record-audit.json`; frozen sources:
`column-sampler-profile-binding-source-manifest.json`. No security admission
follows from this consistency check.


### Temporal XOF producer views (primitive coupling validation pending)

A shared analysis registry now records trusted 64-byte XOF-prefix answer events
and freezes each input's first pre-answer view. Producer entries retain their
first answer time; view tokens carry the issuing registry identity. Lookups
therefore cannot resolve their own answer, later producers or foreign views,
and repeated inputs keep the original view. A persistent epoch/token view avoids
copying the whole producer map on every query; legacy interpreter maps are only
materialized on request. Every overlapping 64-byte window of each supplied
oracle input is registered before its answer, without query/input cutoffs.
The registry records late availability hits and distinct-input output collisions;
callers must handle those bad events separately, rather than treating every
returned map as a security certificate. Repeated inputs must have consistent
answers. This is trusted oracle bookkeeping, not a verifier accepting producer
events from untrusted proof data.
Two bookkeeping tests pass, including late/self/foreign view rejection and
repeat/collision/availability handling. A first compile failed on an ambiguous
array conversion in the target iterator; its log is preserved. Evidence:
`xof-producer-history-bookkeeping-passed-audit.json` and
`xof-producer-history-source-manifest.json`.
A production worker-child primitive control captures actual pre-answer inputs,
replays their first 64-byte SHAKE prefixes into this registry and supplies the
existing receipt interpreter with a temporal producer map. It also checks that
a later receipt producer cannot repair a prior or repeated field-query view.
Execution is pending in `classical-xof-producer-history-prefix-tests.log`.
Analysis completion of a 64-byte prefix does not assert that production consumed
64 output bytes; actual output-length counters remain separate. This primitive
control does not establish full PBS admissibility, all-trials coupling or the
complete security/knowledge bound.

The temporal-producer production primitive test now passes (0.01s after build).
It captures five actual pre-answer inputs across a moved worker child, feeds
SHAKE-prefix completions to the temporal registry, resolves the worker field
receipt through the existing prefix receipt replayer, and rejects late repair
in both earlier and repeated field-query views. Observed/unobserved outputs
match; the control records zero availability hits and output collisions.
Together with the two bookkeeping tests, evidence is
`xof-producer-history-prefix-passed-audit.json` and the frozen source manifest.
This is one BabyBear primitive trace, not complete PBS prefix coverage or a
proof of generic fresh-phase/adaptive reduction. Full-stage trace coupling and
the complete security/knowledge argument remain open.


### Typed child temporal producer coupling

The temporal registry now supplies actual production typed-child prefix replay
across all eight supported extensions and schedules v4/v5 (16 controls). Each
control observes a moved worker child, its empty extension identity, two field
values, child finish and parent continuation: seven pre-answer inputs. The
existing typed-child parser resolves its parent seed and empty identity receipt
from the frozen producer view, binds the actual field/basis/request bytes, and
the existing receipt replayer matches all sampled base coordinates. Independent
framing reconstructs the complete child-finish and parent-continuation inputs.
Observed/unobserved outputs match. Missing seed producers, an altered trusted
profile and later seed/receipt producers cannot repair an earlier or repeated
candidate view. The reordered negative history records availability hits rather
than silently accepting its late producers; honest histories record no hits or
output collisions.
All 16 controls pass in one Rust test (0.94s runtime). Evidence:
`xof-typed-child-history-passed-audit.json`; frozen sources:
`xof-typed-child-history-source-manifest.json`. The first build's two incorrect
legacy field type names are preserved in `classical-xof-typed-child-history-tests.log`;
the corrected build uses the same intended degrees, without fallback.
These are typed child/receipt primitives with an explicit Brakedown descriptor,
not full PCS bodies or complete PBS admissibility. General adaptive coupling,
full security/knowledge and native performance qualification remain unfinished.


The generic typed-child prefix predicate now additionally checks a seed
producer's framed parent namespace/profile and exact fork label/context plus
64-byte seed request tail. Previously it checked the prior answer/preimage
match, leaving fork identification entirely to higher-level parent interpreters.
The full parent algebra/PCS body remains a higher-level obligation; the new
check does not replace those interpreters. Typed-child controls now also reject
a changed child label, changed context and use of a genuine earlier receipt
answer as a child seed. These require no forged oracle answer and test that
producer availability alone is insufficient for the typed link.
Frozen sources: `xof-child-origin-binding-source-manifest.json`; the 16 positive
controls and additional substitutions are rerunning in
`classical-xof-child-origin-binding-tests.log`. This modifies only analysis
prefix interpretation, not production transcript bytes or proof formats.

The strengthened typed-child origin predicate passes all 16 production typed
child controls (1.01s) and 48 additional substitutions of label, context or a
receipt output for the child seed. Honest observed/unobserved bytes remain
identical. Evidence: `xof-child-origin-binding-passed-audit.json`. This adds a
necessary framed fork-origin condition; it does not validate the intervening
parent algebra/PCS body or establish the complete adaptive reduction.


### Original views when following producer ancestors (validation pending)

The temporal registry now offers `producer_first_view`: it first checks that a
producer answer was available in the descendant's view, then returns that
producer input's own immutable first-query view. A successful edge strictly
decreases the query epoch; callers cannot use it to traverse a dependency cycle
or import descendant-only producers into an ancestor. A separate `first_view`
lookup supplies the recorded query view without authorizing an ancestor edge.
Two bookkeeping tests pass, covering original-view retrieval, unavailable
successors, unknown queries and foreign registries. Evidence:
`xof-ancestor-views-bookkeeping-passed-audit.json`; frozen sources:
`xof-ancestor-views-source-manifest.json`.
The 16 production typed-child controls now also follow their seed producer back
to the parent's original query view. The child's empty identity receipt must be
available in the child's later view but absent from the parent's first view.
Runtime validation is pending in `classical-xof-ancestor-views-prefix-tests.log`.
This is still primitive ancestor/receipt coupling, not full parent-body or
complete PBS admissibility.

The original-ancestor-view typed-child control now passes all 16 configurations
(1.18s). A child identity receipt available in the later child view remains
unavailable in its parent's original query view. Existing origin/profile/late
repair negatives also pass. Evidence: `xof-ancestor-views-passed-audit.json`.

The native XOF-output measurement run is now complete: four accepted proofs,
four altered-output rejections, one setup and four proving records. All proof
records and prior measurement fields match the preceding frozen native runner.
Evidence: `xof-output-observer-v3-native-passed-audit.json` and
`xof-output-observer-v3-native-record-audit.json`. This supplies the previously
missing observed output lengths for these native executions.
The exact-profile conditional resource comparison also completes with all
required metrics recorded: all eight verifier executions are within the proposed
ceilings and their observed stopping conditions hold. Evidence:
`classical-native-output-conditional-resources.json`. Its sample-comparison flag
is true, while deterministic resource coupling, protocol security and performance
qualification remain false. The separate earlier comparison without output
metrics remains incomplete historical evidence. Neither report establishes
bounds for all adversarial/rejected executions or the full adaptive reduction.


### Detached child temporal checkpoints (validation pending)

A second production typed-child control now covers detached extension children:
seed, parent checkpoint, empty identity stream/receipt, field stream/receipt,
repeated parent checkpoint, child finish and parent continuation (nine inputs).
It compares detached, scoped and unobserved outputs, verifies spent child
finalization rejects, reconstructs checkpoint and parent continuation inputs,
and feeds actual recorded query/answer events into temporal producer views.
Repeated checkpoint inputs must retain their first view and cannot gain the
child's later empty/field receipt producers. The existing typed-child parser
and field receipt replayer consume the resulting maps. Coverage is all eight
extensions under v4/v5, in addition to the existing scoped/primitive controls.
Frozen sources: `xof-detached-child-history-source-manifest.json`. The combined
three-test module is running in `classical-xof-detached-child-history-tests.log`.
These remain linked-transcript primitives, not complete PCS bodies or a full
PBS first-query/adaptive theorem.

The combined temporal-transcript module passes all three Rust tests (0.86s),
including 16 scoped and 16 detached typed-child controls. Detached/scoped and
observed/unobserved field outputs and parent continuations match. Repeated
checkpoint queries retain their original view, exclude child-only receipts,
and spent child finalization rejects. Independent framing matches actual
checkpoint/parent inputs. Evidence:
`xof-detached-child-history-passed-audit.json`. This closes that primitive
checkpoint/view integration check while leaving full PCS-body and whole-PBS
admissibility/reduction coverage open.


### Temporal producer replay on accepted monomial proofs (validation pending)

The accepted monomial event control now replays every captured hash-input window
and SHAKE input through the temporal XOF registry, completing the first 64 bytes
for analysis. It interprets every post-identity framed child query with the
existing typed-child predicate, using seed/empty-receipt producers retrieved
from the immutable first view. Ancestor lookup uses the parent's original view;
prover/verifier replayed child inputs must agree. Only producers needed by that
predicate are materialized; input windows remain fully registered without an
adversary-query cutoff. Honest availability/output-collision counts must be zero.
Existing strict/decoded verification, NTT/product source-word comparisons and
transcript continuation checks remain mandatory. Brakedown has no extension
child queries and must report zero; the other four backend controls require
positive coverage. A focused BabyBear/EF6 v5 PolyFRIM control is running in
`classical-monomial-temporal-producer-tests.log`; frozen sources:
`monomial-temporal-producers-source-manifest.json`.
This joins actual component proof events to typed producer ancestry. It does
not validate every child PCS body, the entire parent task prefix or full PBS
admissibility, and does not establish security/performance qualification.

The focused accepted monomial v5 PolyFRIM control passes (85.47s debug): all
82 post-identity verifier child queries match earlier prover inputs and resolve
seed/identity producers from their original temporal views. All captured input
windows were registered; the replay records zero XOF availability hits and
output collisions. Strict/decoded verification, NTT/product word comparisons
and continuations still pass. Every pre-existing control field equals the
corresponding prior 20-case monomial matrix record. Evidence:
`monomial-temporal-producers-focused-passed-audit.json`.
The current executable has been frozen separately and is now running the full
20-case two-field/v4-v5/five-backend component matrix. Its PID, executable digest
and source manifest are in `monomial-temporal-producers-matrix-running.json`;
log: `classical-monomial-temporal-producer-matrix-tests.log`. This is additional
accepted component producer-origin coverage, not full child-body or whole-PBS
admissibility. The older complete-PBS matrix remains live on its frozen revision.


### Actual monomial child source/ordered-claim binding (validation pending)

The accepted component temporal replay now derives six expected child seed
request tails from the strict reference verifier's actual NTT and product
obligations: coefficient/evaluation openings for each of two NTT components,
then the two product openings. Each tail binds the trusted source parameter
context, root, complete ordered query/value list, backend child label/context
and 64-byte seed request. Direct/dictionary claims use their production
normalization rule. Distinct verifier child seeds must match these six tails in
protocol order, in addition to temporal producer/origin checks. Brakedown has
no extension children and expects no such tails. Existing NTT/product word
comparisons remain required; this does not reconstruct arbitrary parent-prefix
algebra from candidate inputs.
Frozen sources: `monomial-temporal-claims-source-manifest.json`. The focused
PolyFRIM control is running in `classical-monomial-temporal-claims-tests.log`;
the earlier 20-case origin-only matrix remains active on its separate frozen
executable. Full component/body coverage of the stronger revision is unproven.

The stronger focused PolyFRIM control passes (86.70s): all six child openings
match the expected trusted source context/root and ordered query/value binding
in protocol order. All 82 temporal verifier child queries still match earlier
prover inputs, NTT/product word checks pass, and every previous control field
is unchanged. Evidence: `monomial-temporal-claims-focused-passed-audit.json`.
The stronger 20-case component matrix is queued behind successful completion
of the live origin-only matrix, using a separately frozen executable. Queue
metadata: `monomial-temporal-claims-matrix-queued.json`. It will additionally
require six bound openings per non-Brakedown control and zero for Brakedown.
The predecessor is left running; neither focused result certifies the queued
matrix or the whole-PBS arbitrary-candidate parent-prefix reduction.


### Ordered claim envelope decoding (validation pending)

A new analysis decoder reads the final ordered-claim/fork/seed envelope directly
from candidate parent bytes. It validates the framed namespace/profile and
backend labels, exact source parameter context, trusted claim count, variable
count, matrix widths/cell counts and lane-value row widths. Every nested vector
length must match the caller's trusted stage shape before entries are decoded;
canonical bincode spelling, complete body consumption and the 64-byte seed
request are required. Earlier parent frames are scanned with bounded slice
reads and constant frame-tail storage, without a query/trial cutoff. The
intervening parent algebra/PCS body is deliberately not certified by this
syntax/shape decoder, and well-shaped changed values denote another task.
A targeted test covers two fields, approved widths, v4/v5 and the four extension
child backends: 32 constructor configurations, malformed nested lengths,
truncation/trailing data, noncanonical lengths, foreign contexts and wrong seed
request lengths. Runtime validation is pending in
`classical-ordered-claim-envelope-tests.log`. Frozen sources:
`ordered-claim-envelope-source-manifest.json`. Actual component integration and
the complete parent-task/adaptive reduction remain pending.

The first ordered-claim envelope test build failed because the generic extension
fixture lacked serialization/deserialization bounds required by its PCS
constructors; the failed build log is preserved. Those bounds are now explicit,
with the same intended fields/degrees. Corrected sources:
`ordered-claim-envelope-v2-source-manifest.json`; kernel execution:
`classical-ordered-claim-envelope-v2-tests.log`. Component integration is still
pending after this kernel validation.

The corrected ordered-claim decoder kernel passes across all 32 constructor
configurations (0.13s), rejecting 416 malformed/caller-shape cases while
preserving changed well-shaped values as distinct tasks. Evidence:
`ordered-claim-envelope-v2-passed-audit.json`.
The actual monomial temporal replay now uses the decoder before accepting each
of its six child binding tails, then re-encodes the parsed root/queries/values
and checks them against the strict reference obligation. Trusted counts come
from the reference NTT/product stage shapes; candidate-declared nested lengths
cannot choose allocations. Source manifest: `monomial-bounded-claims-source-manifest.json`.
Focused execution is pending in `classical-monomial-bounded-claim-envelope-tests.log`.

The origin-only temporal monomial matrix has completed all 20 controls in
1087.10s debug, with all previous control fields unchanged. Temporal child
queries in verifier runs match earlier prover inputs, with zero recorded XOF
availability/output-collision events. Evidence:
`monomial-temporal-producers-matrix-passed-audit.json`. The separately frozen
ordered-claim-tail matrix has consequently started, recorded in
`monomial-temporal-claims-matrix-running.json`. These are component controls;
child-body/whole-parent admissibility and full security gates remain open.
The corrected two-field ordered-prefix regression also completed successfully
(5488.06s) on its frozen assignment-scope revision; evidence:
`accumulator-prefix-assignment-scope-broad-passed-audit.json`. This preserves
conditional earlier-opening scope and does not retroactively validate later
prefix revisions or the all-backend full regression.

The actual-proof decoder integration passes the focused v5 PolyFRIM control
(87.33s). Each of the six captured child request envelopes passes trusted-count
nested decoding and re-encodes to its strict reference source/query/value
obligation. All 82 temporal child checks, first-declaration NTT/product word
comparisons and earlier control fields remain unchanged. Evidence:
`monomial-bounded-claims-focused-passed-audit.json`. A separately frozen
20-case decoder-integration matrix is queued behind the active claim-tail
matrix (`monomial-bounded-claims-matrix-queued.json`). Syntax preflight and
these accepted controls do not establish arbitrary parent-body admissibility,
claim truth without source authentication, or complete security qualification.


### Frozen-source ordered-claim task classification

The ordered-claim helper now classifies a decoded task against a supplied
immutable first-declaration source view. It uses the existing role/context
preflight, shared frozen-word decoder and joint-nearness promise, then compares
every ordered query response with normalized claimed values. A task is bad if
its source promise fails or any claim differs; malformed counts/row widths or
unsupported geometry return no classification. View timing and hash availability
remain caller obligations, rather than being asserted by this helper.
The actual monomial control supplies captured first-declaration views for each
of its six child requests. All six tasks classify true. Perturbing each task's
first claimed value, while keeping its word/view/query fixed, classifies it bad
with the source promise unchanged. The focused PolyFRIM control passes (59.77s
debug) and all earlier proof/trace fields remain unchanged. Evidence:
`monomial-fixed-source-tasks-focused-passed-audit.json`; frozen sources:
`monomial-fixed-source-tasks-source-manifest.json`. Its 20-case matrix is queued
behind the active bounded-decoder matrix, using a separate frozen executable.
This adds deterministic fixed-word task classification, not the complete
first-query/fresh-phase argument or a security admission result.

The prior ordered-claim-tail matrix has completed all 20 controls (962.31s
 debug), preserving every previous control field and binding six opening groups
per non-Brakedown case. Evidence:
`monomial-temporal-claims-matrix-passed-audit.json`. The newer bounded-decoder
matrix consequently started, recorded in `monomial-bounded-claims-matrix-running.json`.
These remain accepted component controls; full PCS-body/whole-PBS coupling and
security/performance qualification are still open.

The bounded-decoder component matrix now passes all 20 controls (1017.72s),
preserving previous fields and preflighting every recorded child claim envelope.
Evidence: `monomial-bounded-claims-matrix-passed-audit.json`.
The queued fixed-source-task matrix encountered an orchestration race before
launch: it saw a predecessor marker after file creation but before JSON
serialization finished. The queued driver exited 1 with JSONDecodeError; no
test process or matrix log had started. Evidence:
`monomial-fixed-source-tasks-matrix-queue-failure.json`. The same frozen executable
has now been launched from the fully parsed completed predecessor evidence,
with its checksum reverified. This recovery is from a terminal startup failure,
not an elapsed-time restart of a live validation run.
New `tools/audit_artifacts.py::write_json_new` closes/fsyncs a same-directory
temporary file before atomically linking it into the final name, with exclusive
no-overwrite behavior. Three tests cover a paused partial serializer, immutable
existing artifacts and encoding failures. Evidence:
`atomic-audit-artifacts-passed-audit.json`. The recovered matrix uses this helper
for publication of running/exit/passed records; its PID is in
`monomial-fixed-source-tasks-matrix-running.json`.

### Structural successful Brakedown setup hash count

`tools/classical_setup_resources.py` derives a setup-only count from the trusted
descriptor and explicit BR/KS radix widths, independently of measured activity.
For successful canonical classical preprocessing, validation hashes four role
contexts; BR and KS preparation each hash one context. BR commits twice its
native radix digit count in source tables; KS commits one final-source table
per digit. A Brakedown commitment hashes at most L leaves, L-1 internal Merkle
nodes and one parameter context, hence at most 2L standard hash outputs.
The facade adds exactly one direct profile-ID hash and uses no transcript XOF.
All-zero serialized columns may reduce leaf hashing, so this is an upper bound.
The supported native fields use ceil(modulus_bits / radix_bits) digits here.

For the recorded BabyBear v5 width-eight profile, radix widths 8/5 give eight
BR tables with L=128 and seven KS tables with L=32: 2502 standard hashes and
2503 including the profile ID, agreeing with the independently observed setup.
Three focused tests pass, including the wider Goldilocks source domain and
rejection of unsupported backends/radices. An initial test expectation omitted
the factor of two for Goldilocks leaf/internal hashing; it was corrected to
17222 standard hashes for that test geometry. Evidence and frozen sources:
`structural-setup-resources-native-audit.json` and
`structural-setup-resources-source-manifest.json` under the opening inventory;
test log: `classical-structural-setup-resources-tests.log`.
This closes the hash-query-count inventory for this successful setup path only.
Factories/native key generation, hash-input byte bounds, prover resources,
arbitrary rejected verifier paths and the all-trials reduction remain outside
its scope. Security and performance admission remain false.

The subsequent setup-byte revision also bounds the hash inputs on that same
successful Brakedown path. Standard bincode uses at most nine bytes per native
usize/u64; BabyBear and Goldilocks serialize one u32/u64 newtype. A column leaf
contains its domain tag, a vector length and exactly
`2^left_vars * width * block_width` field entries. Internal nodes hash 128 bytes.
The parameter context contains two modulus strings, six metadata usize values,
the block-RS domain slice, four code usize fields and one base-field root.
Applying these conservative bounds to each leaf/node/context, including the
six external contexts and exact profile-ID input, gives deterministic setup
total/max input-byte bounds without interpreting observations as caps.
Three focused tests pass. Frozen sources and the native numeric result are
`structural-setup-byte-resources-source-manifest.json` and
`structural-setup-byte-resources-native-audit.json`; earlier count-only evidence
is preserved. No input-byte observation is claimed. Proving, rejected verifier
paths, parameter factories/key generation and full all-trials coupling remain
open; no security/performance admission follows from this setup-only bound.

The conditional classical-work worksheet now accepts `--brakedown-setups N`
with `--classical-work` and all three explicit honest offsets. In this mode,
those offsets cover remaining honest work only; the calculator adds N times
the structurally derived native radix-8/5 setup hashes/XOF queries/root counts.
N counts original preprocessing invocations over the modeled lifetime, not
proofs reusing a retained key. The report includes the per-setup inventory and
marks remaining offsets unestablished and all honest work unbounded. The
existing mode retains its original total-offset interpretation. Unsupported
backends, nonpositive setup counts, missing remaining offsets and invalid
integer offsets fail before producing a report. No setup-only total is silently
substituted for total honest work and no admission flag is enabled.
Seventeen focused/existing worksheet tests pass, including equality with direct
offset addition and CLI validation. Evidence:
`work-setup-inventory-passed-audit.json`, frozen source manifest
`work-setup-inventory-source-manifest.json`, log
`classical-work-setup-inventory-tests.log`. Full prover resource accounting,
adversarial prefix/source composition and matched native performance remain open.

### Native prover fresh-commitment inventory

`prover_commitment_resources` now inventories all fresh table commitments in the
successful native shared-radix classical schedule, separately from retained key
setup. With BR digit count d, KS digit count s and lookup repetitions r, role
counts are `[6d+12, 2dr, 3s+4, sr]`. The explicit stage breakdown covers main
coefficient/evaluation tables (2d+1 each), four accumulators, two decomposition
inputs, two monomial evaluations, two sets of d+1 borrows, two sets of dr
reciprocal helpers, final coefficient/evaluation tables (s+1 each), one final
input, s+1 final borrows and sr final reciprocal helpers. Native BR/KS roots
are borrowed from retained setup and are not recommitted. The comparison request
builder emits one request per digit; each repetition emits exactly one helper.
Radix widths remain the native worksheet's fixed 8/5. This inventory covers
classical descriptor versions four and five with the reviewed Brakedown backend.

For the recorded BabyBear profile at r=1, 76 fresh roots require at most 19456
hash calls and 3787937044 total hash-input bytes for commitments alone, including
each commitment's parameter context. All-zero optimizations can reduce this.
External contexts, openings and profile-ID calls are excluded, so these numbers
must not be used as a full honest prover offset. The full-prover flag stays
false. Eighteen focused/existing tests pass, including repetition scaling and
Goldilocks's 132 fresh-root schedule. Evidence:
`prover-commitment-resources-native-audit.json`, frozen sources
`prover-commitment-resources-source-manifest.json`, log
`classical-prover-commitment-resources-tests.log`. Full source/prefix security
composition and security-matched performance qualification remain open.

The prover resource helper now separately bounds successful native Brakedown
opening hash work. `open` and `open_many` each hash a parameter context for the
retained-state check and another for transcript binding, then copy the retained
Merkle paths without hashing leaves/internal nodes. Using the existing shared
native stage call ceilings gives `[86,8,64,7]` opening calls for BabyBear and at
most 330 hash calls / 65670 hash-input bytes in this portion. Root aliases can
reduce calls. Both classical descriptor versions four/five are covered; the
helper rejects non-native 1024/728 dimensions. It excludes commitments and
external contexts and does not claim a full prover resource bound. Nineteen
focused/existing tests pass. Evidence:
`prover-opening-hash-resources-native-audit.json`, frozen sources
`prover-opening-hash-resources-source-manifest.json`, log
`classical-prover-opening-hash-resources-tests.log`. Accounting for external
prover contexts and full honest XOF/stopping composition remains open.

### Successful native prover SHA512 resource union

`prover_hash_resources` now combines the fresh-commitment and successful-opening
inventories with all external parameter-context hashes and two direct profile-ID
hashes for the selected native Brakedown v12 facade. The shared verifier's parent
context inventory applies to the prover's same binding helpers, including both
outer validations (the second occurs inside `bind_inner`). The prover additionally
borrows BR and KS owners before witness preparation (one source context each)
and performs an extra final-stage preflight before final binding (six source
contexts and one helper). Thus external context calls are `[177,15,144,16]` for
BabyBear: 352 total. Shared comparison context counts follow their bind, linear
source list, per-digit lookup preflight, registry and used-source claim loops;
those are the same on successful prove/verify paths.

The resulting successful-prover SHA512 upper bound is 20140 calls and
3788073474 input bytes for the recorded profile. The four independently observed
prover samples, after adding two reviewed direct profile hashes, are
`[19560,19560,19560,19558]`, all below this bound; observations did not determine
the bound. Input-byte observations remain absent. Twenty focused/existing tests
pass. Evidence: `successful-prover-hash-resources-native-audit.json`, frozen
sources `successful-prover-hash-resources-source-manifest.json`, log
`classical-successful-prover-hash-resources-tests.log`. This establishes only the
successful selected prover SHA512 path's resource inventory. Setup is separate;
XOF/retry/stopping resource accounting, rejected prover paths, full adaptive
soundness/knowledge and security/performance admission remain incomplete.

### Conditional stopped honest-prover XOF model

`prover_stopped_resource_model` combines successful prover SHA512 accounting
with the existing typed verifier XOF query/frame/output envelopes, explicitly
conditional on the successful honest prover and matched verifier having the
same request schedule and the source/claim/frame bounds covering that schedule.
It stops analysis at the first reciprocal rejection, a field value requiring
more than 512 candidates, and (v4 only) a column draw requiring more than eight
candidates. Production loops remain uncapped. Fresh independent ideal streams
remain a premise of sampler stop charges. The model does not mark the
prover/verifier resource coupling or unconditional honest-resource bound proved.
For the recorded v5 profile its ceilings include 1265 XOF requests and 544
field phases. Four native completed samples have exactly matching prover and
verifier XOF/retry/field metrics, no reciprocal rejection, and stay inside all
recorded model query/input/output ceilings. This is a sample control, not a
proof of schedule domination or arbitrary candidate admissibility.
Thirty-three focused/existing tests pass. Evidence:
`prover-stopped-resource-model-native-audit.json`, frozen sources
`prover-stopped-resource-model-source-manifest.json`, log
`classical-prover-stopped-resource-model-tests.log`.

The fixed-source-task monomial matrix has completed all 20 controls (952.61s
debug), preserving previous control fields and checking true/perturbed-false
tasks for each non-Brakedown child opening. Its published summary and all raw
records were independently compared, with the log digest verified. Evidence:
`monomial-fixed-source-tasks-matrix-passed-audit.json` and
`monomial-fixed-source-tasks-matrix-record-audit.json`. Whole-PBS coverage and
the full admissible-prefix reduction remain false. The older full-PBS and
final-key source-word jobs remain live; no security/performance admission follows.

### Exact successful prover/verifier request-stream control

`tools/compare_classical_xof_request_streams.py` verifies an immutable trace's
SHA512 fingerprint and every standard-hash preimage/output, then compares
ordered prover/verifier XOF inputs byte-for-byte with bounded IO buffers.
It rejects changed counts, lengths, contents/order, corrupt/truncated traces
and files changed during the comparison. The initial focused comparison failed
because the synthetic harness captures three additional post-prover continuation
requests, while its verifier capture ends at proof acceptance. The failure is
preserved in `exact-xof-request-stream-initial-mismatch.json`; it does not show
a protocol request mismatch.

An explicit continuation mode requires exactly three extra prover requests:
the known prime-field continuation request suffix, consumed-field receipt
namespace, and 32-byte continuation request suffix. It reports full captured
streams unequal and the protocol prefix equal, with the three exclusions
explicit; it does not claim full continuation semantic replay. Without this
mode any extra request fails. Ten tests pass, including chunked large requests
and malformed/missing/extra continuation suffixes. The existing focused full-PBS
trace passes exact comparison of 795 protocol requests / 332599739 input bytes.
Evidence: `exact-xof-request-stream-v2-focused-audit.json`; source manifest
`exact-xof-request-stream-v2-source-manifest.json`; test log
`classical-exact-xof-request-stream-v2-tests.log`.
The same comparison is running on all 20 earlier completed streamed controls,
with immutable per-control progress files and PID recorded in
`exact-xof-request-stream-v2-matrix-running.json`. These controls concern saved
successful executions; arbitrary-stream schedule coupling and full security
qualification remain unproved.

### Explicit honest lifetime inventory in the work calculator

`candidate_classical_work_for_lifetime` and CLI `--brakedown-proofs N` now add
derived native successful setup/prover costs to explicitly supplied remaining
honest offsets. The CLI also requires `--brakedown-setups`, `--classical-work`
and all three remaining offsets. Counts describe original preprocessing and
proving invocations over the modeled honest lifetime, not adversarial query
cutoffs. Hash offsets use structural successful-path inventories; prover XOF
offsets use the conditional stopped resource model. Fresh root offsets count
setup roots and fresh proof commitments separately, preserving retained-key
reuse. Factories, key generation and all other activity must be covered by the
remaining caller assumptions. The report explicitly retains unproved
prover/verifier XOF coupling, honest stopping composition and remaining-resource
coverage; full honest-work and security/performance flags stay false.
Thirty-four focused/existing tests pass, including exact agreement with manually
adding the derived offsets and successful CLI lifetime inventory. Evidence:
`lifetime-resource-inventory-passed-audit.json`, frozen sources
`lifetime-resource-inventory-source-manifest.json`, log
`classical-lifetime-resource-inventory-tests.log`.

### Final-key temporal child-origin control

The actual final key-switch control now replays every captured hash/XOF input
through the temporal XOF producer ledger and checks every post-identity typed
child request, including the shared lookup child. Each check obtains the seed
and empty-identity receipt producers from the request's original earlier-query
view, validates typed child initialization and label/context/profile-bound parent
origin, and obtains the seed producer's own first-query view. Repeated verifier
requests must already appear in the prover capture. Every input window is
registered before the corresponding answer; availability/output-collision counts
must remain zero in these positive controls. The new helper reports child-query
and unique-seed counts separately from existing source-word checks. It does not
assert PCS/lookup body admissibility or whole-PBS security.
Frozen sources: `final-key-temporal-origins-source-manifest.json`.
Focused Brakedown final-stage execution is building/running in
`classical-final-key-temporal-origins-focused-tests.log`; runtime validation is
pending. The older final-key/full-PBS jobs remain on their frozen revisions.
The independent exact XOF request matrix has reached 14 completed controls,
with individual results preserved in its progress artifacts.

### Conditional native lifetime query grid

The derived lifetime calculator was evaluated on Brakedown v5 profiles for
BabyBear/degree6/width8 and Goldilocks/degree3/width4, at common role query counts
64,128,256,512,1024,2048. The explicit hypothetical honest lifetime is one setup
and 21 proofs. Remaining honest offsets are assumed zero for this worksheet,
not established zero. For both fields the conditional 128-bit work target fails
through 512 and passes at 1024/2048. This identifies the least passing point in
that finite grid, not a global optimum or admitted production query count.
All candidate descriptors, exact work polynomials, derived/assumed offsets and
unproved premises are retained in `lifetime-query-grid-conditional-audit.json`.
Frozen sources, including the diagnostic fixture descriptor encoder, are in
`lifetime-query-grid-source-manifest.json`. No adversarial-query cutoff is
introduced. Full security admission, actual honest remaining-resource coverage
and matched performance remain open. The independent exact-request matrix has
now reached 19/20 completed controls; the final-key temporal build is still live.

The exact request-stream comparison has now completed all 20 controls, with
protocol request inputs equal byte-for-byte and exactly three validated harness
continuation requests excluded per prover capture. Evidence:
`exact-xof-request-stream-v2-matrix-passed-audit.json`; independently aggregated
counts/digest: `exact-xof-request-stream-v2-matrix-summary-audit.json`. Both
fields, descriptor versions four/five and all five backends are represented.
The captured full streams are intentionally reported unequal because of those
extra continuation probes. This establishes saved successful-control equality,
not the all-stream resource coupling premise or whole-PBS soundness/knowledge.

### Exact prefix reuse in the temporal target index

The analysis-only XOF ledger now caches prior inputs under their exact first
64 bytes. For a matching key, it compares the actual shared prefix and indexes
windows starting at `shared_length.saturating_sub(63)`. Every omitted window
lies wholly inside a previously indexed exact prefix; every crossing/new window
remains registered before the answer. Inputs shorter than 64 bytes have no
eligible window. No fingerprints, lossy membership filters or query caps replace
the exact target set. Cached input Arcs are shared with query bookkeeping.

Three standalone Rust ledger tests pass (1.42s), including differential equality
against a naive complete window set across every prefix boundary of a 256-byte
input, repeated inputs, and detection of a newly appended boundary target before
its answer. Earlier first-view/late-repair/collision tests also pass. Evidence:
`xof-prefix-target-index-standalone-passed-audit.json`, frozen sources
`xof-prefix-target-index-source-manifest.json`, log
`classical-xof-prefix-target-index-standalone-tests.log`. The normal helper Cargo
test is also running in `classical-xof-prefix-target-index-tests.log`.
The pending final-key temporal build began on its separately frozen earlier
ledger revision; its result will not validate this newer index implementation.
No native performance or whole-protocol security claim follows from these tests.

The normal Cargo helper integration run also passes all three ledger tests
(2.11s), agreeing with the standalone result. Evidence:
`xof-prefix-target-index-cargo-passed-audit.json`. The final-key temporal test's
Cargo invocation remains live while its other test targets finish compiling;
the selected focused test has not yet produced a runtime result.

The earlier frozen final-key temporal executable has now started its focused
runtime test (PID/session in `final-key-temporal-origins-focused-running.json`;
binary fingerprint in `final-key-temporal-origins-focused-binary.json`). It is
still live and has no result yet. Its ledger remains the earlier frozen
pre-prefix-cache revision.

### Temporal seed origin at initial child identity requests

The newer temporal child checker also validates the initial zero-value identity
request, before its own empty-field receipt exists. It follows the seed producer
from that request's original view, checks the producer's SHAKE answer and exact
profile/application/fork-label/context/64-byte-seed-request framing, and requires
repeated verifier identity requests to have appeared earlier in the prover trace.
Later requests retain the existing receipt and typed-child checks. Initial
identity counts are reported separately. This closes a coverage omission in
the control: the earlier checker skipped these deterministic identity requests
and checked seed origin only at later child requests. It does not establish
arbitrary parent-body admissibility.
A targeted regression constructs an initial request without any empty receipt
producer, checks wrong label/context rejection, and requires an identity request
queried before its seed producer to fail even when repeated after that producer.
Sources: `temporal-initial-identity-source-manifest.json`; execution pending in
`classical-temporal-initial-identity-tests.log`. The existing final-key runtime
test continues on its earlier frozen revision; no restart or result upgrade is
inferred from the newer source change.

The initial-identity regression passes (one Rust test, 0.01s). Its intentional
late-producer panic is caught by the negative assertion, and the test exits zero.
Evidence: `temporal-initial-identity-passed-audit.json`. The earlier frozen final-key
temporal runtime also passes (387.80s): 28 post-identity verifier child requests,
one seed, zero availability/output-collision events, and all final-stage
source-word groups remain checked. Evidence:
`final-key-temporal-origins-focused-passed-audit.json`. It does not retroactively
cover initial identity requests or the newer prefix-cache ledger.

The current executable, which includes both additions, is frozen as
`classical-final-key-initial-origins-runner` with fingerprint in
`final-key-initial-origins-binary.json`. All 515 Rust/Cargo source files have been
snapshotted in `final-key-initial-origins-source-manifest.json`. A separate
20-case final-key matrix has started from that executable; PID/log/source
binding is in `final-key-initial-origins-matrix-running.json` and runtime log is
`classical-final-key-initial-origins-matrix-tests.log`. This validates a changed
revision and does not replace/cancel the older still-live source-word matrices.
Full generic adaptive security and matched native performance remain open.

### Final-key child ordered-claim binding

The newer final-key control constructs expected PCS child binding tails from
the independent strict final-stage obligations, in protocol order: known input,
both sides of each NTT, product factors, decomposition linear sources, reciprocal
helpers, grouped lookup sources, extraction. Lookup source aliases are grouped
by first root occurrence within the shared native role/context. Each unique
verifier PCS child seed is traced to its original parent input, which must pass
trusted-count nested ordered-claim decoding and re-encode to exactly the expected
binding tail. The lookup child's distinct algebra body remains outside this PCS
claim-envelope check. Existing frozen-word assertions still check every reference
claim; they are not replaced by syntax matching or repeated per opening.

The generic temporal checker now offers a callback for each unique verifier seed,
including its initial identity request, after producer-origin validation. The
new final-key binding count is reported separately. Source manifest:
`final-key-child-claim-bindings-source-manifest.json`. Build/kernel regression is
pending in `classical-final-key-claim-bindings-build-tests.log`; an accepted
non-Brakedown runtime control is still required. The live 20-case matrix remains
on its frozen initial-origin revision and does not validate this later addition.
No full parent/PCS-body admissibility or security admission is claimed.

The child-claim binding revision compiles and its seed-origin regression passes
(one test, 0.01s); evidence:
`final-key-child-claim-bindings-build-passed-audit.json`. A focused PolyFRIM
final-key control has now been added and started in
`classical-final-key-child-claim-bindings-focused-tests.log`. This subsequent
revision explicitly asserts the shared source-role context assumption before
root alias grouping and normalizes the independently evaluated known-input claim
through its backend. Temporal/envelope checks run before expensive source-word
decoding, while the latter remains required for a successful complete control.
The focused source overlay is frozen in
`final-key-child-claim-bindings-focused-source-manifest.json` against the full
initial-origin source snapshot. Accepted non-Brakedown runtime binding validation
is pending; the live initial-origin matrix is still a separate earlier revision.

The focused PolyFRIM claim-binding control compiled successfully (1m45s) and
has started runtime validation. Its live PID, executable fingerprint, source
overlay and log are bound in
`final-key-child-claim-bindings-focused-running.json`. No passing result or
non-Brakedown binding count is claimed yet.

### Lazy immutable first-declaration word views

The shared analysis `History` now records each digest's first answer epoch and
each eligible target window's first declaration epoch, instead of eagerly
cloning a complete known-preimage map as new eligible hash answers arrive.
`view(root)` materializes only answers strictly before that root's original
declaration, applying the same hash-input eligibility filter, then caches the
immutable Arc by the eligible-answer prefix at that declaration. Declarations
with no intervening eligible answer share a view.
Leaf traversal enforces that same cutoff directly against immutable known
preimages and their first-answer epochs. Later answers/repeated declarations
cannot update a cached view. Every target window and availability count remains
registered at the original event boundary. This changes analysis storage/work,
not production proving or the cryptographic model.

The word-history integration tests now use the public `view` API rather than
inspect the eager snapshot map. A new differential test compares all materialized
views and first-declaration epochs with an independent eager model after each
event, including late answers, repeated answers, shared declarations and input
eligibility filters. The first build failed on two Arc borrow conversions and a
closure borrow lifetime; diagnostics are preserved in
`lazy-history-views-initial-build-failed.json`. Corrected sources are frozen in
`lazy-history-views-v2-source-manifest.json`; the full word-history integration
suite is running in `classical-lazy-history-views-v2-tests.log`. Existing live
source-word/claim-binding jobs retain their earlier frozen history revisions.

The corrected lazy-view build runs the full suite: the eager-vs-lazy differential
test and production leaf grammar/projection controls pass, but the existing Arc
sharing test fails (four passes, one failure). Keying cached views by declaration
epoch failed to preserve sharing across XOF requests with no new eligible answer.
Evidence: `lazy-history-views-v2-sharing-failure.json`. The subsequent revision
records eligible first-answer epochs and keys materialized views by the number
strictly before each declaration. It preserves the original contents/cutoff and
shares views across equal eligible-answer prefixes, including intervening
ineligible hash answers. Sources: `lazy-history-views-v3-source-manifest.json`;
full rerun pending in `classical-lazy-history-views-v3-tests.log`. The original
sharing assertion remains unchanged.

The eligible-answer-revision lazy history now passes all five word-history tests
(2.15s), including the unchanged Arc-sharing assertion, eager snapshot
differential, actual production leaf grammars and projected stream replay.
Evidence: `lazy-history-views-v3-passed-audit.json`. A separately logged PolyFRIM
final-key claim-binding control has started on this history revision in
`classical-final-key-claim-bindings-lazy-history-tests.log`. It validates the new
storage implementation in the real capture/decode path; the earlier frozen
control remains live and is neither replaced nor cancelled. The optimization
affects audit storage/work only, not native proving latency qualification.

The word-history target registry now also reuses exact shared prefixes, retaining
every crossing/new window and the original first-declaration epochs. Its expanded
eager-model differential includes a new boundary after an earlier root declaration
and a return to the shorter prefix, under each eligibility-filter configuration.
All five word-history tests pass (2.62s). Evidence:
`prefix-lazy-history-passed-audit.json`, sources
`prefix-lazy-history-source-manifest.json`, log
`classical-prefix-lazy-history-tests.log`. The live lazy-history PolyFRIM control
uses the preceding eligible-answer-revision implementation, not this later
prefix-index addition.

The earlier focused PolyFRIM final-key claim-binding control now passes
(701.53s debug): all 63 PCS child opening envelopes match strict reference tasks;
64 initial identity requests and 602 post-identity child requests pass temporal
origin checks, with zero availability/output-collision events. All 128 NTT,
15 product, 16 decomposition-linear, 15 lookup-source and seven helper word
claims also pass. Every earlier input/extraction-only control field, including
proof bytes and verifier counters, matches the prior frozen matrix observation.
Evidence: `final-key-child-claim-bindings-focused-passed-audit.json`. This result
uses the frozen pre-lazy word history and does not validate the newer storage
revisions or establish arbitrary parent/PCS-body admissibility. The separate
lazy-history integrated control is now running after successful compilation.

The initial-origin matrix has completed its first case, BabyBear v4 Brakedown,
with one initial identity request, 28 later child requests and all final-stage
word groups checked. Prior control fields remain identical. Its immutable
partial log/record audit is `final-key-initial-origins-matrix-progress-1.json`;
the whole suite remains live and incomplete. Separately, the current claim-binding
revision with both word-history optimizations is being compiled for broader
validation (`classical-final-key-bound-claims-matrix-build.log`). Frozen source
overlay: `final-key-bound-claims-source-manifest.json`. Launch is pending the
current lazy-history focused control's result, rather than treating its ongoing
execution as a pass.

The current claim-binding matrix executable has compiled successfully (2m22s)
and is frozen as `classical-final-key-bound-claims-runner`; fingerprint/source
binding is in `final-key-bound-claims-binary.json`. It includes the eligible-answer
lazy views and exact-prefix word target index. Launch remains pending the live
preceding lazy-history focused control, whose PID/executable/source binding is
recorded in `final-key-claim-bindings-lazy-history-running.json`. No unfinished
runtime validation has been promoted to a passing result.

### Independent final-key record auditor

`tools/audit_classical_final_key_controls.py` validates completed control groups
without inferring suite completion from a live log. It checks record order and
identity, the selected synthetic field/schedule/backend geometry, all five exact
source-word claim counts, nonzero key/input/extraction flags, initial identity
and child-seed coverage, zero positive-control availability/collision events,
and (when required) nested claim preflight and binding counts against the native
stage range. In this one-repetition final stage there is one lookup child and
one child per non-Brakedown PCS opening; the binding/seed counts must agree.
An incomplete trailing group or partial line is reported as incomplete, never
counted as a complete control. Cryptographic assertions remain source/test
obligations and every security/performance/suite-completion flag remains false.

Four auditor tests pass, rejecting malformed identities/counts, record ordering,
missing bindings, unexpected availability events and claimed admission, while
preserving a live partial tail. The real focused PolyFRIM 63-binding record
group and the completed live initial-origin control pass the independent audit.
Evidence: `final-key-child-claim-bindings-focused-record-audit.json`,
`final-key-initial-origins-matrix-record-progress-1.json`; sources
`final-key-control-record-auditor-source-manifest.json`; test log
`classical-final-key-control-record-auditor-tests.log`.

The lazy-history PolyFRIM integration control has completed successfully
(682.54s debug). All three complete record groups—63 PCS claim bindings,
64 initial/602 later child requests, and every final-stage source-word count—are
exactly equal to the earlier eager-history control, including proof bytes and
verifier counters. Evidence:
`final-key-claim-bindings-lazy-history-passed-audit.json`. This validates the
eligible-answer lazy views in the accepted component path; it does not qualify
native proving performance or the later prefix-index addition by itself.

The frozen current executable, including that prefix index and the final-key
claim bindings, has now started its own 20-case matrix. PID, binary hash and
source/auditor bindings are in `final-key-bound-claims-matrix-running.json`;
runtime log: `classical-final-key-bound-claims-matrix-tests.log`. Final completion
requires exit zero, independently valid claim/origin/source record groups and
exact coverage of both fields, both schedules and all five backends. Older live
matrices remain separate and are not restarted or retroactively upgraded.

The two exact-prefix audit indexes now first use slice-prefix comparisons for
the common append-only and shorter-prefix cases, retaining the byte-wise longest
common prefix fallback for other inputs. Window indexing boundaries, first
declarations, producer views and cache keys are unchanged. All eight helper/word
history tests pass (three XOF-ledger tests and five word-history tests), including
naive/eager differential and immutable-view sharing. Evidence:
`slice-prefix-index-passed-audit.json`; sources
`slice-prefix-index-source-manifest.json`. This is analysis-only work; no native
prover latency qualification is inferred.

The frozen bound-claim matrix has completed its first case (BabyBear v4 Brakedown):
zero extension PCS child bindings as expected for this backend, one initial
lookup identity, 28 later child requests, zero availability/collision events,
and all final-stage word groups checked. The independent record auditor accepts
the completed group. Partial log/evidence:
`final-key-bound-claims-matrix-progress-1.json`. The matrix remains live and
incomplete on its separately frozen pre-slice-fast-path revision.

### Exact selected-root prefix prefilter

The streamed selected-root projection now builds a 65536-entry two-byte prefix
table from its fixed selected digest set. A window whose first two bytes match
no selected digest cannot be a selected root and skips the full digest lookup;
every remaining candidate still requires exact 64-byte set membership. Prefix
collisions do not freeze unselected roots. This changes neither selected roots
nor first-declaration timing and imposes no root/query-count limit.
All six word-history tests pass (1.52s), including production leaf grammars,
projection replay, eager/full-history equivalence, and a new colliding-prefix
test with selected/unselected roots at offsets 0,1,31,63,64,65,127. Evidence:
`projection-prefix-prefilter-passed-audit.json`; frozen sources
`projection-prefix-prefilter-source-manifest.json`.

The complete-PBS focused all-source-word control is now building/running with
this projection and current history optimizations, logged in
`classical-complete-pbs-prefix-projection-tests.log`; its source overlay is
`complete-pbs-prefix-projection-source-manifest.json`. Its runtime result is
pending. This is audit-path validation, not native proving latency qualification;
the older full source-word matrix and final-key matrices retain their own frozen
revisions and remain separate live validations.

The bound-claim matrix has completed two cases: BabyBear v4 Brakedown and
PolyFRIM. The latter binds 63 PCS openings, checks 64 initial identity/602 later
child requests and all five final-stage source-word groups, with zero recorded
availability/collision events. The independent record auditor accepts both
complete groups; every prior control field (including proof bytes and verifier
counts) matches the older frozen observations. Immutable partial log/report:
`final-key-bound-claims-matrix-progress-2.json`. Suite completion, all-field/backend
coverage and full security qualification remain unproved.

The complete-PBS optimized-projection focused control passes (114.33s debug).
It checks 258 primary claims plus all final-stage word groups. Independent source
record/trace auditing verifies every recorded SHA512 preimage/output and confirms
the earlier proof size (866389 bytes), all per-phase counters and ordered verifier
XOF inputs. Exact prover/verifier protocol input comparison also passes for 795
requests / 332599739 bytes, excluding the three explicitly checked continuation
probes. The raw trace digest differs with hash-event ordering; byte-identical
whole traces are not claimed. Evidence:
`complete-pbs-prefix-projection-passed-audit.json`. These debug timings do not
qualify native proving latency.

The validated executable is frozen in
`complete-pbs-prefix-projection-binary.json` and has started a separate 20-case
complete-PBS source-word matrix. Runtime PID/log/source binding:
`complete-pbs-prefix-projection-matrix-running.json`; log
`classical-complete-pbs-prefix-projection-matrix-tests.log`. Completion requires
exit zero, independent full trace/source record auditing and exact coverage of
both fields, schedules and all five backends. The earlier full source-word
matrix remains live on its older revision. Whole native geometry, arbitrary
adversarial-prefix soundness/knowledge and security-matched performance remain
incomplete.

### File-backed complete-control temporal child origins

The new `temporal_child_stream_audit` reads a completed oracle-event file and
retains XOF producer offsets/lengths and compact child identities, rather than
copies of every transcript prefix. For matching-profile typed child requests it
requires the seed producer before the request, validates the exact typed parent
fork framing, and checks the initial identity or completed identity/receipt
prefix. Later activity cannot repair an earlier missing producer because every
observed matching request is checked as it is encountered, before inserting its
answer. Repeated XOF outputs require exact byte-for-byte input equality using a
second file handle. All recorded SHA512 preimages and the whole-file fingerprint
are also verified. Input lengths are checked against the remaining file and host
allocation before reading, without imposing an adversarial query cutoff.

This positive-control checker intentionally does not register every input window
or establish a global availability filter. Its diagnostic flags say so. The full
control requires matching prover/verifier child seed sets and identity/later
request counts, while existing source-word checks remain required. It is not an
arbitrary parent-body or full adaptive soundness argument.
A kernel covers repeated producer inputs, missing/late seed and receipt producers,
wrong trace fingerprints, corrupt SHA512 outputs, truncation and oversized frame
lengths. Build/runtime validation is pending in
`classical-streamed-child-origins-kernel-tests.log`; frozen source overlay:
`streamed-child-origins-source-manifest.json`. Existing matrices continue on
their earlier frozen revisions and do not cover this addition.

The first streamed-origin kernel passes (one test, 0.05s), including valid repeated
inputs and all listed producer/file integrity negatives. Evidence:
`streamed-child-origins-kernel-passed-audit.json`. It checks matching-profile child
requests only. The subsequent revision recognizes the child application namespace
before checking the trusted profile, so a foreign/malformed child profile is
rejected instead of ignored; an explicit foreign-profile negative is added.
Corrected/strengthened sources: `streamed-child-origins-v2-source-manifest.json`;
rerun pending in `classical-streamed-child-origins-v2-kernel-tests.log`.
No availability-filter or complete adaptive reduction result follows.

The strengthened streamed-origin kernel also passes (one test, 0.02s), including
foreign-profile rejection. Evidence:
`streamed-child-origins-v2-kernel-passed-audit.json`. A complete-PBS focused control
has now started with that checker integrated alongside the existing source-word
checks. PID/executable/source binding is in
`complete-pbs-streamed-origins-focused-running.json`; log
`classical-complete-pbs-streamed-origins-focused-tests.log`. Its runtime result
is pending, and the availability-filter scope remains explicitly excluded.

The complete-PBS streamed-origin focused control passes (308.82s debug). Prover
and verifier each contain three initial child identity requests, 76 later child
requests and exactly the same three seed identities; no distinct-input XOF
first-64-byte output collision is observed. All 258 primary and 128 NTT / 15
product / 16 decomposition-linear / 15 lookup-source / seven helper final claims
also pass. Independent record/trace auditing confirms the previous proof bytes
and all phase counters, verifying all recorded SHA512 preimages/outputs and the
file fingerprint. Evidence:
`complete-pbs-streamed-origins-focused-passed-audit.json`. Window availability is
still explicitly unchecked by this streamed-origin checker; full adversarial
parent/PCS-body admissibility and security/performance admission remain open.

The independently audited bound-claim matrix now has six completed controls
(all BabyBear v4 backends and v5 Brakedown), recorded in
`final-key-bound-claims-matrix-progress-6.json`. The optimized full-PBS source-word
matrix has one independently audited complete control, with unchanged prior
control fields, in `complete-pbs-prefix-projection-matrix-progress-1.json`.
Neither partial record establishes suite completion.

### Debug Keccak dependency optimization

The workspace now sets `profile.dev.package.keccak.opt-level=3` for the already
locked Keccak 0.1.6 dependency. Large-prefix SHAKE recomputation in the streamed
controls otherwise executes the permutation unoptimized. The verbose compiler
record confirms optimization level three with debug assertions still enabled.
Release and benchmark profiles and cryptographic source/dependency versions are
unchanged. This targets validation work, not native performance qualification.

All seven main classical transcript tests pass, including the fixed SHAKE256
empty-input known-answer vector. The complete helper unit suite also passes all
34 tests, including byte-stream buffer boundaries and transcript/receipt checks.
Evidence: `debug-keccak-transcript-passed-audit.json` and
`debug-keccak-helper-passed-audit.json`; source overlay
`debug-keccak-profile-source-manifest.json`. The integrated complete-PBS focused
control is now rebuilding/running in
`classical-debug-keccak-complete-pbs-focused-tests.log` for comparison with the
preserved trace/control records. It passes (102.92s debug), and the independent
trace/control audit passes in
`debug-keccak-complete-pbs-focused-passed-audit.json`. Existing live matrices
remain on their earlier immutable executables. These debug timings do not
establish a native release speedup.

### Captured answer availability scan

The file-backed child-origin audit now makes a second pass over the captured
oracle input bodies. It checks whether any observed first SHA512 or SHAKE
first-64-byte answer occurs in an input at or before its first answer event.
It verifies the entire file fingerprint again and uses exact 64-byte equality
after a three-byte prefix gate. One previous framed input supplies exact shared
prefix reuse, including the 63 bytes across each changed boundary. This avoids
retaining all input windows. Duplicate answers are counted once per family.

The kernel passes, including deliberately published future H/XOF answers and
repeated producer requests. The integrated full-PBS focused run passes
(156.55s debug) in
`classical-streamed-availability-complete-pbs-focused-tests.log`, with frozen
source overlay `streamed-availability-source-manifest.json`. Both captured
availability-hit counts are zero; all source-word and child-origin checks pass.
Independent full-file hashing, recorded SHA512 preimage/output verification,
and comparison of all prior control fields pass in
`streamed-availability-complete-pbs-focused-passed-audit.json`. A separate
differential test passes against every input window across 257 boundary
positions, covering append, truncate, changed-prefix, and unframed cases.
Evidence: `streamed-availability-kernel-passed-audit.json` and
`streamed-availability-differential-passed-audit.json`. The separate final-key
bound-claim matrix has 11 independently audited completed controls in
`final-key-bound-claims-matrix-progress-11.json`; suite completion is pending.

This is retrospective checking of a finite captured execution. It does not
establish the adaptive availability game, cover unobserved primitives or root
declarations, or discharge whole-parent/PCS-body admissibility. The diagnostic
`all_captured_input_windows_checked` is separate from the still-false general
`all_input_windows_registered` and `availability_filter_checked` flags. Security
and performance admission remain false.


### Generic streamed receipt and child-finish replay

The file-backed full-PBS checker now replays completed byte and field phases
before adding the current XOF answer. It requires an earlier exact request
input; field receipts additionally require an earlier consumed-byte fingerprint
producer. Recorded bytes must equal the request stream, use the trusted prime,
and stop exactly at the requested canonical acceptance count. Rejection loops
remain uncapped. Parent child-finish frames must resolve to an earlier finish
request for the same trusted profile, child label, context and seed. Shared
prefix reuse skips only previously validated complete receipts; all input
framing is still parsed. Application bodies and extension-basis semantics remain
outside this generic checker.

All three streamed kernels pass, including exact-window differential scanning,
original child-origin negatives, missing request/receipt producers, a genuine
fingerprint for bytes from the wrong request, surplus bytes after acceptance,
and malformed request kinds. Evidence:
`streamed-receipt-origin-v2-kernel-passed-audit.json`; frozen source overlay
`streamed-receipt-origin-v2-source-manifest.json`. The integrated complete-PBS
focused test passes (158.89s debug), including 3,780 generic receipt/link
validations, in
`classical-streamed-receipt-origin-v2-complete-pbs-focused-tests.log`; executable
binding is in `streamed-receipt-origin-v2-complete-pbs-running.json`. Independent
full-file/preimage auditing passes, and all previous control fields and all
795 ordered verifier XOF inputs (332,599,739 bytes) are unchanged. Evidence:
`streamed-receipt-origin-v2-complete-pbs-focused-passed-audit.json`.

The v3 kernel revision adds a valid completed child/parent pair and rejects
both a missing finish producer and a genuine same-child answer whose request
was not a finish. All three kernels pass again in
`streamed-receipt-origin-v3-kernel-passed-audit.json`. The generic checking code
is unchanged from the v2 full-PBS control; the v3 changes extend its test.

A complete 20-case generic-receipt/source-word matrix is now running on a frozen
v3 executable. Binding and eventual exit/pass artifacts use the
`complete-pbs-generic-receipts-` prefix. Log:
`classical-complete-pbs-generic-receipts-matrix-tests.log`. Completion is pending;
the earlier matrices continue on their own immutable revisions. Latest
independent partial records for those earlier runs are 12 final-key cases and
six full-PBS source cases in
`final-key-bound-claims-matrix-progress-12.json` and
`complete-pbs-prefix-projection-matrix-progress-6.json`.

The deterministic observed-prefix invariant and prefix-cache induction are
recorded in `docs/unmasked-polyfrim.md`. They do not establish the adaptive
ideal-oracle filter or authenticate arbitrary algebra/PCS messages. General
soundness, knowledge, all-trials work, native coverage and performance admission
remain incomplete.


### Typed metadata in generic streamed field phases

The streamed generic parser now also binds prime application identity and every
field request's sampling metadata, including the current unanswered request.
Extension phases must use the complete trusted multiplication table, request a
multiple of the trusted extension degree in coefficients, and start with the
zero-count identity phase. Typed scalar/vector markers are mandatory for
ordinary requests; scalars request exactly one base or extension element.
Malformed request descriptors and repeated identity phases reject.

All four streamed kernels pass in
`streamed-typed-receipt-kernel-passed-audit.json`, including BabyBear extension
six and Goldilocks extension three metadata cases. Substituted bases, primes,
counts, absent/wrong markers and scalar cardinalities reject. A pending vector
count near u64::MAX is accepted without allocating that vector or imposing an
adversarial query/retry cap. The integrated focused run uses a frozen executable
bound by `complete-pbs-typed-receipts-focused-running.json`, with source overlay
`streamed-typed-receipt-source-manifest.json`. The focused test passes
(176.30s debug), as does independent full-file/preimage auditing and exact
comparison of all 795 verifier XOF inputs (332,599,739 bytes). Evidence:
`complete-pbs-typed-receipts-focused-passed-audit.json`. The earlier 20-case
matrix continues on its generic receipt revision.

A subsequent audit-only optimization absorbs each framed input into a rolling
SHAKE state and clones that state exactly at request boundaries. Receipt replay
uses those snapshots rather than rehashing the full request prefix for every
earlier phase embedded in a parent input. Exact recorded producer input
comparison and raw output checking remain required. This preserves bounded
state (a current and preceding request state) and adds no fingerprint heuristic
or query limit. Its four kernels pass in
`streamed-incremental-receipt-kernel-passed-audit.json`, source overlay
`streamed-incremental-receipt-source-manifest.json`. Its full-PBS focused test
also passes (127.46s debug), with identical temporal records, proof/control
fields and exact ordered verifier XOF inputs. Independent trace/preimage audit
and comparison evidence:
`complete-pbs-incremental-receipts-focused-passed-audit.json`. These debug times
are not matched release benchmarks and establish no native speed qualification.

The independent stream auditor now accepts `--require-temporal` together with
`--require-source-words`. It requires the ordered temporal record between final
obligations and source claims, exact integer phase vectors, matching field /
schedule / backend identity, nonzero receipt coverage, zero captured hits and
collisions, and the explicitly false general security/filter flags. Missing,
duplicate and reordered records and Boolean-as-integer values reject. The
combined auditor/request-stream suite passes 11 tests in
`temporal-source-record-auditor-tests-passed-audit.json`, with frozen auditor
sources in `temporal-source-record-auditor-source-manifest.json`.

Strict temporal/source auditing passes on the optimized focused trace in
`complete-pbs-incremental-receipts-focused-temporal-record-audit.json`. It also
passes on the first completed case of the earlier generic 20-case matrix:
`complete-pbs-generic-receipts-matrix-progress-1.json`, with all prior matching
control fields unchanged. That matrix is still running.

A separate 20-case matrix now runs on the frozen typed/incremental executable,
with strict temporal and source-word auditing required after successful exit.
Binding and eventual exit/pass artifacts use the
`complete-pbs-typed-incremental-receipts-` prefix; log
`classical-complete-pbs-typed-incremental-receipts-matrix-tests.log`. All 20
representative cases and full native coverage remain unproven until appropriate
completion evidence exists. The adaptive soundness/knowledge/work proof and
security-matched native performance gates remain open.


### Parent/request ordering in generic streamed replay

The generic replay now rejects advancement past an unanswered byte/field
request, overwritten unfinished forks, and ordinary parent frames between the
child seed response and its finish. The only alternative is the detached API's
terminal parent-checkpoint query with its exact reserved label and empty body.
A checkpoint frame cannot be absorbed into a continuing parent prefix. This
checks the reserved HasteBoots typed namespace grammar without changing protocol
bytes or restricting the adversary's external oracle interface.

All four streamed kernels pass on the final frozen source revision, including
new missing-response, second-fork, advanced-parent, valid checkpoint and
nonterminal-checkpoint controls. Evidence:
`streamed-parent-sequence-kernel-passed-audit.json`; source overlay
`streamed-parent-sequence-source-manifest.json`. The initial kernel build was
followed by an explicit rebuild after the checkpoint assertions were added;
only the final v2 kernel log is bound to this passing evidence.

The integrated focused full-PBS control passes (155.23s debug) in
`classical-complete-pbs-parent-sequence-focused-tests.log`, with executable
binding `complete-pbs-parent-sequence-focused-running.json`. Independent full
trace/preimage and strict temporal/source auditing passes in
`complete-pbs-parent-sequence-focused-passed-audit.json`. All previous control
fields, temporal records and exact ordered verifier XOF inputs (795 requests,
332,599,739 bytes) are unchanged. Earlier matrices continue on their own
immutable executables. Independently audited partial progress is now 13
final-key bound-claim cases and 10 full-PBS source-word cases in
`final-key-bound-claims-matrix-progress-13.json` and
`complete-pbs-prefix-projection-matrix-progress-10.json`. The source cases cover
all BabyBear v4/v5 backends, not all 20 cases or native encrypted geometry.

The generic acyclic dependency invariant is documented in
`docs/unmasked-polyfrim.md`. Application/PCS task interpretation, authenticated
source assignment, the adaptive availability argument, all-trials knowledge /
work composition and security-matched native benchmarks remain incomplete.


### Replay generic checks against preserved complete traces

An explicitly ignored analysis test,
`replay_preserved_complete_pbs_temporal_trace`, reconstructs the trusted n32 /
LWE21 / width-eight / query-eight fixture for the requested field, schedule and
backend, then runs the current file-backed temporal checker on a saved trace.
It requires all six `HB_REPLAY_*` bindings: `TRACE`, `SHA512`, `PRIME`, `VERSION`,
`BACKEND`, and `BLOCK_WIDTH`. Schedules are v4/v5; fields and backends use the
existing two-field/five-backend matrix. Full-matrix Brakedown uses block width
eight; the focused Brakedown fixture uses two. Non-Brakedown uses the full
fixture's fixed eight argument while its actual profile has no row block.
The expected fingerprint is mandatory and checked over the whole file twice.
Profile metadata are reconstructed independently of the captured input bytes.

The replay entry point passes on the preserved focused trace, reproducing all
prior temporal records. Substituting the other trusted Brakedown block width
rejects that same trace at its profile binding. Evidence:
`preserved-temporal-replay-focused-passed-audit.json`, source overlay
`preserved-temporal-replay-source-manifest.json`. Its output explicitly says
`source_words_rechecked:false` and does not regenerate proofs, claim native
geometry coverage or repeat source-word authentication. It enables checking
new generic parser revisions on existing matrix traces without redoing proof
generation and unrelated source-word checks.

The next revision retains one previously checked prefix for each of the three
fixed typed namespaces (prime root, extension root, child), rather than evicting
the parent prefix when processing a child. Each pass retains at most three
input prefixes, independently of query count. Exact prefix comparison, crossing
windows and full output/producer comparisons remain unchanged. The differential
window test now interleaves all three namespaces, and receipt tests check that
an intervening extension query does not evict a validated prime prefix.
All four kernels pass in `namespace-prefix-cache-kernel-passed-audit.json`,
source overlay `namespace-prefix-cache-source-manifest.json`. Replay of the same
preserved focused trace also passes, with all prior result fields identical
except executed receipt replays decreasing from 3,780 to 930. The wrong trusted
profile still rejects. Evidence:
`namespace-prefix-cache-focused-replay-passed-audit.json`. This counter measures
executed audit work, not protocol query count or a unique-phase inventory. No
native timing improvement or performance admission follows from it.

A 20-case replay matrix now runs the frozen namespace-cache checker against the
already preserved two-field/v4-v5/five-backend trace matrix. The driver verifies
the original passing suite and its independently audited control-file digest
before selecting cases; each case must match its original trace SHA512 and
trusted fixture identity. Per-case PID, exit, log fingerprint and passed-audit
artifacts and aggregate progress use the
`preserved-temporal-namespace-replay-` prefix. Source binding is
`namespace-prefix-cache-source-manifest.json`. This avoids proof regeneration;
it reuses the original independently audited trace bindings and explicitly does
not recheck source words. All 20 replay results are pending. Earlier full-PBS
source-word matrices continue separately on their immutable revisions. Security
admission, native coverage and all-trials application/source composition remain
open.


### Explicit request endpoints and independent byte inventory

The captured-query checker now rejects unknown frame kinds and repeated domain
frames after the header, and requires each framed XOF input to end at a byte /
field request or a valid terminal checkpoint. Synthetic positive child/parent
fixtures now end at actual requests rather than arbitrary transcript messages.
All four kernels pass, including distinct failures for malformed frame kinds,
message-only and response-only endpoints, and the earlier parent-ordering cases.
Evidence: `generic-request-boundary-kernel-passed-audit.json`, source overlay
`generic-request-boundary-source-manifest.json`. Focused replay on the same
preserved full-PBS trace passes with all prior temporal results unchanged and
the wrong profile rejected:
`generic-request-boundary-focused-replay-passed-audit.json`.

`tools/audit_classical_request_boundaries.py` independently checks these
boundaries while verifying the expected file fingerprint and all recorded
SHA512 preimages/outputs. The stream auditor gains an opt-in input callback;
its default streaming behavior is unchanged. The combined boundary / event /
request-comparison suite passes 16 tests with exact source-byte binding in
`request-boundary-auditor-tests-v2-passed-audit.json`; source overlay
`request-boundary-auditor-source-manifest.json`.

The focused independent audit classifies all 795 verifier XOF queries: 141 byte,
248 prime, 76 extension, six checkpoint and 324 field-fingerprint queries. Child
query totals agree with the Rust replay. The field inventory has 100,888 accepted
coefficients, 107,610 candidates and 430,440 consumed raw bytes. Under matching
receipt replay and completed trusted API calls, total logical XOF reader bytes
are 460,584. Evidence: `request-boundary-focused-trace-passed-audit.json`.
The byte inventory is explicitly conditional; it is not an adversarial / native
resource bound or an independent SHAKE-stream consistency proof.

The independent boundary/inventory matrix passes all 20 field/schedule/backend
cases. Evidence: `request-boundary-inventory-matrix-passed-audit.json` and
`request-boundary-inventory-matrix-summary-audit.json`. Independent event and
fingerprint auditing covers all 8,551,786 events and 53,485,529,000 saved trace
bytes, with closed field-receipt counts in every phase. The byte inventory
remains conditional on matching receipt/stream replay and completed API calls.
The earlier namespace Rust temporal replay has 11 completed cases at its latest
preserved snapshot; its remaining cases are pending. Both reuse the original
passing 20-trace matrix and its audited digest. Source-word authentication is
still a separate matrix, and none of these controls establishes full native
geometry or the all-trials security argument.

A scope clarification is added to `docs/unmasked-polyfrim.md`: an available
fingerprint of chosen raw coins does not imply an earlier query to their
sampling request. Honest replay can require that ordering; arbitrary candidate
inputs still need the proposed-receipt phase-emulation and first-bad-transition
argument. It must not be replaced by a 512-bit availability assumption. General
soundness, knowledge, all-trials work and native performance admission remain
incomplete.


### Proposed field coins with original-view input binding

A separate `proposed_phase_audit` interface recovers earlier proposed field
coins without requiring the associated sampling request to have been queried.
It binds the candidate to its original history view, the exact prefix request,
absorbed receipt, trusted label, base prime and base-coefficient count. The
fingerprint producer must already be available in that original view. Output
storage is bounded by its known raw input before calling the legacy decoder;
a usize::MAX count fails without a huge reservation.

The returned request/raw pair is an explicit sampling-consistency obligation.
An earlier request flag does not certify consistency, and later requests cannot
repair original views. A valid alternative receipt already present in the
history cannot replace the receipt actually absorbed by the candidate. Foreign
views and another candidate's view reject. The enclosing stage's full syntax
and source-task admissibility remain caller obligations.

Two proposal tests pass for BabyBear/extension-six and Goldilocks/extension-three,
including an actual typed-child prefix whose unused zero-element sampling query
is omitted from the analysis history. Its real seed, empty fingerprint and next
query still suffice for the existing typed-child interpreter, without an XOF
availability/collision hit. Three history tests and all four strict honest replay
kernels also pass. Evidence: `proposed-phase-input-binding-passed-audit.json`;
frozen source overlay `proposed-phase-input-binding-source-manifest.json`.
The earlier contract-only revision and its five passing tests are preserved in
`proposed-phase-first-view-passed-audit.json`; the current revision additionally
checks candidate/view and absorbed-receipt binding itself.

No production query schedule or protocol bytes change. This implements the
proposed-coin representation needed by the phase-emulation argument, not that
argument or a full admissibility theorem. General soundness, knowledge,
all-trials work and security-matched native performance remain unqualified.


### Uncapped byte-run controls and completed matrix joins

The proposed-coin test support now handles inline byte receipts and complete
prior prefixes of no-message byte runs. Its v4 column interpreter preserves
ordered repeats and the production rejection boundary, with no retry cutoff.
The 513-rejection fixture, both field profiles, original-view binding, changed
message/descriptor controls, history regressions and strict honest replay
kernels pass: 11 targeted tests in `proposed-byte-run-passed-audit.json`, bound
to `proposed-byte-run-source-manifest.json`. This changes no production bytes
or schedule. Root selection, whole-stage admissibility and stream consistency
remain explicit caller obligations.

The final-key bound-claim/source matrix and complete-PBS all-stage source-word
matrix each completed all 20 field/version/backend combinations with exit zero.
Their log hashes, frozen runner hashes and matrix coverage were rechecked in
`completed-source-control-matrices-verified-audit.json`. These are synthetic
n=32/LWE=21 controls, not native n=1024/LWE=728 coverage.

The preserved-trace temporal replay also completed 20/20. Its records are now
joined with the independent 20/20 request-boundary/byte inventory by exact
trace fingerprint, profile and case identity in
`captured-temporal-and-byte-inventory-matrix-joined-audit.json`. The join checks
closed field counts, coefficient totals, namespace counts and logical-reader
byte formulas against strict receipt replay. Those saved traces are a separate
dataset from the all-stage source-word matrix; the join explicitly reports
`source_words_rechecked: false`. It supplies captured execution evidence, not
a general adversarial-prefix or unconditional resource bound.

The protocol notes now state a conditional family-entry bound for an uncapped
column run and enumerate its unproved application hypotheses. No security or
performance admission flag changes. Complete classical soundness, knowledge,
all-trials work and matched native speed/proof-size gates remain outstanding.


### Canonical trailing column-run root selection

`canonical_column_run_proposal` now selects the maximal trailing v4 sampling
run by parsing complete frames, instead of trusting a supplied descendant root.
The new regression demonstrates that the low-level supplied-root interface can
hide an earlier accepted draw when its caller violates the root-selection
premise, and that the canonical entrypoint rejects that counter reset. It also
covers embedded request bytes inside message bodies and truncated frames.
Whole-stage admission and source authentication remain caller obligations.

Source is frozen in `canonical-column-run-source-manifest.json`. Targeted
validation is running, recorded in `canonical-column-run-tests-running.json`
and `classical-canonical-column-run-tests.log`; it is not yet counted as passed.
The live compiler was observed waiting on filesystem creation operations.
No security/performance admission flag changes.


### Scalar v4 column response boundary

`linear_column_run_proposal` adds the immediate scalar PCS boundary to the
canonical trailing-run interpreter. The root must immediately follow a kind-1
`mw linear responses` frame containing exactly the trusted number of base-field
test and evaluation cells, with canonical element encodings and no trailing
bytes. It returns these vectors and the preceding stage prefix; the caller
must authenticate that prefix and supply trusted domain/query/cell counts.
An intervening frame or aggregate-response label cannot serve as this scalar
boundary. Candidate length is checked before reserving the trusted vectors.

The new shape regression covers valid responses, wrong dimensions, usize::MAX
cell counts, wrong labels, intervening frames, trailing bytes and truncation.
Source is preserved in `linear-column-response-source-manifest.json`.
The six proposal tests are queued under `linear-column-response-tests-running.json`
(log `classical-linear-column-response-tests.log`), after the still-live earlier
canonical-root build. No pass is claimed until the test exit and log confirm it.
This remains test-support interpretation, not full application-prefix admission.


### Canonical-root direct regression result and scalar test correction

The canonical-root unit-test executable finished compiling before the original
Cargo invocation finished its additional targets. Running its five proposal
tests directly succeeded with exit zero, including the descendant-root counter
reset, embedded-frame-body and truncation regression. The direct log is
`classical-canonical-column-run-direct-tests.log`; its source revision is
`canonical-column-run-source-manifest.json`. This does not validate the newer
scalar response decoder.

The first scalar-response test build failed with E0599 because the concrete
BabyBear fixture lacked `num_traits::{One, Zero}` imports. The imports are now
fixed in `linear-column-response-v2-source-manifest.json`; the original failed
log and exit artifact are preserved. Concurrent build commands were observed
using the same output path, so the v2 driver explicitly waits for both original
Cargo/compiler process identities to terminate before launching its six-test
`--lib` build. No scalar-response pass is claimed yet. Waiting metadata is in
`linear-column-response-v2-tests-waiting.json`.


### Verified scalar boundary and uncapped column expectations

The corrected scalar-response revision passes all six proposal tests with exit
zero (`linear-column-response-v2-tests-passed-audit.json`, source overlay
`linear-column-response-v2-source-manifest.json`). This includes the earlier
canonical-root controls and the immediate scalar-response shape checks. The
original all-target canonical-root Cargo command also finished with exit zero.
The failed first scalar build remains preserved; no failed run is counted.

`column_run_expected_resources` now supplies exact rational first and second
moments for an uncapped v4 rejection run and its growing transcript input cost.
It assumes a fixed trusted root length/count and fresh independent candidate
streams. There is no deterministic retry cutoff. Fifteen sampler-resource tests
pass, including exhaustive small-support residue counts and first-step moment
equations, the native power-of-two top rejection bucket, empty runs, growing
input costs and invalid parameters. Source snapshots and evidence are in
`uncapped-column-resource-source-manifest.json` and
`uncapped-column-resource-tests-passed-audit.json`.

These are expected single-family costs, not deterministic verifier ceilings or
full adversarial work composition. Existing stopped worksheets are unchanged.
First-entry/source coupling, full classical security and matched native
performance admission remain incomplete.


### First primary v4 opening-task and run binding

The proposed-run parser now composes the existing first-opening prefix
interpreter with the canonical scalar v4 run. Trusted profile geometry supplies
the domain, query and cell counts. The recovered task binds the initial
relation, terminal values, first selected context/commitment, query and claims.
The row-randomness receipt is interpreted from producers available strictly
before the candidate's original query view. It remains an explicit proposed
stream obligation, without requiring that sampling request to have been queried.
The immediate scalar response message and maximal trailing byte run are then
bound to that same task. A later producer cannot enlarge this original view.

Two field controls use the existing synthetic opening fixtures, checking the
root and a descendant with one accepted proposed draw. They compare the task,
row vector and scalar response vectors against the fixture, assert the row
sampling request is absent from the prior history, and reject a changed header.
Together with the six prior proposal controls, eight tests are running under
`primary-v4-column-binding-tests-running.json`, source overlay
`primary-v4-column-binding-source-manifest.json`, log
`classical-primary-v4-column-binding-tests.log`. No pass is claimed yet.

This binds a first-opening task, not its frozen source-word assignment or the
whole PBS. The fixtures include an intentionally rejected PCS opening and must
not be reported as accepted native certificates. Adaptive admissibility,
first-bad transitions, knowledge and all-trials work remain incomplete.


The first-primary v4 task-binding revision completed with exit zero: all eight
proposal tests passed, including both field fixtures (0.86 seconds test runtime;
not a benchmark). Exact source/snapshot bytes and log hash were rechecked in
`primary-v4-column-binding-tests-passed-audit.json`. The preserved source
manifest is `primary-v4-column-binding-source-manifest.json`. These controls
bind the task and proposed coins; frozen source assignment, complete adaptive
security and native performance admission remain unestablished.


### First-primary v4 source assignment from first-declaration histories

`primary_frozen_values` now evaluates the first primary opening task against
immutable first-declaration source views. It validates all contexts/geometries
before view access, memoizes each exact context/root alias, completes canonical
columns, and uses the existing Brakedown decoder and normalized task query.
The interpreted opening fixtures also check the zero completion from a word
history containing declarations but no preimages.

Two new field controls construct nonzero encoded source graphs, verify their
roots against production commitments, and recover their true query values.
They check that exact aliases share one assignment, changed contexts reject,
and late preimages cannot repair the zero assignment of an earlier declaration.
The early-declaration/late-preimage fixture deliberately includes an availability
exception and is not evidence of a successful adversarial proof.

The initial compile failed on an incorrect fixture module path; that log is
preserved. The corrected revision is running ten proposal tests, recorded in
`primary-v4-frozen-word-v2-tests-running.json`, source overlay
`primary-v4-frozen-word-v2-source-manifest.json`, log
`classical-primary-v4-frozen-word-v2-tests.log`. No pass is claimed yet.
Synchronization of SHA/XOF histories and general source/phase/security/work
composition remain unestablished; no admission flag changes.


The corrected frozen-word revision now passes all ten proposal tests with exit
zero (`primary-v4-frozen-word-v3-tests-passed-audit.json`, frozen overlay
`primary-v4-frozen-word-v3-source-manifest.json`). The new nonzero source-graph
controls use widths eight/four for the respective extension-six/extension-three
profiles and validate production roots, true evaluations, immutable early
assignments, alias sharing and context rejection. The earlier width-two fixture
was rejected by the trusted profile constructor; its eight-pass/two-fail result
and source are preserved in `primary-v4-frozen-word-v2-tests-failed-audit.json`.
Exact current source/snapshot bytes and the successful log hash were rechecked.

First-primary v4 frozen assignment is now implemented as component test support.
General SHA/XOF event coupling, all opening families, full adaptive soundness,
knowledge, all-trials work and matched native performance remain incomplete.


### Fixed-word local column failure predicate

`scalar_column_failures` computes the exact set of columns violating either
scalar response equation for a fixed completed word, and independently checks
the final claimed value. `primary_column_failures` supplies the parsed first
primary v4 task, proposed row coefficients, scalar responses and selected root's
first-declaration word. No current sampling answer is used.

The corrected revision passes all ten proposal tests, including both field
controls against production verification. Honest openings have no rejecting
columns. Changing the constant random-test response coefficient makes every
column reject while preserving the final evaluation. The fixture rebinds that
changed response, resamples its indices and supplies valid paths from the
unchanged tree; production then rejects on the linear-response equation.
Wrong final claims and malformed row-weight lengths are also checked separately.
The first attempt retained paths for the old Fiat-Shamir indices and failed
that intended rejection-location assertion; its eight-pass/two-fail log and
source remain preserved in `primary-v4-local-predicate-tests-failed-audit.json`.

Successful evidence is `primary-v4-local-predicate-v2-tests-passed-audit.json`,
frozen source `primary-v4-local-predicate-v2-source-manifest.json` (ten tests,
exit zero, exact source and log hashes checked). The protocol notes relate a
fixed rejecting set to its conditional whole-run miss probability. No uniform
rejecting-set lower bound, row-coin error bound or full adaptive/knowledge/work
composition is established. Security and performance admission remain false.


### Near-word false-claim mapping for the local predicate

The proposed-run controls now include a common t-column perturbation of the
fixed source, with t=floor((D-1)/3). Both fields decode it to the original table.
A changed structured response and false claim are chosen to satisfy the final
value equation; the local predicate still marks at least D-t columns. This
checks the implementation mapping for the deterministic near, correctly padded
case, including shared random/structured column checks.

All ten proposal tests pass with exit zero, source/snapshot equality and log
hash checked in `primary-v4-near-word-predicate-tests-passed-audit.json`; source
is frozen in `primary-v4-near-word-predicate-source-manifest.json`. The protocol
notes spell out the deterministic code-distance argument and its conditional
whole-run sampling tail. These finite controls are not a probability proof or
an accepted false PBS certificate. Far-source and forbidden-padding random-row
exceptions, complete first-query phase/source coupling, knowledge and all-trials
work remain incomplete. No security or performance admission flag changes.


### Response-independent row state and parsed-task integration

`scalar_row_state` now implements a response-independent intermediate state.
It distinguishes a valid nearby decoded source with a false claim from an
invalid source whose projected random-test word has no nearby correctly padded
RS decoding. A bad state supplies a rejection floor for every response packet
whose final claimed-value equation holds. The initial reciprocal far-word and
zero-weight escape controls pass, including both fields; zero weights remain
an explicit escaping row choice, not forbidden candidate syntax.

`primary_row_state` and the column failure predicate now share trusted geometry
and first-declaration source completion through `primary_fixed_word`. The
interpreted first-primary controls check their rejection-floor implication.
All ten tests pass with exit zero, exact source/snapshot bytes and log hash
verified in `primary-v4-row-state-v2-tests-passed-audit.json`, source overlay
`primary-v4-row-state-v2-source-manifest.json`. The earlier standalone row-state
revision's ten-test pass is preserved separately.

The notes connect this deterministic state to the existing conditional RS
exceptional-polynomial argument. Finite reciprocal controls do not test its
entropy hypothesis or prove its probability bound. First-query freshness,
complete source/phase coupling, all opening families, knowledge and all-trials
work remain unfinished. No security/performance admission flag changes.


### Forbidden-padding and supported-symbol row-state controls

The row state now distinguishes RS-nearness from valid padding explicitly.
Two new controls use eight/four test rows with matching eight/four-coordinate
symbols, so h<=b holds. They place a constant nonzero coefficient in a forbidden
padding coordinate of an otherwise valid RS word, use a zero structured query,
and verify that exposing random weights leave the state bad and every column
rejecting. Nonzero weights supported on another source row annihilate the
padding residual and remain explicit escape events. Reciprocal far words and
the same exposing/annihilating choices are also checked in these symbol widths.

All twelve proposal tests pass with exit zero. Exact source/snapshot equality
and log hash are verified in `primary-v4-padding-row-state-tests-passed-audit.json`,
source overlay `primary-v4-padding-row-state-source-manifest.json`. These are
small fixed-word/component controls with native symbol widths, not original-size
encrypted PBS runs or probability estimates. The first family interpretation
must still remain frozen even when a later producer makes a descendant parse
successfully; general phase/source/knowledge/work composition is incomplete.
Security and performance admission remain false.


### Earliest syntactic first-primary column-family entry

`primary_family_entry` now chooses the earliest syntactic family member from
the recorded query database before attempting task admission. It uses the
canonical maximal run/root and trusted dimensions/count, then interprets that
first input using its own original producer view. A descendant queried before
the root remains the first entry. A later producer cannot replace that view or
turn a later successful parse into a fresh family entry.

Both field fixtures deliberately query a descendant with an unavailable row
receipt, reveal its producer, and query the root. A fresh root parse then
succeeds, but family interpretation still selects the earlier unclassifiable
descendant. The delayed receipt is checked as an availability-window hit.
Ordinary fixtures retain available receipt producers without querying the
associated row-sampling request. Four metadata tests verify earliest selection,
original epochs on repeats, exclusion of future queries and foreign-view rejection.

All twelve proposal tests and four history tests pass (sixteen total), exit zero,
source/snapshot bytes and log hashes verified in
`primary-v4-family-entry-tests-passed-audit.json`; source overlay is
`primary-v4-family-entry-source-manifest.json`. The selection scans all recorded
queries and imposes no query-count cutoff. Complete synchronized oracle/source
history, full row-first-query interpretation, all other opening families and
phase/knowledge/work composition remain open. No security/performance admission.


### First-primary pre-row query interpretation

`primary_row_query_state` now interprets the first row request at its exact
original view, returning the bound opening, trusted coefficient count, selected
fixed assigned value and pre-row false-relation flag. It reads no current
answer or proposed row coefficients. Both field controls query the row after
column requests and verify invariance under different current answers. They
also withhold a referenced earlier receipt: an enlarged-map legacy parse later
succeeds, while the guarded original/repeated row view remains unavailable.
Foreign and later views reject, and the delayed producer hits a prior target.

All twelve proposal and four metadata tests pass (sixteen total), exit zero,
source/snapshot bytes and log hashes checked in
`primary-v4-pre-row-query-tests-passed-audit.json`; frozen overlay is
`primary-v4-pre-row-query-source-manifest.json`. The first-primary pre-row
interface is implemented; actual-stream post-transition coupling, the full
adversarial phase/source argument, all opening families, knowledge and all-trials
work remain incomplete. No security or performance admission flag changes.


### Captured-word post-row transition and proposal consistency

The first-primary pre-row object now retains its selected completed word and
trusted scalar parameters. `primary_row_transition` takes explicitly supplied
stream output without any later history argument. It checks the exact request,
coefficient count, canonical masking/rejection decoding and exact raw exhaustion,
then computes the post-row state on the captured word. A separate consistency
operation binds a later proposed receipt to the same request, values and raw.
The raw decoder is shared with legacy receipt replay and rejects counts larger
than the input's candidate capacity before reserving output storage.

Both field controls compare the actual fixture stream with the proposed-coin
state, reject wrong requests, truncated vectors/raw and trailing bytes, and
reject inconsistent accepted values. A counterfactual leading rejection yields
the same accepted values but fails the original receipt's raw consistency.
A usize::MAX decode count also rejects without a large reservation.

All twelve proposal plus four metadata tests pass (sixteen total), exit zero,
source/snapshot bytes and log hashes checked in
`primary-v4-row-transition-tests-passed-audit.json`; frozen overlay is
`primary-v4-row-transition-source-manifest.json`. Actual stream provenance is
an explicit trusted-caller premise; decoding does not prove it. Full accepting-
path consistency, adaptive phase/source composition, knowledge and all-trials
work remain incomplete. Security and performance admission remain false.


### Verifier clause review fixes one-variable prefix omission

Review of the first-primary interpreter against the production verifier found
that `num_vars-2` excluded the accepted one-variable ZeroCheck geometry.
The shared first reduction is now extracted into `first_reduced_prefix`.
A one-variable instance enters the zero-round residual sumcheck directly;
larger geometries retain their round checks and use the same first reduction.
No production transcript/proof bytes or verification rule changed.

Both field controls compare genuine production one-variable proofs with nonzero
first-message polynomials against the interpreted query, expected value and
public equality vector. Missing-receipt and wrong-claim negatives pass, alongside
the existing larger-shape controls. Four metadata regressions also pass: eighteen
tests total, exit zero, exact source/snapshot bytes and log hashes checked in
`primary-v4-one-variable-prefix-tests-passed-audit.json`, source overlay
`primary-v4-one-variable-prefix-source-manifest.json`. A full one-variable PBS
fixture was not run. `first-primary-verifier-clause-review.json` freezes the
reviewed source clauses and scope; it is not a general admissibility certificate.
Full phase/source/knowledge/work and matched native performance remain open.


### Observed first-primary query/family ledger

The new metadata-only iterator and `primary_query_ledger` count distinct row
inputs and canonical first-family entries at an original temporal boundary.
Admitted, false/bad and unclassified counts are separate. Repeated inputs and
family descendants are not recharged; future inputs do not alter older-view
counts. There is no maximum-query parameter or adversarial query cutoff.

Both field controls verify a complete nonzero selected-source graph against
its production commitment, exercising one false row and one bad family, while
retaining one unclassified row and one unclassified family. Zero-completion
controls remain. The first ledger run passed but had zero false-state counts;
the revised fixture adds the real source graph to cover those branches.
An intermediate scripted edit failed before writing, and its subsequent log
contains only another run of the original revision; it is not evidence for
the new graph control.

Fourteen proposal plus four metadata tests pass (eighteen total). Effective
changed-source/snapshot bytes, log hashes, both field records and ledger count
identities were independently checked in
`primary-v4-query-ledger-v3-tests-passed-audit.json`; frozen overlay is
`primary-v4-query-ledger-v3-source-manifest.json`. These observed counts are not
attacker-work ceilings or security admission. Complete accepting-path coverage,
adaptive phase/source/knowledge/work composition and matched native benchmarks
remain incomplete.


### Conditional first-component expected-count composition

The protocol notes now state the conditional first-component charge
`oracle exceptions + coverage failures + e_R*E[N_R] + e_C*E[N_C]` and its row-
escape/family-miss dichotomy, including descendant-first ordering. They distinguish
realized ledger counts from expectation bounds and use truncation/monotone
convergence instead of an arbitrary adversarial query cutoff. The coverage term
explicitly retains unresolved accepting entries and source/stream mismatches.

`brakedown_opening_terms.first_query_terms` adds exact-rational arithmetic for
separate expected false-row and bad-family counts. Oracle-exception and coverage-
failure bounds are mandatory inputs, never silently zero. Supplied bounds are
not verified and no work/security admission flag is set. Seven new/existing
opening-term tests pass, including independent row/family scaling, an unbounded
geometric-stopping control, finite stopping, trivial missing-coverage bounds,
arbitrarily large trial expectations and invalid-input rejection.

This is conditional composition arithmetic and a proof obligation map. Observed
trace counts are not treated as adversarial budgets. Uniform transition premises,
full accepting-path coverage, primitive/source/work coupling, all other opening
families, knowledge and matched native performance remain incomplete.


### Unclassified row/family reason partition and fingerprint witnesses

The first-query ledger now partitions unresolved entries into trusted-header
mismatches, missing field fingerprints and other failures. A missing receipt
returns an exact 64-byte digest window at its original query view. The scanner
uses frame boundaries, ignores receipt-like bytes inside opaque messages, and
rejects malformed framing/receipt sizes and foreign views. Availability alone
does not validate producer namespace, raw sampling or stage admission.

Both field controls check witness offsets and late-producer availability hits.
Family diagnostics retain the earliest member's missing receipt after a later
root parse succeeds. The real-source ledger's malformed entries classify as
header mismatches; independent late-row and late-family controls each retain
one missing receipt. Reason counts independently sum to the unclassified totals.

Sixteen proposal plus four metadata tests pass (twenty total), exit zero,
source/snapshot equality, log hashes and both field diagnostic partitions checked
in `primary-v4-receipt-diagnostics-tests-passed-audit.json`; source overlay is
`primary-v4-receipt-diagnostics-source-manifest.json`. The notes state the
conditional later-acceptance/availability-hit consequence, but full input-window
work accounting, remaining coverage failures, all-family phase/source/knowledge
composition and matched native performance remain incomplete. No admission.


### First-primary v5 atomic-query support

The shared row/source interfaces now support both schedules four/five.
A separate v5 atomic-column entrypoint binds the full first-scalar request at
its original view, proposed row receipt, trusted domain/count and fixed source
predicate. The post-sampling interface checks exact request/byte length and
retains all ordered masked draws before duplicate path transport. Field-row
consistency and the complete real-source graph builder are shared with v4.

Two new explicitly first-primary-only v5 fixtures compare supplied atomic bytes
and indices with production sampling, check real commitment roots and false row
states, row-after-column ordering, duplicates, malformed byte counts and later
receipt repair rejection. The existing broad fixture entrypoint still uses its
full scope; the new scoped runner does not supersede any broad test or native
validation requirement. No production protocol bytes, FHE parameters or output
key changed.

Eighteen proposal plus four metadata tests pass (twenty-two total), exit zero,
source/snapshot bytes and log hashes checked in
`v5-first-primary-tests-passed-audit.json`; frozen overlay is
`v5-first-primary-source-manifest.json`. These are synthetic first-primary
controls. V5 ledger coverage, remaining opening families, full adaptive/source/
knowledge/work composition and matched native performance remain incomplete.
Security and performance admission remain false.

### V5 first-primary ledger extension

The first-primary query ledger now supports schedules four and five. Each
distinct v5 atomic column request is a singleton sampling family. Candidate
matching uses the trusted byte-count suffix, leaving malformed headers and
index domains visible as unresolved entries. Repeats retain their original
view; later receipts cannot repair the recorded classification. V4 keeps its
existing canonical rejection-run family grouping. These observed counts are
not expectation bounds or an adversarial query cutoff.

Both field controls check admission before a row query, row-after-column
ordering, repeat deduplication, old boundaries, malformed header/domain
partitions and late-receipt diagnostics. Eighteen proposal and four history
tests pass; source and log hashes are frozen in
`v5-first-primary-ledger-tests-passed-audit.json` and
`v5-first-primary-ledger-source-manifest.json`. This supersedes the earlier
statement that v5 first-primary ledger integration is unfinished. Full
accepting-path, all-family, knowledge and oracle-work composition, and the
security-matched native benchmark remain open. Admission flags remain false.

### Predictable XOF prefix exposure accounting

The temporal XOF history now records fresh-answer counts and the sums of target
window counts and distinct prior-output counts before each fresh answer. It
registers the current input first, deduplicates equal windows, includes external
input declarations, and does not recharge repeats. The current answer does not
determine that query's exposure increment. Five history tests pass inside snarks;
the eighteen proposal regressions also pass on this source.

The protocol notes derive the conditional bound
`min(1,(E[S_targets]+E[S_outputs])/2^512)` by conditional union bounds and
monotone convergence, including adaptive stopping without a deterministic query
cutoff. The exact-rational `xof_expected_exposure_bound` requires separately
justified expectation bounds. Three new arithmetic controls exhaust small
adaptive experiments and check unbounded geometric stopping; three uncapped
sampler regressions pass. The twenty-nine-test source/log evidence is frozen in
`predictable-xof-exposure-tests-passed-audit.json` with source overlay
`predictable-xof-exposure-source-manifest.json`. Observed counter values do not
justify the input expectations, whole-protocol window coverage, attacker work,
knowledge extraction, or security admission.

The completed typed incremental receipt matrix also passed a separate strict
`audit_source_controls(..., require_temporal=True)` reread of the captured traces.
The log remained unchanged, with its exit-zero record and original twenty-control
audit checked. The rerun's returned payload was not saved; the completion receipt
`typed-incremental-receipts-independent-reread-completed.json` records successful
return and points to the existing detailed matrix audit. This remains evidence
for the synthetic matrix rather than a general adversarial proof. Security and
performance admission remain false.

### Shared-prefix window work model

A new explicit string-construction model accounts for literal bytes,
concatenations, slices and oracle submissions while allowing shared strings and
prefix states to be reused. A 64-byte window crossing a concatenation boundary
has at most 63 possible new values; slices add none. Consequently window values
are bounded by 63 times charged construction work, without charging each
query's logical input length again. Repeated doubling controls grow logical
length exponentially while keeping the construction charge linear.

`classical_window_work.shared_window_xof_polynomial` substitutes mandatory affine
query/construction caps and honest window/query offsets into the exposure bound.
It emits exact constant/linear/quadratic coefficients compatible with the existing
work optimizer. No adversarial query cutoff or protocol admission is introduced.
The proof notes distinguish deterministic charged budgets from expected work,
which alone does not bound a quadratic exposure term.

Four new model tests and eight work-cost regressions pass (twelve total).
`shared-window-work-tests-passed-audit.json` freezes their logs and the source
manifest `shared-window-work-source-manifest.json`. The first failed test log
is preserved: its append-one-byte expectation was corrected from 63 new windows
to one. Exhaustive actual binary window sets support the general join bound.
The mapping from all attacker/verifier/setup activity to this explicit primitive
model, complete phase/accepting-path/knowledge composition, Merkle exceptions
and matched native performance remain incomplete. Admission flags remain false.

### V5 first-primary row/column path coupling

A new combined path interface binds pre-row and pre-column states to exact row
request/receipt bytes and the same completed source-column arrays. It recomputes
the row transition, compares every row-state field, verifies the rejecting-column
floor when needed, and applies the atomic output transition. Its conditional
false-path record identifies the disjoint row-escape/column-miss alternatives.
This connects the existing first-primary transitions without inferring Merkle
authentication or full verifier acceptance.

Both field fixtures check actual ordered production indices, wrong row/column
requests, a changed completed source word with unchanged receipt/flags, and a
changed row state. Restoring the original state restores a valid path record.
Eighteen proposal and five history tests pass (twenty-three total), with source
and log evidence frozen in `v5-primary-path-coupling-tests-passed-audit.json` and
`v5-primary-path-coupling-source-manifest.json`. No protocol parameters, output
key or production transcript changed. Actual stream/common-experiment provenance,
authenticated-source coupling, arbitrary first-entry and all-family coverage,
knowledge/work composition and matched native performance remain open. Security
and performance admission remain false.

### V5 first-primary authenticated transport and production cross-check

The combined path interface now has an authenticated transport wrapper. It
sorts/deduplicates the ordered draws, checks exact transport shapes and counts,
and uses the production leaf hashing convention and Merkle checker at each
sampled index against the selected root. Authenticated values differing from
the frozen word remain explicit source-mismatch indices; they are not assumed
away as hash collisions or valid completions.

Both field fixtures reject their original stale packet: the adversarial fixture
changed sumcheck messages while retaining paths from an earlier sampling request.
The positive control regenerates paths for the actual new draws from the same
complete source tree and checks that its root equals the unchanged production
commitment. Empty transport, truncated paths and changed values reject. Changing
only a frozen column leaves valid authentication but produces the expected
explicit source-mismatch index.

A freshly replayed exact pre-opening transcript then drives the unchanged
production Brakedown verifier on the regenerated packet. Its failure status
matches the combined scalar predicate, and any error is restricted to the
linear-response or final-value equations. Thus the positive control reaches
the scalar verifier after successful authentication.

Eighteen proposal and five history tests pass (twenty-three total), frozen in
`v5-authenticated-primary-tests-passed-audit.json` and
`v5-authenticated-primary-source-manifest.json`. The first failed log is
preserved; it is not passing authentication evidence. This is still a synthetic
first-primary control, with production protocol bytes, FHE parameters and output
key unchanged. Complete adaptive source/stream provenance, arbitrary first-entry
and all-family coverage, knowledge/work composition and matched native performance
remain open. Security and performance admission remain false.

### Authenticated-path first-declaration witnesses

The shared hash history now diagnoses a valid concrete Merkle path at its root's
immutable first-declaration boundary. It walks root to leaf and separates known
preimages, the first missing preimage with declaration/answer timestamps, a
same-digest/different-input collision witness, length-filter exclusions and
unregistered child targets. Malformed paths remain unclassified. The diagnostic
does not add oracle queries or repair earlier views.

The proof notes give the root/known-parent declaration argument: the first
missing digest was already a target by the root boundary, so a later first
answer is an availability hit. A collision or filtering/registration gap remains
an explicit alternative. Earlier-known canonical paths agree with canonical
frozen-column completion under the same trusted geometry and leaf convention.

V5 authenticated path results now carry each mismatching index and its optional
temporal status. Both fields construct genuine row/column states from an
incomplete history using the existing parsers. Valid authenticated columns then
differ from its zero completion and return missing-root witnesses. Revealing the
root produces an availability hit; the result preserves its original mismatch
and boundary while recording the late answer. Complete histories return known
paths and no source mismatch. Missing/inconsistent history evidence remains an
unresolved coverage obligation.

Eight shared-history, eighteen proposal and five XOF-history tests pass
(thirty-one total), frozen in `frozen-path-witness-tests-passed-audit.json` and
`frozen-path-witness-source-manifest.json`. The collision branch is implemented
but no real SHA512 collision is manufactured for a test. Complete event
registration, the global source-availability probability/work argument,
all-family/accepting-path/knowledge composition and matched native performance
remain open. Security and performance admission remain false.

### Predictable hash exposure and joint oracle arithmetic

The hash history now records pre-answer target/output exposure sums. It registers
eligible current-input windows first, conservatively charges repeat hash requests,
and retains oversized/filtered inputs' outputs in later collision exposure.
External declarations add targets without creating hash answers; later target
declarations do not change earlier increments. No duplicate full-input index,
production protocol change or adversary query cutoff is introduced.

`ideal_oracle_expected_exposure_bound` requires separate hash and XOF target/
collision expectation bounds in one complete experiment. It unions exact
contributions for first-answer window hits and within-oracle output collisions.
The notes explain the repeated-query zero-new-event case, joint-history
conditional uniformity premise and absence of an independence assumption between
bad events. Neither observed counters nor the new arithmetic establish the
required expectations, complete registrations or attacker-work costs.

Nine shared-history, eighteen proposal, five XOF-history and five arithmetic
tests pass (thirty-seven total), including interleaved adaptive stopping and both
fields' production/source-witness regressions. Source/log evidence is frozen in
`joint-oracle-exposure-tests-passed-audit.json` and
`joint-oracle-exposure-source-manifest.json`. Full adaptive all-family/knowledge/
work composition and matched native performance remain open. Security and
performance admission remain false.

### Joint shared-prefix oracle work coefficients

`joint_shared_window_oracle_polynomial` now supplies separate ideal-hash and XOF
constant/linear/quadratic components under mandatory query rates/offsets and one
shared string-construction/window cap. It uses `(Q_H+Q_X)*W` for target exposure
and `(Q_H^2+Q_X^2)/2` for within-oracle collisions. Shared strings and prefix
states are not reconstructed or charged twice simply because both oracle types
receive them. The construction ledger separately inventories both submission
kinds. The existing optimizer requires an explicit phase component in addition
to these oracle terms; the helper cannot silently substitute a complete proof
bound.

Eight shared-window tests, including four new joint-model controls, and eight
work-cost regressions pass (sixteen total). Evidence is frozen in
`joint-shared-window-work-tests-passed-audit.json` and
`joint-shared-window-work-source-manifest.json`. Exact caps and offsets remain
caller obligations across the entire experiment, including all trials and
rejected verifier/setup/factory activity. Native cap justification, complete
adaptive phase/source/knowledge/work reduction and matched native performance
remain incomplete. Security and performance admission remain false.

### Native stopped-verifier construction substitution

The joint work model now has `native_stopped_joint_window_work`, which consumes
existing typed verifier query/input envelopes. Its conservative literal
construction representation costs at most `V_H*L_H+V_X*L_X` per stopped verifier.
Charging each submission gives affine whole-experiment coefficients while
retaining separate oracle query rates and mandatory honest output/window offsets.
This is a conditional representation cap, not a concrete CPU lower bound or a
proof that all adversarial verifier paths satisfy the typed premises.

The wrapper preserves lookup, canonical-field and schedule-four column stopping
conditions, labels sampler-stop union as per invocation, and supplies no phase
component. Production loops remain uncapped. Its offsets and all-submission phase
charges cannot be inferred from a single accepted trace.

Ten tests pass, including twenty typed descriptor cases spanning both native
field/width geometries, schedules four/five and five backends. Exact substitution,
stops, mandatory offsets and monotonicity are checked. The twenty arithmetic
controls use illustrative offsets only and execute no native runtime. Source,
logs and controls are frozen in `native-stopped-joint-window-tests-passed-audit.json`,
`native-stopped-joint-window-source-manifest.json` and
`native-stopped-joint-window-twenty-case-controls.json`. Native cap justification,
complete adaptive phase/source/knowledge/work composition and matched native
performance remain open. Security and performance admission remain false.

### Remaining-failure and verifier-stop work composition

`native_stopped_joint_work_report` now combines the native joint oracle
polynomial with a mandatory remaining-failure polynomial before optimizing
charged integer work. It adds the per-verifier additional sampler-stop error
beta to the phase linear coefficient, using at most T charged submissions.
It does not default missing algebraic, source, unclassified-path or adversarial
sampler failures to zero.

This automatic beta*T term requires a proved fresh-versus-prequeried stream
split. Stops selected from adversary-prequeried streams belong to the supplied
other-failure bound; their probability is not justified by a fresh per-selected-
submission estimate. The report explicitly leaves this split and every supplied
bound unverified, alongside native cap and whole-proof admission flags.

Fourteen combined model/native/composition tests pass, retaining the twenty
typed descriptor subcases. A synthetic large stop term checks repeated-submission
scaling and the optimizer input; constant-one unknown coverage yields only the
trivial work bound. Evidence is frozen in
`native-joint-work-composition-tests-passed-audit.json` and
`native-joint-work-composition-source-manifest.json`. The initial failed test
fixture log is preserved: it attempted to encode a negative probability before
reaching the new validator; the corrected raw exact-rational fixture exercises
that validator. Full adaptive phase/source/knowledge/work composition, native
cap justification and matched native performance remain open. Admission remains
false, and production sampler loops remain unchanged.

### Exclusive sampler first-exposure boundaries

The XOF history now supplies a distinct exclusive pre-phase checkpoint and
metadata-only exact-input exposure classification. An input first queried at the
checkpoint's next event remains fresh at that boundary; a previously queried
input returns its original view. Later queries, repeats, target declarations and
other inputs cannot repair or replace the saved classification. Foreign-history
checkpoints remain unclassified. Receipt availability alone does not imply a
query to the sampler input.

Both v5 field fixtures check original/replay column boundaries and a fresh row
sampler whose receipt was already proposed in the column request. Eighteen
proposal and six integrated history tests pass (twenty-four total), with six
standalone history controls also passing. Source/log evidence is frozen in
`sampler-exposure-boundary-tests-passed-audit.json` and
`sampler-exposure-boundary-source-manifest.json`.

This supplies the deterministic boundary partition, not the complete sampler
probability/work reduction. Whole-stream/reader provenance, first-entry stage
and actor interpretation, adaptive source coupling and all-family coverage are
still required. The work report's sampler-split certification flag remains false.
Full security/knowledge/work composition and matched native performance remain
open; production transcript bytes, parameters and output key are unchanged.

### First-query actors and actor-resolved opportunity ledgers

The XOF recorder now supports explicit first-query actors (adversary, verifier,
setup or unknown). Existing unlabeled calls remain unknown. Attribution is fixed
at the original input/view; repeats, later better-informed labels and inconsistent
answers cannot replace it. The original-view accessor rejects foreign histories
and mismatched input/views without reading oracle output bytes.

First-primary ledgers now partition distinct inputs, false-row entries and
bad-family entries by actor. V4 uses the earliest syntactic family member; v5 uses
the singleton atomic request. Debug checks verify actor subtotals and that false
row plus bad-family opportunities inject into distinct inputs within each actor.
Both v5 field fixtures retain one verifier-origin false row and one adversary-
origin bad family; original unlabeled receipt producers remain unknown. Replay
attribution does not create a new verifier-origin opportunity.

Eighteen proposal and seven integrated history tests pass (twenty-five total),
with seven standalone metadata controls also passing. Source/log evidence is
frozen in `first-query-actor-tests-passed-audit.json` and
`first-query-actor-source-manifest.json`. These are trusted recorder labels and
observed counts, not proved whole-experiment origin or expected-work bounds.
Complete recorder/reader provenance, first-entry admission, adaptive all-family/
source/knowledge/work composition and matched native performance remain open.
Sampler-split and security/performance certification flags remain false.

### Syntactic field-stop requests and coefficient-weighted first-query bound

A new conservative field-request classifier checks full framing, trusted profile,
base modulus, final flat coefficient count and a supplied trusted count ceiling.
It intentionally does not require stage/body/receipt admission for the raw
rejection-stop event. Zero-count requests contribute zero weight; oversized
counts remain separate and cause no descriptor-sized allocation. The associated
ledger retains each distinct input's original actor and coefficient weight,
including adversarial syntactic requests replayed later by a verifier.

The exact arithmetic helper `field_stop_first_query_bound` requires actor-resolved
expected coefficient sums and applies the conditional canonical-sampler tail
`r^R * sum(expected coefficients)`, capped at one. The notes give the virtual
whole-stream and adaptive first-query argument, without an adversarial query
cutoff. Realized trace counts are not used as expectation bounds. Request
coverage, count ceilings and whole-stream consistency remain explicit premises.

Eighteen proposal, seven history, three new arithmetic and twelve sampler
regression tests pass (forty total). Both field first-primary controls cover the
actual row request, syntax-only adversarial requests, repeated attribution, zero
and oversized counts, wrong profile/modulus and malformed frames. Small-sampler
exhaustion and unbounded grinding controls check the probability arithmetic.
Evidence is frozen in `field-stop-superclass-tests-passed-audit.json` and
`field-stop-superclass-source-manifest.json`. Complete native request/stream
coverage, global expected-work and adaptive phase/source/knowledge composition,
and matched native performance remain open. Admission flags remain false and
production sampler loops remain uncapped.

### Work-measure scope and valid expected-work tail sums

Review of the sampler-work composition exposed a distinction that must be
preserved before native admission: the existing optimizer minimizes a fixed
maximum budget/success ratio, which need not lower-bound early-stopping expected
runtime. Exact birthday controls demonstrate the difference (size 16: expected
first collision about 5.704 queries, fixed-budget worksheet ratio 6).

Work and candidate reports now explicitly label `fixed_maximum_budget`, preserve
existing numbers/legacy keys, provide the clearer budget-ratio alias, and mark
unrestricted expected-work certification false. The separate
`expected_work_bound` requires a positive success-probability floor and a justified
successful-run minimum cost, then computes an exact success-CDF tail-sum lower
bound. It uses integer threshold search and closed power sums, including at
2^128 scales, rather than iterating over all budgets. It supplies no protocol CDF,
success probability, physical cost mapping or native security proof.

Thirty-one regression tests pass, covering the new expected-work controls,
existing optimizer, native composition, candidate and setup worksheets. Source,
logs and exact counterexamples are frozen in
`expected-work-scope-tests-passed-audit.json`,
`expected-work-scope-source-manifest.json` and
`expected-work-birthday-controls.json`. Historical frozen worksheet numbers remain
fixed-budget arithmetic evidence and cannot be reused as expected-runtime
certificates. The planned native field-stop bridge was deferred while resolving
this accounting distinction. Full adaptive soundness/knowledge/work composition
and matched native performance remain open; security/performance admission is
unchanged and false.

### Native first-query field-stop bridge and exact reporting

The deferred native field-stop bridge is now implemented. A uniform per-eligible-
input canonical stop term `mu=min(1,C*r^R)` is charged against the total distinct
input upper bound `(1+V_X)*T+h_X`, covering prequeries and honest offsets at first
input rather than using a fresh estimate per selected verifier submission.
The new composition entrypoint adds this term once, requires every remaining
failure in an explicit polynomial, and reports fixed-budget and success-floor
expected-work targets separately. V4 column rejection and lookup stops are not
automatically covered by this field-only bridge.

The first integration run exposed Python's decimal conversion limit on native
rejection fractions. Exact local chunked formatting/parsing now supports the
large numerator/denominator strings without changing the global digit limit or
rounding values. Existing ordinary rational strings remain compatible.

Forty-one tests pass, including all twenty complete typed descriptor reports,
large-rational round trips, sampler/counting regressions and candidate/setup
worksheets. A synthetic control passes the conditional fixed-budget target but
fails the expected-work target; it is not a native phase-error proof. Unknown
remaining coverage gives trivial bounds in both interpretations. Evidence is
frozen in `native-first-query-field-work-tests-passed-audit.json`,
`native-first-query-field-work-source-manifest.json` and
`native-first-query-field-work-twenty-case-controls.json`. The initial failed log
is preserved. Complete request/stream coverage, native work caps, the supplied
remaining-failure and success-floor premises, full adaptive soundness/knowledge
composition and matched native performance remain open. Admission remains false.

### V4 whole-family rejection-stop accounting

Canonical byte-family root identity is now separate from semantic proposed-run
replay. Existing accepted-draw/source admission checks remain unchanged, while a
new stop ledger includes every syntactic descendant at its maximal root, even
an off-path node beyond the verifier quota. It attributes each family at its
earliest member rather than a later root/replay. Both field controls preserve an
adversary-origin first descendant and a separate setup-origin root.

The conditional arithmetic helper `column_stop_first_family_bound` charges the
exact production MAX-cutoff geometric tail once per expected first-family trial.
The notes give the fresh latent-tree argument and the native power-of-two
maximum-domain/quota domination condition. Small-oracle controls expose the
selection bias (1/4 unconditional versus 3/8 after selecting a favorable
prequeried descendant), while first-family expectation charging remains valid.
Unknown origins and unbounded grinding remain explicit.

Eighteen proposal, seven history and twenty-one sampler/arithmetic tests pass
(forty-six total), frozen in `column-stop-first-family-tests-passed-audit.json` and
`column-stop-first-family-source-manifest.json`. Complete native family/geometry
coverage, ideal output-tree consistency, expected-work caps and automatic native
column-stop composition remain open, along with the full adaptive soundness/
knowledge reduction and matched native performance gate. Admission remains false
and production retry loops are unchanged.

### Native joint first-query/family sampler-stop reports

The native column-stop composition gap is now addressed within the conditional
model. A new sampler polynomial combines canonical field-input stops with v4
Brakedown first-family stops, using the maximum listed power-of-two domain and
ordered quota. It rejects invalid geometry, inconsistent retry thresholds and
unreviewed schedules/backends. V5 and non-Brakedown cases retain the field-only
coefficients. Because field inputs and first byte-family members have different
terminal frame kinds, their joint opportunity count injects into XOF inputs and
the global bound uses the larger local stop probability rather than their sum.

The new report combines this stop term once with explicit remaining failures
and oracle terms, retaining separate fixed-budget/expected-work interpretations.
The existing field-only interface is preserved. Lookup retries and application/
opening/source/coverage failures remain caller-supplied; no admission is inferred.

Fifty-six regression tests pass, including all twenty typed report cases and
role-tail domination checks. Source/log/control evidence is frozen in
`native-joint-sampler-first-query-tests-passed-audit.json`,
`native-joint-sampler-first-query-source-manifest.json` and
`native-joint-sampler-first-query-twenty-case-controls.json`. These arithmetic
controls use illustrative offsets and unknown remaining coverage, and execute no
native runtime. Complete runtime family/request coverage, native call/geometry
and work caps, ideal tree/stream consistency, the full adaptive soundness/knowledge
reduction and matched native performance remain open. Admission remains false.

### Native sampler phase maxima and conditional cap checks

The optional transcript observer now records the largest accepted field-value
count and ordered column-draw count in any sampler phase. These observations
use existing sampler events and do not change transcripts or retry loops. The
native validation example emits both maxima for setup, proving, accepted
verification and altered-output rejection. Older logs remain readable, but the
strict phase-maxima audit rejects missing or inconsistent observations.

`audit_classical_native_sampler_caps.py` compares fully audited accepted and
rejected verifier records with the descriptor's conditional sampler shape,
query, input-byte and output-byte ceilings. Records crossing the analysis's
lookup, field or column retry thresholds remain visible and are excluded from
the stopped-game resource comparison. Shape checks still apply. Honest
setup/prover activity is not compared with verifier ceilings, and direct
primitive calls are outside this observer's scope.

Fourteen Python tests and one Rust observer component test pass; the native
validation example builds. Component evidence is frozen in
`sampler-phase-maxima-component-tests-passed-audit.json` and
`sampler-phase-maxima-cap-source-manifest.json`. The component test's column
events are synthetic. A real n=1024/LWE728 v5 Brakedown run with one query
completed four accepted proofs and four altered-output rejections. All eight
verifier records satisfy the conditional caps without crossing analysis stops;
the observed field phase maximum is 65,536 values. All four complete validation
records exactly match the earlier reference, including proof hashes and sizes.
Evidence is in `sampler-phase-maxima-native-record-audit.json`,
`sampler-phase-maxima-native-cap-audit.json` and
`sampler-phase-maxima-native-exact-reference-audit.json`. This is a
correctness/counter control, not a security-matched benchmark or universal
adversarial bound. Complete
request/stream coverage, universal native work bounds, adaptive soundness and
knowledge composition, and matched native performance remain open. Admission
remains false.

### Recorded XOF stream-prefix consistency

The analysis history can now record prefixes beyond its original 64-byte
producer digest. Prefix extensions must agree on every previously recorded
byte, retain the first query's view and actor, and incur no new distinct-query
exposure. Exclusive checkpoints reveal only the prefix length recorded before
that boundary; later extensions do not repair earlier missing bytes. Inputs
whose real reader consumed fewer than 64 bytes still require the existing
explicit virtual completion for analysis.

The v5 algebraic-path control now has a recorded-stream entry point that checks
the exact consumed row and column bytes against prefixes available at an
explicit post-answer boundary. Its earlier bad-set construction is unchanged.
This checks trusted recorded provenance and consistency; it does not establish
the ideal-stream assumption or instrument every production reader.

Eight helper tests pass, including independent and incremental real SHAKE
readers over 4,096 bytes, a conflicting tail with the same first 64 bytes,
shorter replays, original actor preservation and old/foreign checkpoints.
Eighteen proposal tests also pass, including both fields' v5 primary-path
controls with recorded stream checks. Source and log evidence is frozen in
`recorded-stream-prefix-source-manifest.json` and
`recorded-stream-prefix-tests-passed-audit.json`. V4 native sequential-column
validation completed four proofs and four altered-output rejections, using one
query. All eight verifier records fit the conditional caps without crossing
analysis stops. Its field and ordered column phase maxima are 65,536 and one.
Evidence is in `sampler-phase-maxima-v4-native-record-audit.json` and
`sampler-phase-maxima-v4-native-cap-audit.json`; it establishes no security or
timing gate.

The authenticated v5 path helper now requires the same recorded-prefix
boundary, so authentication cannot bypass stream provenance. A negative control
changes an ignored high bit in a sampled column word: ordered indices and
Merkle authentication remain valid, but the recorded-stream check rejects it.
Older checkpoints and foreign histories also fail this entry point. All
eighteen proposal tests pass on the frozen final source, with evidence in
`recorded-authenticated-stream-source-manifest.json` and
`recorded-authenticated-stream-tests-passed-audit.json`.
The change remains analysis instrumentation, with complete production-reader
coverage and adaptive soundness/knowledge composition still open.

### Recorded v4 sequential-column past coins

Byte-run controls now check each completed draw against the trusted prefix
recorded for its exact request at a supplied post-answer boundary. This check
does not inspect the pending current answer and remains separate from proposal
admission: an adversary's first descendant can contain unqueried proposed past
coins and must still be counted. Later matching parent answers can establish
consistency at a later boundary without repairing the first descendant's
original producer view.

Nineteen proposal tests pass. The new control uses real transcript byte draws,
accepts matching recorded past coins, and rejects changed high bits that retain
the same accepted index. Missing past records and foreign boundaries fail,
including the empty-run foreign-boundary case. Source/log evidence is frozen
in `recorded-sequential-stream-source-manifest.json` and
`recorded-sequential-stream-tests-passed-audit.json`. Full v4 accepting-path
coupling and production-reader coverage remain open. The separate v4 native
maxima run subsequently passed the eight conditional-cap checks described
above; no security or performance admission follows from these controls.

### Combined recorded v4 row/column transition

A post-answer transition now combines exact row-request/receipt/coefficient
replay with recorded row-stream bytes and every completed sequential column
draw. It leaves the pending draw unread and does not alter first-family
proposal admission. Both field controls construct a matching descendant and
a changed-byte descendant with the same accepted index. Both remain admitted
proposals; only the matching descendant passes recorded-stream provenance.
Missing row-tail bytes at an earlier checkpoint and foreign histories fail.
The original frozen-ledger checks run before these later observations.

All nineteen proposal tests pass on the frozen final source. Evidence is in
`recorded-v4-row-column-source-manifest.json` and
`recorded-v4-row-column-tests-passed-audit.json`. This narrows the
analysis-control provenance gap; complete actual-reader coverage, v4 accepting
path authentication coupling and adaptive soundness/knowledge remain open.

### Optional actual-reader chunk observation

`observe_with_output_chunks` extends the transcript audit interface with exact
reader input, byte offset and borrowed returned bytes. Repeated readers restart
their offsets at zero; empty reads are reported. The callback inherits the
observer across child states/workers and stops with its guard. Input-only and
resource-only observers do not retain reader inputs or copy returned chunks.
The non-audit build does not include this instrumentation. No virtual output
completion is emitted for short reads.

Thirty-nine tests pass across audit transcript units, reader/history integration
and non-audit transcript units. The integration feeds actual prime/extension
sampler, receipt and byte-challenge reads into the prefix history, then verifies
identical challenge values with auditing disabled. This reconstruction checks
post-read byte consistency; it does not certify temporal query ordering or a
complete native query ledger. Sources and logs are frozen
in `reader-output-chunks-source-manifest.json` and
`reader-output-chunks-helper-tests-passed-audit.json`. The verifier counter
component test and all nineteen proposal tests also pass, bringing the total
to fifty-nine checks across the runs; their evidence is in
`reader-output-chunks-compatibility-tests-passed-audit.json`. The completed native maxima runs
used the earlier frozen runner and do not validate this new callback. Complete
native-reader/path coverage and the full security/performance gates remain open.

### Actual-reader snapshots in primary-path controls

The Brakedown transcript replay now captures returned chunks with the optional
reader observer. A prefix collector merges overlapping/restarted reads by
exact input and rejects gaps, conflicting bytes and overflowing offsets.
The v4/v5 primary-path controls consume a snapshot of these observed row bytes.
V5 also compares its column bytes with the actual reader snapshot; v4 obtains
its first sequential draw directly from the snapshot after replaying its draws.
Snapshots are copied before entering callbacks that can themselves replay the
verifier, avoiding a held collector lock across those calls.

All twenty proposal tests pass, including the collector controls and both
fields' selected v4/v5 path checks. Source/log evidence is frozen in
`observed-reader-primary-path-source-manifest.json` and
`observed-reader-primary-path-tests-passed-audit.json`. These controls use
n=32/LWE21 and establish post-read provenance for selected paths, not complete
temporal query ordering, arbitrary-query coverage or native security admission.

### Selected real-reader first-query boundaries

The reader snapshot now records input callbacks and prefix-growth events in
the same serialized collector. Repeated inputs retain their original first
query event. A frozen-prefix lookup returns only consumed bytes strictly before
that event, so later reads or input repeats cannot repair its earlier view.
Unregistered inputs, gaps, conflicting bytes and offset/event overflows fail;
an observed empty read remains distinct from a missing output.

Both fields' v4/v5 controls now check that the complete row stream precedes
the first column query, and that the column query cannot see its own output.
The v4 control also checks that its first completed draw precedes the next
draw request. These are checks on selected real verifier replays; the separate
adversarial proposed-input ledgers retain their original semantics.

All twenty-one proposal tests pass. Source/log evidence is frozen in
`observed-reader-temporal-source-manifest.json` and
`observed-reader-temporal-tests-passed-audit.json`. Complete joint hash/XOF order,
actor provenance, arbitrary-query/reader coverage and the native soundness,
knowledge and performance gates remain open.

### Complete-PBS reader-instance companion stream

An optional reader-event observer assigns a scope-local ID to each reader,
emits its exact input once, and emits each actual output chunk with its offset.
Repeated inputs still receive different reader IDs; these IDs are not distinct
oracle trials. This mode does not retain the full input for each reader or
repeat it for every short sampler read. Existing observer interfaces remain
available.

The full-PBS recorder has an optional companion file that serializes hash
events, reader starts and returned chunks under the same stream lock. It also
writes the existing legacy query file, so all existing source/receipt checks
remain available. A new focused control enables the companion without changing
the twenty-case matrix's default behavior.

`audit_classical_reader_event_stream.py` independently checks SHA-512 preimages,
SHAKE256 returned bytes, reader identities, contiguous offsets and phase order.
It can compare the companion's query projection byte for byte with the legacy
file, detecting reordered events even when their counts agree. It uses bounded
IO blocks and geometric SHAKE-prefix caching; claimed lengths are not treated
as allocation instructions. Seventeen helper, five auditor and twenty-one
proposal tests pass (forty-three component checks), with evidence in
`complete-reader-events-component-tests-passed-audit.json`. The focused
full-PBS control passed from its frozen executable. The independent companion
audit verified 1,593 readers and 228,855 joint events, including all consumed
SHAKE256 bytes and a byte-for-byte exact legacy query projection. The verifier
portion contains 795 reader starts, 108,081 reads and 460,584 returned bytes.
The existing source/temporal-control auditor also passed on the legacy file.
Evidence is in `complete-reader-events-focused-passed-audit.json` and
`complete-reader-events-focused-source-controls-audit.json`. This is one
n=32/LWE21, BabyBear^6, v5 Brakedown control with synthetic keys, not completion
of the twenty-case matrix or native qualification. Sources are frozen in
`complete-reader-events-source-manifest.json`. The initial helper build failed
the crate's documentation lint; that log is retained and the documented final
source passes. Complete native reader/actor coverage, ideal-stream assumptions
and full soundness/knowledge/performance admission remain open.

### Optional native verifier reader captures

The native counter verifier now accepts an optional borrowed event callback.
Capture mode retains each instrumented hash state's preimage, including clones
and resets, and serializes hash/reader events through one writer. Default
counters retain no hash preimage buffers. The existing strict verifier entry
point delegates with capture disabled; transcript/proof semantics are unchanged.

`classical_native_validation --reader-events` captures ordinal zero's accepted
and altered-output rejected executions in separate immutable files. Each capture
also runs ordinary observation and checks the same accept/reject outcome and
identical counters. Its log
record binds the file fingerprint to profile, proof, statement, setup and FHE
dimensions. All four scheduled proofs are still validated. Trace paths use a
canonical byte-hex encoding rather than unescaped JSON path strings.

`audit_classical_native_reader_events.py` joins the first pair to complete strict
correctness/count records, independently checks hash and reader bytes, and
compares every query/input counter plus total/maximum returned bytes. These
verifier-only files must contain no setup/prover events. Captures remain partial
coverage of the instrumented interfaces; direct primitive calls are excluded.

One Rust observer and twenty Python tests pass. The toy preflight passed four
proofs and both captures (861 accepted readers, four rejected readers), with
independent byte/binding evidence in `native-reader-events-toy-passed-audit.json`.
Source/component evidence is in `native-reader-events-source-manifest.json` and
`native-reader-events-component-tests-passed-audit.json`. The original-size
n=1024/LWE728 v5 Brakedown run passed all four proofs and altered-output checks.
Both captures passed independent byte/proof/counter binding, with 1,250 accepted
readers and four rejected readers. All eight verifier counter records fit the
conditional caps, and all four complete validation records exactly match the
earlier reference. Evidence is in `native-reader-events-native-passed-audit.json`,
`native-reader-events-native-cap-audit.json` and
`native-reader-events-native-exact-reference-audit.json`. This is a one-query
correctness/capture control, not a security-matched benchmark.
Universal native coverage, adaptive soundness/knowledge, all-trials work and the
matched native performance gates remain open. Admission remains false.

### Observed reader completion and causal raw receipts

`audit_classical_reader_inventory.py` classifies the actual reader inputs and
decodes canonical field candidates from independently verified returned bytes.
It checks descriptor completion without allocating from declared counts. Unknown,
foreign, malformed, incomplete and cross-phase readers remain explicit. Completed
field phases are matched to receipt inputs using exact raw-byte equality and
strict temporal precedence, including duplicate empty streams. A receipt queried
before its field bytes complete cannot be repaired by later matching output.
This is syntactic/byte provenance, not authenticated semantic stage binding.

Nineteen reader/request/binding tests pass, including early receipts, overreads,
huge declared byte counts and unclassified inputs. The verified toy captures
have closed inventories with 346 accepted and two rejected field/receipt pairs;
all seven independently decoded field metrics equal the observer counters.
The saved complete-PBS focused capture also closes all recorded readers, with
649 pairs (325 proving, 324 verifying). Its descriptor inventory reconciles
exactly with 460,684 proving and 460,584 verifying returned bytes and with the
legacy receipt-derived field metrics. These are finite captured-trace results.

Evidence is frozen in `reader-inventory-source-manifest.json`,
`reader-inventory-tests-passed-audit.json`,
`reader-inventory-toy-captures-passed-audit.json`,
`reader-inventory-complete-pbs-focused-passed-audit.json` and
`reader-inventory-complete-pbs-legacy-comparison.json`. The verified original-size
native pair also has closed inventories: 539 accepted and two rejected
field/receipt pairs, with all seven field metrics matching the observer counters.
Its evidence is in `reader-inventory-native-captures-passed-audit.json`.
Arbitrary-query coverage, semantic stage/knowledge coupling, universal
native work bounds and matched performance remain open. Admission remains false.

### Caller-factory role context diagnostics

Reader-enabled validation now emits four context digests computed from the
caller factory's actual role parameters. V4 sequential draw requests do not
carry their domain size directly; these diagnostics prepare an explicit role
geometry join rather than guessing that size from byte-request labels. They
are diagnostics, never verifier profiles loaded from proof data.

The example builds. A v4 toy control with eight ordered draws passed all four
proofs and both reader captures, checked the four factory context digest values,
and matched the independently decoded field metrics to the observer counters.
Evidence is frozen in `role-context-diagnostics-source-manifest.json` and
`role-context-diagnostics-v4-toy-passed-audit.json`.
The independent context-preimage join and v4 toy column reconstruction are
described below. The completed native capture above used the earlier executable
and does not validate this new diagnostic. All security/performance gates remain
open.

### Observed role-context preimages and geometry

The reader auditor can now deliver verified hash preimages to a consumer.
`audit_classical_role_contexts.py` binds the caller diagnostic to completed
proof/counter/capture records and joins each role digest to an observed parameter
preimage. It checks the namespace, modulus, role dimensions/quota, domain
separator and complete serialized block-code geometry against the decoded
profile. It parses the root wire representation but does not establish NTT-root
algebra or semantic stage admission. Additional parameter contexts remain
explicit, and missing declared contexts fail the audit.

Twenty-two context/reader/request tests pass. The saved v4 eight-draw toy capture
has all four declared contexts, no additional contexts, and domain size 32 for
each role. Source/log evidence is frozen in
`role-context-preimages-source-manifest.json`,
`role-context-preimages-tests-passed-audit.json` and
`role-context-preimages-v4-toy-passed-audit.json`. The preimage join is now checked
for this control; sequential-column reconstruction is described below. No universal
adversarial, native security or performance admission follows.

### Observed v4 sequential-column reconstruction

`audit_classical_column_readers.py` now groups byte readers by the exact maximal
trailing run root, joins the caller context to its verified role geometry, and
replays the production `MAX - MAX % domain` cutoff. It retains ordered repeated
indices before deduplication. Repeated root readers are physical run instances,
not new distinct root-family trials. Each descendant's inline past bytes must
match predecessor outputs available strictly before its input was queried.

Missing/partial draws, forks, unavailable predecessors, inconsistent run
multiplicity and queries beyond the ordered quota remain explicit failures;
they cannot become completed sampler calls. The first queried family member's
position is retained even when it precedes the root query. The tool requires
complete closed inventories before comparing all five column resource counters.

Twenty-seven column/context/reader/request tests pass. The saved v4 eight-draw
toy capture independently reconstructs 157 sampler calls and 1,256 ordered
draws, including 128 duplicate accepted draws. All five counters match; the
rejected capture contains no column draws. Evidence is frozen in
`column-reader-inventory-source-manifest.json`,
`column-reader-inventory-tests-passed-audit.json` and
`column-reader-inventory-v4-toy-passed-audit.json`. These are observed v4 toy
results. Semantic stage admission, arbitrary-query coverage, universal native
work bounds and security-matched performance remain open. Admission stays false.

### Algebraic validation of observed context roots

`audit_classical_context_roots.py` consumes a saved context-preimage join,
binds it to the strict proof/counter log and caller role geometry, and checks
the serialized root's exact order. For a power-of-two domain N it requires
`root^N = -1` in the reviewed prime field, which proves exact order 2N.
It decodes BabyBear's canonical Montgomery wire representation and Goldilocks'
direct u64 representation, including the latter's lazy representatives.
Unsupported domains and field storage values reject before exponentiation.
The tool records the consumed evidence's SHA256 and explicitly does not claim
to rescan its preimages or establish transform correctness or stage binding.

Three focused tests pass, covering both fields through their largest supported
negacyclic domains, lower-order roots, incorrect representations and the actual
captured BabyBear root. All four roles in the saved v4 eight-draw toy context
join pass. Evidence is in `context-root-algebra-source-manifest.json`,
`context-root-algebra-tests-passed-audit.json` and
`context-root-algebra-v4-toy-passed-audit.json`.

The follow-up `context-root-binding-*` evidence strengthens this check by
reconstructing the exact standard-bincode parameter preimage, hashing it with
SHA512, and requiring equality with both the saved context join and the caller's
diagnostic in the bound log. An alternative root of the same valid order cannot
be substituted, even if the saved join's digest is altered alongside it.
Five focused tests pass, including both fields, all four roles, integer encoding
boundaries and this substitution control. The actual four toy contexts also
pass; see `context-root-binding-v4-toy-passed-audit.json`. The running native
driver and its frozen auditor sources are unchanged.

The original-size v4 capture/reconciliation process is active under the frozen
role-context diagnostics executable. Its launch record is
`column-reader-v4-native-running.json` and its log is
`target/performance/classical-column-reader-v4-native-tests.log`.
No terminal result has yet been observed. This one-query run is a correctness
and capture control. Security admission and matched performance remain open.

### Expected work without a success floor under conditional hazards

`classical_hazard_work.py` adds a distinct expected-work theorem interface.
It requires the first-success probability at charged unit step j to be at most
`h_j = min(1, a + b*j)`, conditional on the entire pre-step joint history.
The charged index is global across retries and verifier submissions. No success
may occur before a charged step. These are stronger premises than an
unconditional success-by-budget CDF; the existing CDF-only interface still
requires its supplied success floor. Neither interface establishes the other's
premises from observed counters.

For completeness, consider the dominating process that succeeds independently
at each step with probability h_j. This auxiliary independence defines the
comparison process only; actual trials need not be independent. For b>0 the
hazard reaches one at finite K. Let v_j be its expected remaining steps after j
failures, with v_K=0 and `v_j=1+(1-h_(j+1))*v_(j+1)`. Monotonicity of h gives
`0 <= v_j <= v_0 = C`, by coupling remaining waiting times using shared uniform
draws. Define the nonnegative potential `V_j=C-v_j`, and `V_j=C` for j>=K.
Before actual success, a step whose conditional success chance p is at most
h_(j+1) has
`-1 + p*C + (1-p)*V_(j+1) <= V_j`.
The inequality follows from the recurrence and `C-V_(j+1)=v_(j+1)>=0`.
Stopping discards a nonnegative potential. Starting from V_0=0, finite-horizon
backward induction therefore gives `C*Pr(success by n) <= E[min(W,n)]`
for every stopping policy. Monotone convergence extends this to arbitrary
adaptive stopping, including zero-work failures and rare randomized branches.
Thus `E[W]/Pr(success) >= C` whenever the success probability is positive.
For constant hazard, summing the conditional per-step probabilities gives the
sharper exact ratio `1/min(1,a)` directly.

The implementation avoids enumerating K. The comparison process has
`Pr(success by t) <= min(1, a*t + b*t*(t+1)/2)`, so summing its complementary
CDF yields an exact rational lower bound on C using the existing polynomial
tail-sum routine. The probability-one argument used internally refers to the
auxiliary dominating process, not the actual adversary. This supplies no
fixed query cutoff and no actual-success-floor assumption.

Four tests pass: exact finite survival and optimal adaptive stopping by backward
induction, rare participation down to 2^-256, constant-hazard edge cases and
exact arithmetic at 256-bit support without iterating the work budget.
Evidence is frozen in `conditional-hazard-work-source-manifest.json` and
`conditional-hazard-work-tests-passed-audit.json`. The complete protocol's
conditional hazard and charged-work coupling remain unproved; no existing
all-trials polynomial or captured trace is automatically promoted to this
stronger premise. Security and performance admission remain false.

### Predictable joint-oracle hazards and expected work

`joint_oracle_hazard` now computes a conditional affine first-bad-event hazard
from explicit limits on fresh hash/XOF answers per charged step. Before step j,
the separate prior-answer counts must be bounded by `q_H*j+h_H` and
`q_X*j+h_X`. Throughout the step, predictable registered targets must be bounded
by `w*j+w_0`. If the step produces at most r_H and r_X fresh answers, the
hazard is at most
`[(r_H+r_X)*(w*j+w_0) + r_H*(q_H*j+h_H) + r_X*(q_X*j+h_X)
  + r_H*(r_H-1)/2 + r_X*(r_X-1)/2] / 2^512`, capped at one.
Each within-step unordered collision pair is charged once; hash and XOF outputs
do not create cross-oracle collision pairs. Repeated queries are not fresh
answers. Predictability and conditional uniformity permit a union bound across
adaptively interleaved answers, without independent bad events. The caps must
hold pathwise on every relevant pre-answer history, including verifier batches;
aggregate observed counts or derivatives of a budget polynomial do not suffice.

`joint_hazard_work_report` requires a separate affine conditional hazard for
ALL remaining failures, unions it before the expected-work conversion, and
retains the complete-history and charged-index premises. Remaining coverage
includes field/column stops, algebraic transitions, complete stream consistency
and knowledge failures. An uncharged initial bad event cannot be discarded.
Supplying one as the remaining constant yields the trivial one-step bound.
No existing native cap or success-by-budget polynomial is automatically treated
as a proved conditional hazard.

Seven tests pass, including exact enumeration of batch exposure increments,
separate-oracle and repeated-query boundaries, mandatory remaining hazards,
adaptive stopping and rare branches. Frozen source/test evidence is in
`joint-conditional-hazard-source-manifest.json` and
`joint-conditional-hazard-tests-passed-audit.json`. This completes the arithmetic
composition interface; pathwise native cap proofs, complete protocol coupling,
security admission and matched performance remain open.

### Canonical-field first-input conditional hazard

`field_sampler_hazard` connects the pure canonical-field rejection tail to the
new conditional-hazard interface. At an eligible first input, the descriptor
fixes at most C base-field values. For masked support S and reviewed prime p,
let r=(S-p)/S. In a fresh ideal whole-stream completion, each of the at most C
geometric waiting segments has probability r^R of beginning with R rejections.
The conditional first-input stop probability is therefore at most
`min(1,C*r^R)`. A per-step bound B on distinct fresh XOF inputs yields constant
hazard `B*min(1,C*r^R)`, with saturation handled by the expected-work converter.
The latent stop is assigned at the input's first query, even if a later verifier
consumes its bytes. Reusing that input supplies no new independent trial.

The descriptor/count superclass, common whole-stream completion and all-actor
fresh-input batch cap remain explicit premises. The function does not derive
those premises from observed traces. In particular it does not treat v4 column
families or lookup reciprocal retries as field phases. The work report accepts
this component explicitly, adds it once with the oracle hazard, and still
requires every remaining failure's conditional hazard.

Nine focused tests pass. They cover both fields, both schedules and all five
backends (20 native profile combinations), with zero, one and 17 fresh inputs
per charged step. Unknown remaining coverage keeps the resulting report at the
trivial one-step bound. Goldilocks tail denominators exceed Python's default
decimal-string conversion limit; the checks use the existing chunked exact
rational parser without changing that global limit. Evidence is frozen in
`field-conditional-hazard-source-manifest.json` and
`field-conditional-hazard-tests-passed-audit.json`. Complete native request
coverage, whole-stream/column-tree consistency, application/knowledge coupling
and performance admission remain open.

### Joint native sampler conditional-hazard composition

The expected-work interface now accepts `native_sampler_hazard`, combining
the field and v4 Brakedown column first-opportunity terms using their disjoint
input classes. A caller-supplied per-step fresh-XOF-input ceiling multiplies
the maximum of their local bounds. The implementation reuses only the reviewed
local probability/geometry calculation, not an aggregate query polynomial as a
conditional-hazard premise. V5 and other backends retain zero column rejection.
The report rejects simultaneous field-only and combined sampler components;
lookup failures and all remaining protocol hazards stay mandatory separate
premises. The family model includes early off-path descendants and requires
fresh whole-tree consistency before their first answer.

Ten tests pass, including all 20 typed native profile combinations, exact
production MAX-cutoff tails, zero column contributions outside v4 Brakedown,
double-charge rejection and trivial bounds for unknown remaining coverage.
Evidence is frozen in `native-sampler-conditional-hazard-source-manifest.json`
and `native-sampler-conditional-hazard-tests-passed-audit.json`.
This does not establish native family/request coverage or all-stage conditional
failure bounds. The original-size capture remains live, with no terminal result
yet observed; security and performance admission remain false.

### Rejected Brakedown call hash resources

The PCS counter regression now exercises 264 rejected single/batch openings
across both fields, v4/v5 and draw counts below/above the domain size. It checks
exact context-output counts at malformed shape guards and the all-columns hash
bound for corrupted symbols, leaves and siblings, including parallel workers.
The existing accepted five-backend counter controls also pass in the same
single counter-owning Rust test. A compile error from using the adapter commit
signature on the inherent method is preserved in the initial test log; the
corrected run exits zero.

The source-level per-call bound and scope are documented in `block-rs.md`.
Sources, executable fingerprint and terminal evidence are frozen in
`rejected-brakedown-hash-resources-source-manifest.json` and
`rejected-brakedown-hash-resources-tests-passed-audit.json`. This establishes
neither parent invocation ceilings nor complete native pathwise resources.
The native capture is still active on its fourth proof. The full security,
knowledge, work and matched performance gates remain open.

### Rejected Brakedown transcript resources and call worksheet

The rejected-call regression passes with transcript observation enabled and
disabled. The enabled run checks zero XOF requests for all 192 shape failures
and exact field/receipt/column counts and returned bytes for 72 authentication
failures. Ordered duplicate draws remain counted even when Q exceeds N.
Three Python controls reconcile the new geometry-only single-call worksheet
with existing native PCS/hash counts across 16 role/field/schedule combinations.
The worksheet separates the unconditional hash bound from stopped field/v4
column output bounds, and does not alter production loops. It avoids unnecessary
soundness-probability exponentiation when handling large quotas. An initial
overflow-control test was deliberately terminated after exposing that unnecessary
calculation; the geometry-only replacement and its large-quota controls pass.
No native or production validation job was cancelled.

Sources, enabled/disabled executable fingerprints and terminal evidence are in
`brakedown-call-resources-source-manifest.json` and
`brakedown-call-resources-tests-passed-audit.json`. Parent invocation ceilings,
input construction, complete native work and security/performance admission
remain open.

### Completed native v4 reader and column reconciliation

The frozen original-size v4 diagnostics executable exited zero. All four
n1024/LWE728 proofs and altered-output rejections pass. Every proof record is
exactly equal to the earlier v4 sampler-maxima reference. The first accepted
and rejected captures have closed actual-byte field inventories (539 and two
causally matched raw/receipt pairs), and all seven field counters match. The
accepted column inventory closes 160 families and 160 ordered draws; all five
column counters match. The rejected capture has no column draws. All eight
verifier records satisfy the conditional stopped-cap comparisons.

Observed context preimages join all four caller roles with domains
128,512,32,32. Reconstructed parameter preimages hash to the caller context
digests, and decoded roots have exact negacyclic orders 256,1024,64,64.
The terminal aggregate `column-reader-v4-native-complete-passed-audit.json`
binds the individual evidence files by SHA256, including
`context-root-binding-v4-native-passed-audit.json`. The log SHA256 is
`d428ff523d9d67c596f388ca4df8464176e0271c2e5c1834897c9331e4e200cf`.

This closes the observed original-size v4 capture/reconciliation milestone.
The run uses Q=1; it is not a 128-bit profile or a timing comparison. Semantic
stage/knowledge binding, arbitrary-query coverage, universal native work caps
and security-matched performance remain unproved. Admission remains false.

### Shared call resources in the native PCS worksheet

`native_pcs_query_envelope` now derives its Brakedown request/byte counts from
`classical_brakedown_resources.call_envelope`, exposing the single-call bounds
and their stopped-resource assumptions beside the caller's invocation ceiling.
Trusted role geometry is shared through the pure
`classical_brakedown_geometry.py` module; context auditing reexports the same
function, with no import dependency from resource arithmetic on trace auditors.
The existing aggregate numerical bounds are unchanged.

Forty-seven context/root/resource/candidate/hazard/cap tests pass. Recomputing
the completed original-size v4 and v5 conditional cap audits yields exactly the
saved results, and the original-size v4 context-root binding audit is likewise
exactly unchanged. No native proofs or multi-gigabyte reader scans were rerun
for this arithmetic integration. Evidence is frozen in
`brakedown-call-resources-integration-source-manifest.json`,
`brakedown-call-resources-integration-tests-passed-audit.json` and
`brakedown-call-resources-integration-native-comparison.json`. Parent invocation
and complete pathwise work bounds, security and matched performance remain open.

### Submitted parent PCS calls on rejected paths

The parent context wrapper now counts single/batch PCS entry before delegation.
A focused complete synthetic BabyBear v4 Brakedown control passes with accepted
calls [70,8,50,7] below [86,8,64,7]. Missing main NTT/decomposition vectors reject
with zero calls; missing final NTT/borrow vectors retain preceding stage counts
and remain below the same ceilings. This is n32/LWE21, not an encrypted native
security profile. Frozen executable/source and terminal evidence are in
`parent-call-resources-source-manifest.json` and
`parent-call-resources-focused-passed-audit.json`.

The source argument in `canonical-opening-budget.md` accounts for every parent
stage's fixed loops, vector guards and caller-derived source registry. It bounds
submitted PCS calls, including a failing delegated call, by
[16d+22,2d,8s+8,s] for the reviewed fixed shared configuration. Rejection exits
cannot repeat a PCS loop, and root aliases cannot introduce source slots. The
schedule now records this restricted source-level call bound explicitly. This
does not promote transcript-byte, full hash/context or attacker-work bounds.
Forty-nine Python schedule/resource/hazard controls pass, and recomputed v4/v5
native cap audit results remain exactly equal to the frozen references.
Evidence is in `parent-call-resource-schedule-source-manifest.json` and
`parent-call-resource-schedule-tests-passed-audit.json`. Full native resources,
adaptive soundness/knowledge coupling and matched performance remain open.

### Delegated PCS failure accounting across both fields and schedules

The focused parent control now runs BabyBear and Goldilocks with v4 and v5.
The test wrapper can alter a claim's first coordinate immediately before the
chosen real PCS delegation. For each valid parent proof it targets the first,
middle and final call, requires a backend rejection, and checks that the summed
role counters equal that target exactly. Thus the first failing call is counted
and no subsequent parent call is submitted. This exercises the counter's error
path; it does not construct a forged parent certificate.

All 32 records pass: four accepted, 16 child-vector rejections and 12 delegated
claim failures. Accepted counts are [70,8,50,7] for BabyBear and [118,16,86,13]
for Goldilocks in either schedule, below the source-derived caps. Sources,
executable fingerprint, log and terminal records are frozen in
`parent-delegated-failure-source-manifest.json` and
`parent-delegated-failure-passed-audit.json`. The controls use n32/LWE21
synthetic keys. Complete native work, adaptive soundness/knowledge coupling
and matched performance remain open; security admission remains false.
