# Shape-derived canonical opening allowances

The first original-size masked Goldilocks PBS run stopped at accumulator linkage
with an insufficient private mask lifetime. The harness had copied `width+8`
from the ring-32/LWE-21 fixture. It is correct there but not at LWE 728.

`packed_accumulator::Shape::opening_counts(width)` now exposes the exact counts
of its seven query maps. With r padded-round bits, the input accumulator uses
one base query, one initial-row query, r shift branches and one wrap branch:
r+3 in total. Its separate monomial NTT uses another width queries on that same
owner. The required total is width+r+3. At LWE 21, r=5 gives width+8; at LWE 728,
r=10 gives width+13: 17 for Goldilocks width 4, 21 for BabyBear width 8.

`Config::canonical_opening_budget(width)` derives a named per-owner resource
plan for complete canonical versions 10/11. It includes coefficient,
evaluation, input, borrow, reciprocal-helper, monomial and final-stage owners.
These are per-source counts for one PBS, not a count of roots, a soundness
worksheet or a private masking theorem. The query-map tests compare the public
count contract with the actual generated maps, including the zero-row-bit case.

`CanonicalPcs` exposes optional declared and remaining opening allowances. Both
bounded masked backends report their actual private-owner counters. Backends
without exposed bounds retain the default None. These are resource methods;
parameter serialization, transcript contexts and proof formats do not change.

Complete canonical parameter validation now rejects an exposed finite limit
below the full operation schedule. This occurs before witness commitments or
proof messages. The native harness derives all its allowances from the plan
and explicitly checks them before generating key setup. It retains the original
mask-capacity guard; a larger allowance must still fit a constructor-validated
physical domain. Goldilocks's corrected 17-opening accumulator fits physical
21; BabyBear's 21-opening accumulator requires physical 23. Logical FHE
variables, dimensions, noise and output keys remain unchanged.

The prover also checks already-exhausted retained native key owners before
constructing fresh witness owners. This is an observation rather than an
atomic reservation across all keys: per-source opening calls retain their
existing locks/reservations and late failures retain spent allowances.

Three new budget tests pass: native/small schedule derivation, every finite
role's insufficient-limit rejection, and shared remaining counters through
independent/joint-source parameter views. The original native mistake now
reports `accumulator input: required 17, configured 12` without committing data.
The complete integration test additionally requires a third proof attempt on
exhausted original key owners to reject without consuming RNG output.

Sources, raw checks and complete-proof compatibility results are archived under
`target/performance/canonical-opening-budget/`. The failed native run remains
preserved under `target/performance/native-complete-masked-pbs/goldilocks-run-1/`;
its status 101 is terminal, not an observation timeout. It produced no complete
proof or replay. Full native validation and the original security, hiding,
aggregation, performance and review gates remain open until separately proved.

Both complete joint-backend integration tests pass, including versions 10/11
over both fields and the exhausted-key/RNG checks. Every non-timing field of
all four profiles, including proof hashes, matches the archived pre-change
profiles exactly. The actual query-map test passes one selected test (the
initial incorrectly named zero-test filter is preserved but is not evidence).
The workspace all-target check passes with the existing VFHE warnings.

The final complete-regression executed source archive SHA-256 is
`5e1a5864d0de8dc86751d6512262e77a4dec4778fc1123a444fedb84c9cd524b`.
Subsequent canonical-prover changes are exactly rustfmt output, checked against
that archive. The formatted source archive SHA-256 is
`15132835e3515f828ed5db7fbe5206b25ba4ab87908c68a402d11c260949fcf8`.
Cargo.lock remains
`293790853366e0bc0562752d17999bab335368dd6e0c33823f1afaee8c214718`.

## Submitted PCS calls on rejected shared-parent paths

For one invocation of the trusted shared v11/v12 parent, fix the original
radix-8 main decomposition, radix-5 final decomposition and one lookup repetition
per comparison request. Let d and s be the corresponding trusted digit counts.
Count a PCS call when its `verify`/`verify_many` method is entered, including the
first failing call. The four role call totals are bounded by
`[16*d+22, 2*d, 8*s+8, s]` for every proof, not only accepted proofs.
This concerns the parent-to-PCS interface, not calls made inside an adapter.

| Parent stage | Role | Submitted call bound | Source guard or loop |
| --- | ---: | ---: | --- |
| Main NTT | 0 | 2(2d+1) | Parent checks NTT count, loops exactly 2d+1; each NTT makes at most two calls |
| Main key product | 0 | 4d+1 | Factor count is caller-derived; relation values/openings must match it |
| Two main linear decompositions | 0 | 2(2d+2) | Each borrow-root list must have d+1 entries; linear openings match caller source count |
| Two main lookup source registries | 0 | 2(2d+1) | Digits and borrows supply 2d+1 slots per registry; grouping cannot create slots |
| Accumulator | 0 | 7 | Exactly seven value/opening groups, zipped with caller-derived source queries |
| Monomial NTT/product | 0 | 4+2 | Exactly two NTTs and two product openings, with proof counts checked first |
| Main lookup helpers | 1 | 2d | Two sets of d requests, each with one repetition; helper proof counts equal that sum |
| Final known input/extraction | 2 | 1+1 | One direct PCS call at each fixed endpoint |
| Final NTT | 2 | 2(s+1) | Final NTT count must be s+1; each relation makes at most two calls |
| Final key product | 2 | 2s+1 | Fixed caller-derived factors and matching proof count |
| Final linear decomposition | 2 | 2s+2 | Same linear/borrow guards as above with s digits |
| Final lookup sources | 2 | 2s+1 | Fixed digit/borrow registry, grouped only by root and trusted context |
| Final lookup helpers | 3 | s | s trusted comparison requests and one repetition each |

The relevant implementations are `packed_pbs/canonical.rs`, `packed_ntt.rs`,
`packed_relation.rs`, `packed_linear.rs`, `packed_accumulator.rs`,
`packed_monomial/canonical.rs`, the shared decomposition/lookup verifiers,
`packed_opening_batch.rs`, and the final key-switch protocol. The registry
constructs representatives from caller source slots before examining opening
packets; its packet count must equal the number of used groups. Aliasing and
unused slots can decrease that count. A proof cannot add a representative.
All listed call loops are fixed by those trusted shapes or checked counts.
An error exits through `?`, without a retry of a PCS call. Field and reciprocal
rejection loops occur before the corresponding PCS loops and do not themselves
delegate PCS calls. Thus every finite rejected or nonterminating execution
prefix also satisfies the submitted-call bound. No adversary query cutoff or
production sampler cutoff is needed for this call-count statement.

`shared_stage_schedule` records this restricted source-level result separately
from transcript-byte and attacker-work bounds. The focused complete-PBS
regression counts before delegation on an accepted synthetic BabyBear v4
Brakedown proof and four altered child-vector proofs. Missing main NTT or
decomposition vectors make zero calls; missing final NTT or borrow roots retain
earlier calls and stay within the same caps. Its frozen evidence is
`parent-call-resources-focused-passed-audit.json` in the opening inventory.
The control uses n32/LWE21 synthetic keys and does not establish original-size
security. The general call-count argument comes from the guards above, not
from extrapolating that finite control. Whole-verifier hash/context counts,
XOF/input construction, conditional failure bounds and knowledge security
remain separate obligations.

The follow-up control runs both BabyBear/Goldilocks and v4/v5. Its test wrapper
can perturb the first coordinate of a derived claim immediately before a
selected real PCS delegation. For each accepted proof it selects the first,
middle and final submitted calls, preserves the accepted history before that
point, and requires the backend to reject. Exactly one claim is perturbed, and
the role-count sum must equal the selected ordinal: the failed invocation is
included and the parent submits no later call. This is a test of error-path
resource accounting, not an adversarial forgery construction.

All 32 records pass: four accepted, 16 malformed child-vector cases and 12
delegated-claim failures. BabyBear accepted counts are [70,8,50,7] for both
schedules, with failures at ordinals 1,67,135; Goldilocks counts are
[118,16,86,13], with failures at 1,116,233. All satisfy the source-derived caps.
The frozen executable, source manifest and terminal records are
`parent-delegated-failure-*` in the opening inventory. These remain synthetic
n32/LWE21 controls; the universal submitted-call argument and its limited
scope are unchanged.
