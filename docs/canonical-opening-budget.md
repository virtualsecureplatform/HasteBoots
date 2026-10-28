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
