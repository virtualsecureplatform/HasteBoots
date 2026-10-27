# Measured results — 2026-10-27

The existing complete BabyBear PBS backend is faster after the scalar sumcheck
and PCS aggregation changes. The packed implementation now composes a complete binary NAND PBS relation
through `snarks::packed_pbs`. It remains experimental and unbudgeted for whole-
proof security, and is not a promoted replacement for the existing backend. The complete research plan
is unfinished. See [remaining implementation and research gates](performance.md#research-gates-and-remaining-implementation).

## Block-RS component follow-up

The block-RS encoder and whole-symbol MW openings are now implemented. A single
16-thread release smoke run on the original full-size BabyBear native trace
verified the external-product Hadamard relation with 17 factors and eight packed
lanes. It measured 0.874 s preparation/commitment, 0.621 s proof generation and
0.175 s verification. The component proof was 62,534,859 bytes, plus 545 bytes
of separately supplied commitments. Whole-process peak RSS was about 1.13 GiB.
These are component smoke measurements, not a complete-PBS benchmark or a
two-session performance promotion result.

The actual layout has 18 packed variables, four row variables, 2,048 padded
coefficient symbols, 4,096 encoded symbols and 512 independent query samples.
The recorded conservative component algebraic model totals approximately
`9.31e-40`, below `2^-128`. This does not account for the missing PBS relations,
their composition, Fiat-Shamir knowledge soundness or hiding. The complete
128-bit target remains open.

The follow-up regression run passed 97 Rust tests across algebra, PCS, PIOP,
sumcheck and SNARK crates, plus four Python tests. Actual component metadata,
phase timings, model output and resources are in `target/performance/block-rs/`.
Construction details are in [block-rs.md](block-rs.md).

## Complete PBS measurements

Intel Core i9-12900K, Rust 1.98.0, release/LTO, native CPU target, Rayon thread
counts below, artifact `BABYBEAR_BINARY_128_BITS_PARAMETERS`, seed 42, NAND(1,1).
Each entry is the median of ten measured proofs after one warm-up. FHE key
material and ciphertext fixtures are seeded; PCS setup retains artifact
randomness. Both versions verify every generated complete proof.

| Session / threads | Before, complete | After, complete | Reduction |
|---|---:|---:|---:|
| First comparison / 1 | 32.030 s | 28.901 s | 9.8% |
| First comparison / 16 | 5.503 s | 4.780 s | 13.1% |
| Independent confirmation / 16 | 5.477 s | 4.808 s | 12.2% |

These are warm-key-commitment measurements. Complete time includes trace
generation, finalization, per-input preparation, all four PBS proof stages and
serialization. Key generation and verification are separate. The confirmation
uses the saved executable copies and validates their hashes before execution.

In the first 16-thread comparison, proof generation alone changed from 5.153 s
to 4.423 s. Serialized complete proofs remain approximately 319 MB: median
318,941,150 bytes before and 318,942,621 bytes after. The independent confirmation
also stays within 0.01% of the original size. The proof format is unchanged.
The serialized tuple includes parameter data; its size is distinct from the
artifact's logical PCS/PIOP size methods and from papers that omit public
preprocessing parameters.

Whole-process peak RSS in the first comparison was 5,154→5,411 MiB at one thread
and 5,752→5,453 MiB at 16 threads. In-place folding retains table capacity, so
reduced allocation traffic does not guarantee a lower peak in every setting.

The allocation-only exploration showed approximately 31.5–31.7 s in two measured
single-thread samples. That run was intentionally stopped; it is not a ten-run
result. The final measurements additionally include the identity-affine fast path.

## Interpretation and artifacts

The 16-thread engineering changes clear the 10% latency and 2x proof-size
thresholds in two sessions. The single-thread result is below the 10% latency
threshold. These results preserve the original proof backend's security
properties; they do **not** establish the planned whole-proof 128-bit security
target, and no new cryptographic backend is promoted.

The baseline exposes a large PCS cost: about 14.10 s out of 31.68 s proving on
one thread, versus about 0.87 s out of 5.15 s at 16 threads. Blind rotation
accounts for nearly all remaining prover time. In the optimized single-thread
profile, tracked commitment work is about 13.66 s, openings 0.45 s, and selected
extension conversions 0.20 s. These measurements support further commitment
and sumcheck work; they do not yet justify a wholesale integer-arithmetization
replacement or establish the benefit of a convolution-check replacement.

Raw samples, executable copies, source archives, lockfiles, hashes, and
provenance are retained locally under:

* `target/performance/baseline/`
* `target/performance/optimized/`
* `target/performance/confirmation/`
* `target/performance/allocation-only/` (intentionally stopped exploration)

Generated artifacts are ignored by Git. The source archives preserve the exact
experiment versions. The later Goldilocks benchmark correction selects its
artifact's 64-bit code specification; it leaves the reported BabyBear workload's
32-bit specification unchanged.

## Validation

* 49 Rust tests passed across PCS, PIOP, sumcheck, and SNARK libraries/integration
  tests, including independent scalar-message and PCS-matrix reference checks.
* Three Python tests passed for exact algebraic budgeting and measurement
  aggregation.
* Packed tests cover false claims, transcript changes, malformed proof shapes,
  changed commitments/parameters, noncommuting matrix order, serialization, and
  padding/partial lanes for 728-row workloads and sizes corresponding to batches
  of four and sixteen.
* The native-PBS Hadamard component smoke proof verifies. It uses an explicitly
  insecure small FHE fixture and does not certify complete PBS execution.
* The complete Goldilocks release proof verifies with its original 64-bit code
  specification. This is a smoke test, not a comparative Goldilocks benchmark.

## NTT linkage component smoke

`packed_pbs_hadamard --full --with-ntt` now verifies coefficient/NTT consistency
against the exact 17 roots used by the native Hadamard relation. The seed-42,
16-thread release smoke adds 126,369,724 bytes for coefficient commitments and
NTT proofs, for 188,905,128 component bytes including Hadamard. The NTT commit,
prove and verify portion takes 2.451 s; process wall time is 4.45 s and peak RSS
1,405,340 KiB. This is one component run with the original FHE dimensions; it
still excludes several PBS relations and has no complete proof-security claim.
See `packed-ntt.md` and `target/performance/packed-ntt/` for details. All 69 tests
in the algebra/PCS/SNARK run and four Python tool tests pass.

## Native digit range component

`packed_pbs_hadamard --full --with-lookup` verifies range lookups for all eight
native digit coefficient factors using the same roots as the NTT links. It
still lacks digit reconstruction, accumulator/key/endpoint binding and the
remaining PBS stages. Sixteen rational repetitions are separately budgeted;
the lookup-only interactive model uses the conditional challenge domain and
counts shared-opening responses. At Q=544 it totals approximately 5.2865e-41.
This is not a complete proof-security argument.

At 16 threads and original FHE dimensions, the initial Q=544 run takes 66.031 s
for lookup preparation, commits, proving, verification and serialization, adding
856,907,878 bytes. Resolving table membership once and reusing the 256 distinct
inverses per challenge reduces that portion to 46.599 s with the same byte count.
Hadamard and NTT components are additional. The automatic single-opening layout
changes from left_vars=4 at Q=512 to left_vars=3 at Q=544; shared lookup openings
need their own workload-aware layout selection. Both latency and proof size
require substantial further work before promotion. Comparison binaries/logs and
budget records are under `target/performance/packed-lookup/`.

## Canonical reconstruction component smoke

The canonical decomposition component now verifies both native external-product
input halves against the same digit roots used by NTT/Hadamard. Borrow-transition
tuple lookups establish integer canonicity below p, including rejection of x+p
representations. Original BabyBear FHE parameters and seed 42, 16 threads:
1,162,351,774 additional component bytes, 66.693 s for preparation, commits,
proving, verification and serialization. Combined Hadamard/NTT/decomposition
bytes are 1,347,164,944; process wall time is 73.39 s, peak RSS 5,806,732 KiB.
This does not meet the performance gate and still excludes accumulator/key/public
endpoint relations. See `packed-decomposition.md` for the component-only
interactive budget and `target/performance/packed-decomposition/` for evidence.

All 112 Rust tests in the five-crate validation and six Python tool tests pass.
The original complete Goldilocks PBS release smoke also passes after correction
of a lazy-representation arithmetic bug exposed by tuple interpolation; its
security label remains artifact-unbudgeted, and its timing is not a comparative
packed-backend result.

## Lookup challenge lane batching

The original-size canonical decomposition smoke now uses two groups of eight
independent tuple-hash/reciprocal pairs. It authenticates scalar broadcasts with
matrix-query pullbacks to original roots; no broadcast source is committed.
At seed 42/16 threads, it adds 376,277,702 bytes (67.6% below independent
repetitions) and takes 53.253 s including preparation, proving, verification and
serialization (20.1% below the prior 66.693 s smoke). Combined component bytes
are 561,090,872, process wall time 59.45 s, peak RSS 4,780,400 KiB.

The source and helper domains differ: 8192 versus 16384 encoded blocks. The
separate-domain conservative interactive component budget totals 3.2428e-40;
whole-PBS/Fiat-Shamir analysis is still pending. The broad run passes 116 Rust
tests, plus the new focused mask/pole regression; seven Python tests pass. See
`lookup-batching-design.md` and `target/performance/lane-batching/`. These are
component smokes, not complete-PBS promotion measurements.

## Constant-factor packed kernels

The lane lookup profile identifies ZeroCheck as the largest cost (31.519 s of
52.869 s for canonical decomposition). Repeated-cell factor interpolations are
now cached per round, constant lane vectors fold once, and degree-one rounds
skip unused extrapolation work. Independent Lagrange and ordered-matrix
references pass over BabyBear and Goldilocks; the full regression run passes
120 Rust tests and seven Python tool tests.

Two original-size, seed-42, 16-thread component pairs verify: 52.869 -> 46.069 s
(12.9%) and 53.205 -> 45.226 s (15.0%). Canonical-decomposition proof bytes remain
376,277,702 in every run. Complete-PBS/Fiat-Shamir and promotion requirements are
still open. See `lookup-profiling.md` and
`target/performance/constant-factors/comparison.json` for the phase breakdown and
evidence; these results concern a component, not the complete PBS verifier.

## Accumulator arithmetic and continuity linkage

The original-size native example now verifies accumulator additions, both
expected endpoints, actual-round continuity and links to the same duplicated
input roots consumed by canonical decomposition. It reuses the Hadamard
sum-product coefficient root. At N=1024/L=728, 16 threads and seed 42, this adds
25,190,926 bytes and takes 0.825 s including preparation/commits/proving/verification
and serialization in one smoke run. Its 22 query claims share 14 responses/tests.
The interactive component budget totals 1.6742e-42, excluding whole-PBS and
Fiat-Shamir analysis. Monomial multiplication, public initialization, keys,
modulus/key switching and extraction still require completion. See
`packed-accumulator.md` and `target/performance/accumulator-linkage/`.

## Public-input monomial linkage

The original-size native BabyBear example now also checks public monomial
multiplication against the accumulator coefficient roots and derives its initial
NAND accumulator from x+y. The monomial proof adds 21,747,637 bytes and 0.698 s
for preparation, proving, verification and serialization in one 16-thread release
smoke. Implemented components total 608,029,435 bytes; process wall time is
51.72 s and peak RSS is 4,804,160 KiB. This remains a partial PBS implementation;
key binding, final output relations, complete security and performance promotion
remain open. The shared native modulus switch now uses exact integer rounding,
fixing a Goldilocks floating-point boundary case. See `packed-monomial.md` and
`target/performance/public-monomial/` for tests and provenance.

## Final key-switching/output linkage

The original-size native BabyBear example now verifies canonical negative-a
key-switching digits, products against trusted public switching-key roots and
signed/truncated extraction against the actual output LWE ciphertext. The final
stage adds 5,824,846 bytes and 0.226 s for preparation, setup, proving,
verification and serialization in one 16-thread release smoke. All implemented
components total 613,854,281 bytes; wall time is 52.97 s and peak RSS is
4,796,244 KiB. These measurements are not complete-PBS promotion results: the
standalone complete proof/verifier API, whole-proof security and matched
baseline validation remain open. See `packed-key-switch.md` and the preserved
artifacts under `target/performance/key-switch-linkage/`.

## Complete packed NAND API smoke

`packed_pbs --full` now generates and independently verifies one serialized
complete binary NAND relation, using the original BabyBear FHE parameters and
original output key/dimension. Trusted public key states are reused and only the
nine private digit/sum sources have coefficient-to-NTT proofs. The proof is
556,173,638 bytes, warm complete time is 48.976 s, verification is 2.751 s, and
peak RSS is 5,640,492 KiB in one 16-thread release smoke. Warm time includes trace,
private preparation, proving and serialization and excludes 0.624 s public setup.
These results do not meet the latency promotion target. Canonical decomposition
consumes 44.184 s out of 48.561 s proving and is the primary optimization target.
The optional convolution experiment is deferred on this measured profile.

Small native test suites verify fresh independent complete proofs in groups
1/4/16 over both fields. Whole-proof security, matched baseline parameters,
stronger complete-protocol adversarial review, remaining backend experiments and
promotion remain open. See `performance.md` and the complete implementation
ledger. Artifacts are under `target/performance/complete-packed-pbs/`.

## Complete packed terminal reuse

Retaining the terminals already computed by packed folding removes repeated
canonical table evaluations in lookup and product proofs. Every opening and
verifier equation remains unchanged. Two alternating-order, 16-thread complete
BabyBear pairs measure 48.814→41.231 s (15.5%) and 49.051→41.169 s (16.1%).
Serialized bytes remain 556,173,638 in all four runs. Decomposition proving
changes from roughly 44.07 s to 36.57 s. Peak RSS falls from approximately
5,638,000 KiB to 4,155,000 KiB in both pairs. These are engineering smokes against
the previous experimental complete backend, not security-matched promotion.
The old artifact baseline, whole-proof security and remaining backend work
still need completion. All 58 selected Rust tests and 16 Python tests pass;
artifacts and checked manifests are under `target/performance/terminal-reuse/`.

## Version-2 direct transcript smoke

Complete packed proofs now use direct canonical rejection sampling from Merlin
bytes, with explicit wire/transcript version 2. The legacy helper path remains
available and passes byte-compatibility reference tests. Both native field suites
pass, including independent ciphertext groups 1/4/16 and changed-version rejection.

One original-size BabyBear v2 release smoke verifies a 555,651,057-byte serialized
proof with 41.473 s warm complete time and 2.928 s verification. Process wall time
is 45.40 s and peak RSS is 4,155,308 KiB. These are functional v2 measurements;
protocol versions are not compared as one engineering configuration. The abstract
interactive inventory is unchanged, but the full Fiat-Shamir/hash/MW security
analysis and security-matched promotion are still incomplete. See
`target/performance/direct-transcript/` and `performance.md`.

## Ordinary PipFRI scalar reference smoke

The non-hiding reference now authenticates ordinary scalar evaluation claims in
both coefficient and Boolean-evaluation bases. It combines shared fragment-pair
Merkle leaves, random batch aggregation, public-point folds and rolling batch
FRI. This variant uses an extra explicit combined-oracle tree and independent
consistency/proximity query batches. It is not selected by the native PBS path.

All 15 PCS library/integration tests pass, including native NTT/Horner/tensor
references, serialization/tampering, and fresh malicious certificates with valid
low-degree proofs and genuine Merkle openings. Both prime fields are covered.

The following three-run release medians use 16 Rayon threads, blowup 2 and 64
queries in each query batch. The point/value check uses the repository's native
dense multilinear evaluator; verification consumes a deserialized proof. The
workload is a synthetic Boolean table, not a complete PBS or native-trace proof.

| Field | Entries | Fragment length | Commit (s) | Open (s) | Verify (s) | Proof bytes |
|---|---:|---:|---:|---:|---:|---:|
| babybear | 2^18 | 2^14 | 0.0276 | 0.0335 | 0.0026 | 771,514 |
| babybear | 2^21 | 2^16 | 0.1485 | 0.0898 | 0.0031 | 988,938 |
| goldilocks | 2^18 | 2^14 | 0.0253 | 0.0325 | 0.0031 | 800,766 |
| goldilocks | 2^21 | 2^16 | 0.1688 | 0.0979 | 0.0036 | 1,029,518 |

These are experimental, unbudgeted component smokes. Base-field batching/folding
challenges do not establish 128-bit security; masking, composed security bounds,
native integration and security-matched comparison remain open. No complete PBS
speedup or promotion follows from these figures. Saved executable, source and
lock hashes, raw records, test/build logs and process RSS measurements are under
`target/performance/ordinary-pipfri/`.

## Direct extension-field ordinary PipFRI smoke

`Transcript::new_direct_extension<Base>` now samples every extension coefficient
by canonical prime-field rejection from Merlin bytes. A separate protocol domain
binds characteristic, degree and canonical basis multiplication products. An
independent binomial/byte-stream reference verifies the BabyBear^4 and Goldilocks^2
modes; existing legacy and direct-prime references remain unchanged. Coefficient
sampling order is explicit, independent of the extension constructor's callback
order. The ordinary PCS passes dense/tensor evaluation and fresh false-claim
checks with non-base coefficients and points.

The final code passes 27 helper/PCS library/integration tests and all four
complete packed PBS tests, including the native groups 1/4/16 and genuine-child
forgery cases. The existing complete packed protocol still uses direct prime-field
v2 sampling. Its protocol and native parameters are unchanged.

Twenty-eight release smoke runs verify after deserialization: three runs for
each field/layout below, plus one four-entry small-domain case per field. The
latter checks construction below the native NTT library's minimum plan size.
The following medians use 16 threads, blowup 2 and 64 queries in each query batch.
All points are uniform in the declared scalar field; extension data includes
all basis coordinates. These are synthetic scalar tables, not native PBS proofs.
The older base-field smoke used integer points and retains its original records.

| Scalar field | Entries | Fragment length | Commit (s) | Open (s) | Verify (s) | Proof bytes |
|---|---:|---:|---:|---:|---:|---:|
| babybear | 2^18 | 2^14 | 0.0279 | 0.0279 | 0.0045 | 771,514 |
| babybear | 2^21 | 2^16 | 0.1485 | 0.0900 | 0.0031 | 988,936 |
| babybear-ext4 | 2^18 | 2^14 | 0.1710 | 0.0701 | 0.0039 | 888,516 |
| babybear-ext4 | 2^21 | 2^16 | 1.4656 | 0.3640 | 0.0049 | 1,151,254 |
| goldilocks | 2^18 | 2^14 | 0.0279 | 0.0368 | 0.0037 | 800,766 |
| goldilocks | 2^21 | 2^16 | 0.1653 | 0.0976 | 0.0036 | 1,029,518 |
| goldilocks-ext2 | 2^18 | 2^14 | 0.0579 | 0.0364 | 0.0033 | 873,896 |
| goldilocks-ext2 | 2^21 | 2^16 | 0.4335 | 0.1335 | 0.0040 | 1,130,968 |

These remain experimental unbudgeted parameters. Uniform extension sampling is
not a complete 128-bit argument, and the existing extension cardinalities must
be accounted for together with batching, degrees, proximity and composition.
Masking, native integration, packed compatibility and security-matched comparison
remain open. Commitment cost dominates the BabyBear^4 reference at 2^21 entries;
coefficient-wise base-field encoding is a candidate to measure against this saved
generic extension-arithmetic executable. Saved binary/source/lock hashes, raw
records, process RSS and final-state test/build logs are under
`target/performance/ordinary-pipfri-extension/`.

## Ordinary PipFRI scalar adapter and original-size native PBS

The opt-in scalar PCS adapter now supports base/extension tables, logical
zero-variable constants, single openings and batches through the existing trait.
It rejects uninitialized trusted parameters, mismatched dimensions, truncated
batches and reordered claims. Base tables are currently embedded and committed
in the extension field. Existing scalar LogUp SNARKs verify over BabyBear and
Goldilocks with direct extension-field transcripts. All 21 PCS library/integration
tests and the two LogUp integration tests pass on the final code.

Two new executables exercise the original native FHE parameters (ring dimension
1024, LWE dimension 728), native key/output semantics, and all four existing
scalar proof wrappers. Six original-size proofs verify: an initial proof and a
separate two-proof process per field. Every proof checks native NAND decryption,
all four stage verifiers, and terminal transcript agreement. Public statement,
full FHE configuration and trusted key-root hashes, together with serialized
proof byte counts, agree across processes and key reuse for each field.

The following are individual functional smokes at 16 threads, max fragment
variables 14, blowup 2 and 64 independent queries in each query batch. First-proof
time includes new key commitment generation; reused time comes from the second
proof in a process. They are not ten-run medians or security-matched comparisons.

| Field | First proof (s) | Initial key commitment (s) | Reused-key proof (s) | Reused PCS commit (s) | Reused PCS open (s) | Proof bytes |
|---|---:|---:|---:|---:|---:|---:|
| babybear | 42.655 | 9.589 | 32.412 | 25.255 | 3.790 | 13,869,869 |
| goldilocks | 25.789 | 5.833 | 18.543 | 14.140 | 1.619 | 18,584,284 |

These runs use in-memory verification through the existing scalar wrappers.
They do not establish a standalone fully bound complete-PBS verification API,
hiding, 128-bit proof security, or the promotion gates. The performance target
is not met; extension-field commitment work dominates this reference. The
existing default and complete packed backends remain separate. Whole-process
RSS includes both initial and reused proofs, setup, serialization and verification;
see `summary.json` for the observed peaks. Exact source/binary/lock hashes,
commands, fixture hashes, raw stage logs and verification results are preserved
under `target/performance/ordinary-pipfri-native/`.

## Ordinary PipFRI coordinate encoding

The scalar adapter now evaluates extension coefficients coordinate-wise over the
base field and skips FFTs of identically zero coordinates. It selects this path
only when the domain root is in the base field. Generic and optimized encoders
produce identical parameter bytes, commitment roots, complete scalar proof bytes
and final transcript states in independent zero/base/sparse/dense extension tests.
Both extension-only root rejection tests and existing Horner/coefficient checks
pass. All 24 PCS tests, two existing LogUp SNARK tests and three comparison-tool
validation tests pass.

Two alternating execution-order sessions compare saved original-size native
binaries with 16 threads and unchanged experimental geometry. Each process
verifies an initial proof and one reused-key proof; all 16 proofs in the paired
sessions verify through the four existing scalar wrappers with final transcript
agreement. Public FHE configuration, ciphertext statement, trusted BSK root and
serialized proof/PCS/PIOP sizes match across both binaries and key reuse.

| Session | Field | Reference reused (s) | Coordinate reused (s) | Reduction | Proof bytes |
|---|---|---:|---:|---:|---:|
| 1 | babybear | 32.208 | 10.635 | 67.0% | 13,869,869 |
| 1 | goldilocks | 18.527 | 10.685 | 42.3% | 18,584,284 |
| 2 | babybear | 32.478 | 10.828 | 66.7% | 13,869,869 |
| 2 | goldilocks | 18.551 | 10.852 | 41.5% | 18,584,284 |

In the first pair, BabyBear's tracked PCS commit cost falls to 3.846 s, while
opening costs 3.524 s. Goldilocks PCS commit is 6.180 s and opening is 1.672 s.
The complete proof sizes remain 13,869,869 bytes and 18,584,284 bytes respectively.
The native comparison tool rejects executable-hash changes, missing/unverified
records, inconsistent key reuse, differing actual public fixture/key hashes,
protocol geometry changes and differing serialized sizes.

These are paired engineering smokes with one reused observation per process,
not ten-run medians or security-matched comparisons. The underlying reference
remains non-hiding and unbudgeted, with in-memory legacy-wrapper verification.
The whole-plan performance/security/promotion gates remain unmet. Current source,
lock and executable hashes, raw phase/resource logs and checked comparison
records are preserved under `target/performance/ordinary-pipfri-coordinate/`;
the original native reference snapshots remain intact.

## Larger and quintic extension-field prerequisites

The algebra crate now exports BabyBear degree 8, Goldilocks degree 4 and degree 5
extensions of both primes. Arithmetic parameters no longer require an unrelated
primitive multiplicative generator; the existing generator interfaces and default
field aliases remain intact. Extension exponentiation through u128::MAX is now
implemented. Independently coded integer polynomial Rabin/gcd checks prove the
defining polynomials irreducible over the checked prime candidates; integer
polynomial multiplication, modular powers, Frobenius and extended-Euclidean
inverses validate old and new field arithmetic. Reducible control polynomials
are rejected. See `performance.md` for constants and the criterion reference.

The malformed-input tests reproduced an inherited BabyBear decoder defect: raw
internal representatives >=p, including extension coefficients, were accepted.
The checked newtype decoder rejects these inputs while preserving valid existing
Montgomery wire bytes. The pre-fix failing test log is retained as evidence.

On final code, 100 algebra/helper/PCS tests, six existing scalar LogUp integration
tests and all four complete packed PBS tests pass. These include old/new direct
sampling references, independent field arithmetic, malformed proof/batch checks,
constant tables and generic/coordinate encoder proof-byte agreement. Workspace
checking and algebra checking without default features also pass.

Forty-eight release scalar smokes verify deserialized proofs against the native
dense multilinear evaluator: three runs at each of 2^18 and 2^21 entries over
two prime fields, the two original extensions, and the four new extensions.
Extension modes explicitly select and record coordinate-wise base-field encoding.
The following three-run medians describe the new fields at 2^21 entries, fragment
size 2^16, blowup 2, 64 queries in each batch and 16 Rayon threads.

| Scalar field | Commit (s) | Open (s) | Verify (s) | Proof bytes |
|---|---:|---:|---:|---:|
| babybear-ext5 | 0.6104 | 0.2979 | 0.0060 | 1,201,983 |
| babybear-ext8 | 0.9146 | 0.8493 | 0.0128 | 1,354,152 |
| goldilocks-ext4 | 0.5535 | 0.2772 | 0.0057 | 1,313,578 |
| goldilocks-ext5 | 0.6902 | 0.4058 | 0.0089 | 1,404,883 |

Field cardinality is not a composed proof-security level. These scalar smokes
remain non-hiding and unbudgeted; defaults are not promoted or replaced. Proximity
query counts, degrees/batching, composition and Fiat-Shamir still require the
whole-proof analysis. The degree-5 fields are arithmetic prerequisites for further
lookup experiments, not a new lookup protocol. Parameter/cardinality/primality
audit data, source/binary/lock hashes, all checks and raw smoke/resource records
are preserved under `target/performance/extension-fields/`.

## Complete PBS with extension-field canonical comparisons

The opt-in `packed_pbs::prove_extension/verify_extension` path now covers every
native binary NAND stage, including final key switching. Its typed proof carries
checked version 3 and a separate parent domain. It authenticates GF lookup
terminals through the original base-field matrix-weighted roots. The default
version-2 API continues to use lane comparisons.

Two alternating-order sessions use the saved release binaries, 16 Rayon threads,
seed 42, original BabyBear/Goldilocks FHE parameters (N=1024, LWE dimension 728),
the original output key and NAND(1,1). Each backend process generates an initial
proof and one proof reusing preprocessing. Complete time includes native
execution, preparation, every proof stage and serialization. Public-key
preprocessing and verification are outside that timer. All sixteen full-size
proofs verify after deserialization. Eight additional toy proofs verify through
the same runner. Each pair has matching ciphertext, FHE-configuration, native
public-key and all four PCS-layout digests/metadata. Within each protocol, exact
proof digests and sizes also match across initial/reused proofs and sessions.

| Field / session | Lane v2 reused | Extension v3 reused | Reduction |
|---|---:|---:|---:|
| BabyBear / first | 41.921 s | 18.483 s | 55.9% |
| BabyBear / reversed | 41.298 s | 18.384 s | 55.5% |
| Goldilocks / first | 104.714 s | 48.252 s | 53.9% |
| Goldilocks / reversed | 104.354 s | 48.314 s | 53.7% |

BabyBear proofs shrink from 555,651,057 to 388,875,431 bytes (30.0%); Goldilocks
proofs shrink from 1,760,150,519 to 1,182,299,399 bytes (32.8%). Peak process RSS
is 4.06→2.78 GiB for BabyBear and 11.47→9.06 GiB for Goldilocks. These figures
include two proofs and verification per process. Reused decomposition medians
fall from 37.16→14.10 s and 94.89→39.00 s, respectively; decomposition remains
the main cost. Native private NTT links stay around 0.75 / 1.76 s, so the
optional convolution experiment is still below the dominant lookup work.

This compares **different experimental protocols**: sixteen independent
base-field pairs, batched into lanes, versus one full quintic-extension pair.
The actual-shape interactive inventory is about 131.13 / 130.10 model bits for
BabyBear lane/extension and 134.24 / 134.57 for Goldilocks. These are conservative
interactive contributions under the existing experimental MW adaptation, not
whole-proof security certificates. Child/parent transcript composition,
Fiat-Shamir, hash binding, hiding and independent MW review remain open. The
original artifact benchmark is also unbudgeted; these results do not establish
a security-matched improvement over that backend or authorize promotion. One
reused observation per process is a paired smoke, not a ten-run distribution.

The final regression run passes 38 Rust tests (30 component/library tests and
eight complete-PBS tests) and 31 Python tool tests; workspace checking passes.
Complete tests cover both versions/fields, groups of 1/4/16 independent native
proofs on small fixtures, every NAND plaintext case, wrong roots/keys/output
claims, and fresh complete false-statement certificates with genuine child
proofs. A later test-only audit adds the global key/endpoint forgery variants;
full-size aggregated batches and independent security review remain requirements
in the implementation ledger.

Artifacts are under `target/performance/packed-extension-pbs/`: saved executables,
source/lock snapshots, all validation logs, toy and native sessions, per-process
resources, phase data, exact interactive fractions and a SHA-256 manifest.
Source snapshot SHA-256:
`4482cdd1b01b6b5fc07f41ab8723fe5c9db30ad31bd3d9d55c76d527f60c1e2f`.
Lock SHA-256:
`293790853366e0bc0562752d17999bab335368dd6e0c33823f1afaee8c214718`.
The snapshot precedes this results section; implementation sources match the
saved binaries. Reproduce from saved artifacts with:

```sh
python3 tools/compare_extension_pbs.py target/performance/packed-extension-pbs --output target/performance/packed-extension-pbs-repeat --full --sessions 2 --iterations 2 --threads 16
```

## Structured MW-Basefold comparison on native Hadamard traces

The Appendix D.1 streaming reference is now executable through
`pcs::mw_basefold` and `snarks::packed_basefold`. It fixes each derived root and
answers its fresh queries between successive packed-sumcheck challenges. All
encoding/folding uses base-field coordinates, with authenticated terminal
codeword decoding. The existing after-query MW-Brakedown API and complete-PBS
backend selection are unchanged.

Two alternating-order sessions use saved binaries, 16 threads, the original
BabyBear/Goldilocks FHE parameters, N=1024/LWE=728, seed 42 and the actual native
external-product Hadamard factors. Both backends use width 8, rate 1/2 and 544
independent samples. Exact factor/ciphertext and FHE-configuration digests match
across backend modes and sessions. Each process commits once and verifies an
initial and a reused component proof after serialization. All sixteen full-size
component proofs and eight toy proofs verify, with stable per-protocol proof
digests across process repeats.

| Field / session | Brakedown reused prover | Basefold reused prover | Brakedown / Basefold bytes |
|---|---:|---:|---:|
| BabyBear / first | 0.590 s | 1.303 s | 61,134,794 / 133,230,151 |
| BabyBear / reversed | 0.514 s | 1.192 s | 61,134,794 / 133,230,151 |
| Goldilocks / first | 1.251 s | 2.215 s | 203,623,902 / 330,927,189 |
| Goldilocks / reversed | 1.269 s | 2.282 s | 203,623,902 / 330,927,189 |

These prove only the native Hadamard component with existing commitments.
Commitment construction is separate: median Brakedown/Basefold commit time is
1.273/0.858 s for BabyBear and 2.861/5.459 s for Goldilocks. Reused verification
medians are 0.265/0.608 s and 0.641/1.393 s, respectively. Basefold's oracle-fold
callbacks account for about 0.962/1.600 s of its 1.247/2.248 s reused prover
medians. This reference loses on reused proof time and serialized size at these
settings: 2.18x bytes for BabyBear and 1.63x for Goldilocks. Keep Brakedown on the
current packed path.

The common sample count is an explicit experimental comparison setting; it is
not a security-matched choice. This result is not complete-PBS latency, a general
performance claim about Basefold, or a cryptographic promotion decision. The
reference is non-hiding; concrete proximity/composition/Fiat-Shamir analysis and
independent review remain open. GF-multiplication matrix queries are outside the
structured challenge guarantee used by this driver.

Validation passes 64 Rust tests: 19 sumcheck tests (including independent legacy
framing and interleaving/error-callback checks), 16 PCS library tests, 21 SNARK
library tests and eight complete-PBS regressions. The latter retain versions
2/3, both fields, native plaintext/batch cases and fresh key/endpoint/view
forgeries. The Basefold tests include independent Horner evaluation, direct
fold/re-encoding with noncommuting matrices, genuine-path high-degree attacks,
and fresh false-source certificates with genuine local algebra and streamed
openings. All 34 Python tool tests and workspace checking pass.

Artifacts are in `target/performance/mw-basefold-comparison/`: source/lock
snapshots, saved executables, validation logs, exact native/toy sessions,
per-process resources and hashes. Source snapshot SHA-256:
`e76ddaa3ba48c6ebfc744d147024862d48ca4045a612ed9c83aaf20ea7515d3b`.
Lock SHA-256:
`293790853366e0bc0562752d17999bab335368dd6e0c33823f1afaee8c214718`.
The source snapshot precedes this results section. Reproduce the paired smoke:

```sh
python3 tools/compare_mw_basefold.py target/performance/mw-basefold-comparison --output target/performance/mw-basefold-repeat --full --sessions 2 --iterations 2 --threads 16
```

## Masked scalar PipFRI reference smoke

`target/performance/masked-pipfri-reference/` records a synthetic scalar table
with 2^21 entries, fragments of 2^14 entries, rate 1/2, 64 queries and four
openings from one privately masked commitment. Direct quintic transcripts and
the coordinate-wise encoder are used, with 16 Rayon threads. Each proof is
serialized, decoded and verified against the retained expected root. All eight
native and four toy openings verify; both session budgets are exhausted exactly.

| Field | Commit once (s) | Median opening (s) | Median verify (s) | Proof bytes | Max RSS (MiB) |
|---|---:|---:|---:|---:|---:|
| BabyBear degree 5 | 1.103 | 0.449 | 0.00524 | 1,049,071–1,049,077 | 403 |
| Goldilocks degree 5 | 1.376 | 0.638 | 0.00658 | 1,453,601 | 810 |

This is a single scalar smoke per field, not a full PBS benchmark or a
security-matched comparison. Fresh private masks make proof hashes and some
variable-length field encodings vary between executions. Commitment cost is
reported once and must not be charged four times when interpreting the rows.

The cumulative two-opening linear-view audit reconstructs all 68 revealed field
elements independently. Both bases and both prime fields give random rank 36,
permitted-evaluation rank 2 and joint rank 38. An individual-fragment disclosure
negative control increases the rank to 39. Seven masked unit tests plus the
existing PCS/adapter/encoding and LogUp regressions give 42 passing tests. This
does not establish adaptive zero knowledge, hash hiding, Fiat–Shamir security or
complete-PBS composition. See `masked-pipfri.md` for the remaining gates.

### Masked scalar adapter integration

The opt-in `multilinear::masked_pipfri` adapter now implements the existing PCS
trait with one lifetime-bounded private session per root. The adapter supports
base/quintic tables, constants, multi-fragment tables and 1/4/16-point batches.
Checks confirm that a malformed/oversized batch consumes no allowance and does
not mutate its transcript, and that simultaneous batches cannot both spend the
same capacity. The remaining single allowance is usable after the rejected race,
and exhausted state cannot produce another opening. Trait verification explicitly
permits independent re-verification, while enforcing bounded proof indices and
consecutive indices within a batch. The existing LogUp relation selects this
backend without interface changes.

All 47 regression tests pass: 23 PCS library tests, six ordinary scalar adapters,
seven ordinary encoder tests, three masked adapter tests, six ordinary LogUp
tests and two masked LogUp tests. The locked workspace check also passes. Logs
and exact source/lock provenance are saved under
`target/performance/masked-pipfri-adapter/`. No new timing claim is made for the
adapter. Full masked-PBS binding and the hiding/soundness/Fiat–Shamir composition
remain open.

## Native masked PipFRI four-stage wrapper baseline

`target/performance/masked-pipfri-native/` records the original native FHE
parameter objects with the quintic scalar adapter, fragment size 2^14, blowup 2,
64 queries, four lifetime openings per commitment and 16 Rayon threads. Each
field runs two NAND(1,1) proofs with one cached masked blind-rotation key. All
four in-memory four-stage proofs verify and decrypt correctly. Within each
field, actual public fixture, native BSK, FHE parameter, statement and masked key
root hashes remain equal across iterations. The key opening indices are 0/1 and
the remaining budget moves 4→3→2. Two additional CLI checks reject five reused
iterations before generating keys or proofs.

| Field | First complete run (s) | Reused complete run (s) | Reused proving (s) | Proof bytes | Peak process RSS (GiB) |
|---|---:|---:|---:|---:|---:|
| BabyBear degree 5 | 51.919 | 42.064 | 41.961 | 19,645,950–19,645,990 | 11.92 |
| Goldilocks degree 5 | 131.988 | 106.417 | 105.945 | 51,401,145 | 45.23 |

The first run includes masked key commitment (9.026/22.318 s). Reused proving
spends 23.112/54.397 s in PCS commitments and 15.043/40.773 s in openings for
BabyBear/Goldilocks. The key oracles have 24/25 variables, larger than the earlier
2^21-entry scalar smoke. The process uses roughly one CPU core despite the
16-thread pool; fragment encoding and the virtual batch linear combinations are
serial in this source snapshot. These are concrete targets for optimization.

This is a single first/reused pair per field, with no matched-baseline or
whole-proof security claim. The verification scope is explicitly
`legacy-four-stage-wrapper-in-memory`: bytes are measured by serializing the
proof tuple, then the retained in-memory proofs are verified. Witness-derived
evaluation fields skipped by serialization remain necessary for these legacy
wrappers. Trusted global/key/endpoint binding and a decoded standalone complete
verifier still need integration. These results neither promote the backend nor
satisfy the complete-PBS performance/bytes/security gates. The earlier ordinary
non-hiding timings and different field degrees are not a security-matched
comparison. Exact binary, source, lock, console, budget-rejection and timing
artifacts are retained separately from earlier snapshots.

## Parallel masked PipFRI kernels

`target/performance/masked-pipfri-parallel/` compares the saved sequential
implementation with ordered parallel fragment encoding/leaf hashing and blocked
linear combinations. Randomness remains sequential, and every coefficient keeps
the original addition order. Both bases, both quintics and both encoders preserve
commitment, codeword, proof and transcript bytes across 1/2/4 workers for fixed
private randomness. The next RNG output also agrees. All 49 PCS/LogUp tests and
the locked workspace check pass.

Two reversed-order scalar sessions use the same 2^21-entry public tables,
2^14-entry fragments, blowup 2, 64 queries, budget four and 16 threads. All 32
serialized openings verify. Ranges below are across two processes, each taking
the median of its four opening times.

| Field | Serial commit (s) | Parallel commit (s) | Serial opening (s) | Parallel opening (s) |
|---|---:|---:|---:|---:|
| BabyBear degree 5 | 1.100–1.105 | 0.298–0.301 | 0.448–0.450 | 0.185–0.216 |
| Goldilocks degree 5 | 1.378–1.379 | 0.370–0.377 | 0.638–0.641 | 0.253–0.254 |

Commit time falls about 73%; median opening time falls 52–60%. The example and
critical field/transcript/FRI sources match the archived sequential scalar
benchmark; only the masked implementation schedule changes.

The native first/reused experiment then verifies two parallel proofs per field,
using exactly the previous example source, parameters, fixture and native BSK
hashes. Masked roots intentionally differ between processes because masks are
fresh, while each process retains its root and budget transition 4→3→2.

| Field | Serial reused (s) | Parallel first (s) | Parallel reused (s) | Reused reduction | Peak RSS (GiB) |
|---|---:|---:|---:|---:|---:|
| BabyBear degree 5 | 42.064 | 17.775 | 15.375 | 63.4% | 11.91 |
| Goldilocks degree 5 | 106.417 | 46.740 | 40.503 | 61.9% | 45.29 |

Reused commitment costs fall 23.112→4.024 s / 54.397→8.768 s. Opening costs fall
15.043→7.223 s / 40.773→19.012 s. Process CPU utilization rises to about
555%/508%; peak memory is essentially unchanged. Native proof sizes remain about
19.65/51.40 MB, with small variable-length field-encoding differences under fresh
masks. Public fixture, FHE parameter, native key, statement, geometry and budget
metadata are checked against the saved baseline.

These are implementation-equivalent experimental configurations, without a
whole-proof security claim. Scalar improvement is confirmed in two reversed
orders; native results are one first/reused process per implementation/field.
Native verification still uses the legacy four-stage in-memory wrappers. This
is not a standalone decoded complete-PBS verifier, security-matched baseline,
full repeated native confirmation or evidence for backend promotion. The
remaining complete-PBS binding and composed security gates stay open.

## Ordered matrix bridge capacity comparison

`target/performance/packed-scalar-comparison/` runs both implementations on the
same synthetic 2^21-scalar tables, independent dense ordered matrices and claimed
responses (18 cell variables, eight lanes). Each process commits once, then opens
1/4/16-query batches. Two sessions reverse backend and field process order. The
bridge uses its quintic masked scalar adapter (fragment size 2^14, budget four);
MW-Brakedown uses its balanced block-RS layout. Both request 64 oracle queries
and blowup two. This is a common experimental count, not a security-matched
configuration.

All 24 large certificates and 12 toy certificates are serialized, decoded and
verified against retained expected roots. Fixture/query hashes agree across
backends and sessions. Bridge roots are fresh between processes and remain
fixed within a process; its three batches use indices 0/1/2 and remaining
budgets 3/2/1. Brakedown's deterministic roots remain identical between sessions.
The prior 81-test runtime sources are byte-identical to the saved bridge
checkpoint, and the current release example/workspace builds pass.

| Field | Matrix queries | Brakedown prove (s) | Bridge prove (s) | Brakedown proof (MB) | Bridge proof (MB) |
|---|---:|---:|---:|---:|---:|
| BabyBear | 1 | 0.007 | 0.927–0.987 | 1.325 | 1.051 |
| BabyBear | 4 | 0.019–0.020 | 1.549–1.600 | 2.308 | 1.051 |
| BabyBear | 16 | 0.062–0.064 | 3.890–3.929 | 6.251 | 1.051 |
| Goldilocks | 1 | 0.010–0.011 | 1.267–1.355 | 2.365 | 1.457 |
| Goldilocks | 4 | 0.025 | 2.052–2.092 | 4.154 | 1.457 |
| Goldilocks | 16 | 0.084–0.085 | 5.148–5.256 | 11.232 | 1.457 |

Brakedown commitment is 0.035–0.036 s / 0.050–0.051 s, versus bridge
0.308 s / 0.386–0.391 s. At 16 queries the bridge uses only 16.8% / 13.0%
of the bytes but is about 62x slower to prove. The full kernel expansion and extra
sumcheck make the current general reduction unsuitable for the latency goal.
Its preflight claim check is included in proving; common expected-response
construction is timed separately for both implementations.

Retain MW-Brakedown and keep the bridge as a conditional research reference.
This experiment does not rule out specialized/direct packed PipFRI designs. It
does not measure actual native FHE traces or complete PBS, resolve the bridge's
non-hiding view, establish a concrete soundness bound, or satisfy promotion gates.
Complete source, lock, binary, commands, hashes, resource logs and validated
summary remain in the separate archive.

## Goldilocks cubic/four-lane complete PBS

Two reversed profile orders at 16 threads use unchanged native ring-1024,
LWE-728 FHE parameters, public fixture and native keys. Each process generates
first/reused proofs and verifies the complete decoded certificate plus native
decryption. All 12 full-size and eight toy controls pass. Archived/current
quintic toy proof bytes match exactly; each profile is byte-deterministic across
reuse and processes. Artifacts: `target/performance/goldilocks-cubic-pbs/`.

| Lookup degree / width | First complete seconds (sessions 0 / 1) | Reused complete seconds | Proof bytes | Peak RSS GiB |
|---|---|---|---|---|
| 5 / 8 | 48.612 / 48.937 | 48.137 / 48.307 | 1,182,299,399 | 9.06 / 9.07 |
| 3 / 8 | 34.900 / 34.864 | 34.495 / 34.273 | 1,100,842,315 | 8.84 / 8.85 |
| 3 / 4 | 32.342 / 32.579 | 31.931 / 31.900 | 614,289,399 | 8.01 / 8.01 |

Degree three alone reduces reused complete time by 28.3–29.1%; four lanes
increase the reduction to 33.7–34.0% and reduce bytes by 48.0%. Median
all-iteration decomposition costs are 38.95 / 25.11 / 22.87 seconds, respectively.
Setup costs are about 1.64 / 1.63 / 2.49 seconds and are reported separately
from complete trace/prove/serialization time. Public verification takes
5.15–5.50 / 5.10–5.29 / 2.27–2.52 seconds, respectively.

`tools/compare_extension_profiles.py` validates profile metadata, actual public
fixture/key hashes, all four layouts and the complete interactive inventory.
The inventory yields 134.57 / 134.57 / 134.55 bits for these profiles. These are
conditional interactive bounds, not a whole-proof Fiat-Shamir certificate or
security-matched baseline comparison. The cubic profile is opt-in; the quintic
eight-lane default is unchanged. Independent field/sampling, scalar PCS,
lookup forgery and complete-PBS batch/binding tests pass (28 Rust tests), along
with 39 Python tests, both release builds and the locked workspace check.

## Full-size fresh-input validation at groups 1/4/16

The shared complete-PBS extension example now has `--validation-batches`.
With unchanged original ring-1024/LWE-728 parameters and one setup per field,
BabyBear quintic/eight-lane and Goldilocks cubic/four-lane each pass 21 fresh
complete proofs. The four- and sixteen-case groups cover every NAND plaintext
pair. Every proof is serialized, decoded and verified using public setup and
the actual public ciphertext statement; each output decrypts to NAND. Both
native parameter/key hashes match earlier complete runs. All 42 native and
42 toy fresh-input proofs pass, plus two byte-identical archived/default cubic
controls. No aggregated or concurrent batch protocol is claimed.

| Profile | Native fresh proofs | Per-proof interactive inventory bits | Sum over 21 proofs, bits |
|---|---:|---:|---:|
| BabyBear, degree 5 / width 8 | 1+4+16 | 130.10 | 125.71 |
| Goldilocks, degree 3 / width 4 | 1+4+16 | 134.55 | 130.16 |

These are conditional interactive inventories. In particular, the BabyBear
21-proof union misses 128 bits despite each individual inventory exceeding it.
`budget-candidate-screen.json` records hypothetical degree-eight/helper-layout
changes that raise that model's joint bound; those settings have not been
implemented or measured here. Whole-proof Fiat-Shamir, independent composition
review, a security-matched baseline and aggregated validation remain open.

`tools/validate_full_batches.py` checks exact schedule, strict types and protocol
metadata, all four layouts, native dimensions, fresh statement/proof hashes,
unchanged setup/key hashes, plaintext truth-table results and public verification.
Optional historical references additionally check actual FHE/key hashes. Six
negative/positive analyzer tests join the full 45-test Python suite. Both release
examples and the locked workspace check pass; conflicting validation/iteration
flags reject before proving. The original repeated-statement path is preserved.

Evidence is saved under `target/performance/full-native-batches/`, including
commands, per-process resources, decoded log inventories, binaries, source and
lock provenance. Goldilocks continued successfully after its tool/Python runner
session disappeared: the still-live native child was not restarted, and its
`time` trailer confirms exit zero with all 21 proofs. Recovery is recorded.
Timings are incidental to correctness validation, not another paired speedup
measurement; a brief Python regression process overlapped the final Goldilocks
validation after recovery.

## BabyBear stronger joint interactive profile

The independently checked X^6-31 extension and `--helper-left-extra 1` now provide
an opt-in stronger profile without changing the ring-1024/LWE-728 FHE parameters
or native keys. Both helper splits move one variable from columns to rows; the
encoder's real minimum domain remains 32 symbols. Independent field arithmetic,
transcript-byte references, scalar PCS, canonical matrix mappings, decomposition,
lookup forgery and complete-PBS tests cover degrees six/eight. No primitive
extension generator or composed security certificate is asserted.

Two reversed degree-five/six/eight process orders at 16 threads each generate
first/reused complete proofs and verify them after serialization and decoding.
All actual public FHE/key/statement hashes match across profiles; each profile's
proof bytes/layouts are stable across reuse and processes. The archived default
quintic native and toy proofs are byte-identical to the updated default.

| Degree / helper shift | First complete seconds, sessions 0 / 1 | Reused complete seconds | Proof bytes | Peak RSS GiB |
|---|---|---|---:|---|
| 5 / 0 (default) | 18.732 / 18.741 | 18.571 / 18.481 | 388,875,431 | 2.772 / 2.776 |
| 6 / 1 | 23.296 / 23.099 | 22.803 / 23.278 | 405,612,783 | 2.835 / 2.840 |
| 8 / 1 | 39.982 / 40.230 | 39.789 / 39.924 | 428,858,023 | 2.953 / 2.952 |

Degree six is 41.7–42.7% faster than degree eight on reused complete proofs.
It costs 4.3% more bytes and about 23–26% more time than the quintic default,
whose 21-proof conditional inventory misses the joint threshold. These compare
experimental profiles, not a reviewed security-matched baseline. Decomposition
medians over all four iterations are 14.25 / 18.62 / 35.55 seconds, respectively.

The runner selected degree six using the lower sum of the two reused complete
times among eligible stronger profiles, then completed 21 native fresh-input
proofs in groups 1/4/16. All NAND input pairs decrypt correctly, every decoded
complete proof verifies, statements/proofs are distinct and setup/keys are
reused. The actual layouts yield 134.90 conditional interactive bits per proof
and 130.51 for their sum over 21 proofs. Summing this new BabyBear inventory with
the previously verified 21 Goldilocks cubic proofs yields 129.32 bits. These
union bounds do not need independence between the proof events, but retain the
model's existing MW, transcript-composition and Fiat-Shamir caveats; they are
not a whole-proof security certificate or an aggregated protocol.

All 77 benchmark proofs pass: 33 native (12 controls plus 21 fresh), 42 toy
fresh-input cases and two default toy controls. Both stronger profiles reject
wrong degree/split metadata, unsupported geometry and a joint inventory above
the 2^-128 threshold. All 46 targeted Rust and 47 Python regressions, three
release builds and the locked workspace check pass. Sources, lockfile, binaries,
commands, child process status and resource reports are saved under
`target/performance/babybear-batch-budget-pbs/`. A build-time source archive is
kept separately from the final archive with this report.

Next, measure a lane-comparison baseline with shifted helper geometry at the
same conditional joint target; its model is saved as `lane-baseline-candidate.json`
and is not measured here. The degree-six multiplication follow-up is now implemented and measured below;
it preserves the archived proof bytes and passes independent arithmetic and
transcript checks. Whole-proof Fiat-Shamir/composition review, direct
packed PipFRI/hiding research and aggregated validation remain open.

## Degree-six Karatsuba kernel: unchanged proofs, lower complete latency

Degree-six multiplication now splits each input into two degree-two polynomials,
uses three Karatsuba products and reduces the five high coefficients once by
X^6=31. Stack arrays avoid allocation. This changes the degree-six multiplication
branch only. An independent integer-polynomial reference plus the old kernel's
serialized outputs cover all 36 basis products, four boundary cases and 512
deterministic random pairs. The full field/inverse/Frobenius/power, transcript,
scalar PCS, canonical mappings, decomposition, lookup forgery and complete-PBS
regressions pass (45 Rust tests), along with 47 Python tests, the release build
and locked workspace check.

The saved old binary and optimized binary run two reversed process orders at
16 threads, with first/reused complete NAND proofs at the original ring-1024,
LWE-728 dimensions. Native parameters, keys, actual statements, trusted layouts,
proof hashes and sizes match. Complete certificates are decoded and verified
through the public verifier, and native outputs decrypt correctly.

| Kernel | First complete seconds, sessions 0 / 1 | Reused complete seconds | Proof bytes | Peak RSS GiB |
|---|---|---|---:|---|
| Previous | 23.026 / 22.966 | 23.052 / 22.894 | 405,612,783 | 2.835 / 2.839 |
| Karatsuba | 18.495 / 18.473 | 18.295 / 18.172 | 405,612,783 | 2.835 / 2.834 |

Complete reused latency drops by 20.64% / 20.63%; median decomposition over the
four iterations drops from 18.57 to 13.93 seconds (about 25%). Setup is reported
separately. This is an implementation comparison of the same experimental
protocol/parameters, not a newly reviewed proof-security claim.

All 54 benchmark proofs pass: eight native repeated controls, four toy repeated
controls, 21 native fresh inputs and 21 toy fresh inputs in 1/4/16 groups. Every
fresh statement/proof hash and proof size matches the corresponding archived
pre-optimization fixture. The trusted layouts and conditional interactive model
are unchanged: 134.90 bits per proof, 130.51 for the 21-proof union. No FHE,
transcript, protocol, field, packing, query or helper-layout parameter changes.
These remain independent proofs, with whole-proof Fiat-Shamir/composition,
security-matched baseline, hiding/direct packed PipFRI and aggregation gates open.

Evidence is under `target/performance/sextic-kernel-pbs/`, including old/new
binaries, before/final source archives with the same pinned lockfile, commands,
child status, resource reports, proof-hash controls and toolchain provenance.
The runner requires a complete latency improvement in both reversed sessions
before continuing to the native 1/4/16 validation. The next comparison is the
shifted-helper lane baseline at the same conditional joint target, as described
in the preceding profile report.

## Lane/extension comparison at a common conditional 21-proof target

Both complete BabyBear profiles now use the same native FHE parameters, actual
public fixture/key hashes and four trusted PCS layouts: width eight, 544 raw
queries and shifted helper splits. Version-two lanes use 16 base-field pairs;
version-three lookups use one degree-six pair. Their complete conditional
interactive inventories are 134.66 / 134.90 bits per proof and 130.26 / 130.51
bits for the 21-proof union. Thus both clear the same numerical 128-bit target.
This does not certify a whole-proof security match: extraction/proximity,
Fiat-Shamir/hash and parent/child composition remain open.

Two reversed process orders at 16 threads give:

| Profile | First complete seconds, sessions 0 / 1 | Reused complete seconds | Serialized proof bytes | Peak RSS GiB |
|---|---|---|---:|---|
| Shifted-helper lanes | 40.068 / 40.527 | 39.073 / 39.517 | 579,831,829 | 4.071 / 4.075 |
| Optimized degree-six extension | 18.436 / 18.374 | 18.302 / 18.159 | 405,612,783 | 2.840 / 2.835 |

Complete reused latency is 53.16% / 54.05% lower and proof bytes are 30.05%
lower. Both engineering gates (at least 10% lower latency twice and at most
2x bytes) pass at the common conditional target. Median decomposition across
all four iterations falls from 35.24 to 13.93 seconds. Setup is separate from
complete trace/prove/serialization latency; these are original ring-1024,
LWE-728 binary NAND proofs, verified from decoded certificates without witness
access. Native decryption is checked separately. No FHE/key changes are used.

All 50 new benchmark proofs pass: eight native controls, 21 toy lane cases and
21 native lane cases in fresh 1/4/16 groups. Their actual statements, keys and
layouts match the archived optimized-extension fresh-input fixtures; per-profile
control proof hashes remain stable across process orders and the extension
control hashes match the earlier kernel benchmark. The binary is copied from
that verified build, and all 326 existing Rust/manifest/lock inputs match its
source archive. New code changes are validators/tests, not production proving.

`compare_joint_target_profiles.py` checks strict mode/transcript/repetition
metadata, common geometry/fixtures, per-profile wire stability and each full
21-proof target before reporting engineering gates. `validate_full_batches.py`
now supports `babybear-lanes-helper1`. All 53 Python tests pass. After native
measurement finished, four focused Rust tests passed: existing block-RS checks
plus the new BabyBear/Goldilocks lifting identity, independent Horner evaluation
and negative controls. This is an algebraic reduction step, not a quantified
proximity or knowledge-soundness theorem. See `block-rs.md` for assumptions and
source-to-implementation differences. The referenced Galois-ring proof could
not be fetched (HTTP 403); its full proof was not reviewed here.

Commands, raw logs, resources, reference fixtures, binary/source provenance,
source-audit notes and source/lock snapshots are under
`target/performance/joint-target-pbs/`. The independent proofs do not implement
aggregation. Full security-matched promotion, hiding/direct packed PipFRI and
aggregated validation remain open.

## Reciprocal-table inversion and reuse

Extension lookups now compute each reciprocal table once and reuse it for helper
values and public multiplicity sums. For BabyBear's supported binomial extension
profiles, a prefix-product/backward pass uses one inversion and 3m extension
multiplications for m nonzero denominators. Previously the prover performed m
individual inversions while building helpers and another m while checking the
public sum; the verifier performed m. Challenge rejection already excludes zero
denominators. Challenge order, field values, roots and protocol parameters are
unchanged.

A byte comparison caught Goldilocks batch inversion returning field-equal but
byte-distinct lazy representations, even on [1,-1]. The production dispatcher
therefore retains individual Goldilocks inversions and caches their exact
results; only BabyBear uses batch inversion. This halves Goldilocks prover
inverse work for each table without changing its inverse representation. It
does not reduce the verifier's Goldilocks inversion count. Tests compare direct
inversion, product identities and exact serialization on lengths 0/1/2/17/511
across BabyBear degrees 5/6/8 and Goldilocks degrees 3/5, plus zero rejection.
Five genuine false-source child tests and twelve lookup/mapping/decomposition
tests also pass: 19 targeted Rust tests total, plus 79 Python tests. Both selected
release examples build successfully.

Two reversed native BabyBear comparisons use the archived optimized sextic
binary as baseline and the new degree-six binary as candidate. Both use 16
threads, width eight, Q544 and helper-left-extra one; no compilation or tests
run during measurement. Each process proves/serializes/decodes/verifies two
complete native NAND certificates. Reused complete time, including native trace
and serialization, is:

| Order | Before | After | Measured reduction |
|---|---:|---:|---:|
| Before then after | 18.353 s | 18.115 s | 1.29% |
| After then before | 18.324 s | 18.202 s | 0.67% |

First-proof times are 18.460/18.420 s before and 18.380/18.415 s after. Peak RSS
stays about 2.84 GiB. These are small two-session differences, not a statistical
confidence estimate or a new >=10% promotion claim. All native proof hashes,
405,612,783-byte sizes, statement/key/FHE hashes and four PCS layouts match the
archived native reference. The same conditional 134.90-bit per-proof / 130.51-bit
21-proof interactive inventory applies; full hash/Fiat-Shamir/composition review
remains open.

All 37 benchmark certificates verify: eight native controls, four BabyBear and
four Goldilocks repeated toy controls, and 21 fresh BabyBear toy cases. Before
and after toy wire bytes match for both fields, and all 21 fresh toy certificates
match archived source/proof/key hashes. There is no new Goldilocks original-size
latency measurement or new 21-case native validation in this increment. Existing
native validation evidence remains separate.

`target/performance/reciprocal-table-pbs/` preserves build sources and pinned
Cargo.lock, exact baseline/candidate binaries, commands, raw logs/resources,
paired comparisons and fresh-toy validation. The runner and all nine subprocesses
finished successfully. Production source changes are confined to reciprocal
calculation/reuse in `packed_extension_lookup.rs`; no budget formula, FHE
parameter, transcript version or proof wire type changes.

## Common-query multi-root PCS aggregation component

The new experimental `pcs::matrix_weighted::aggregate` combines the responses of
several roots at one shared ordered matrix query. It authenticates every source
column and uses extension-field weights to combine fixed claims, with a joint
random row test. It is non-hiding and not yet composed into complete-PBS proofs.
See `packed-multi-root.md` for the protocol, conditional argument and limitations.

At the complete source capacity of 2^21 Base scalars per table, two reversed
16-thread sessions for sixteen roots reduce BabyBear opening+serialization from
274.03/263.93 ms to 163.69/160.57 ms, and Goldilocks from 192.07/190.03 ms to
101.09/131.28 ms. Bytes fall 67,339,647→34,930,423 and
61,605,861→28,848,827 respectively. Parallel verification is also faster;
the initial serial-verifier regression is retained as comparison evidence.
One-root aggregation is larger/slower; four-root BabyBear saves bytes but is
slightly slower. No automatic full-backend selection or promotion follows.

These are synthetic common-query PCS measurements with matched roots/claims,
common Q544 and separate commitment/setup, not native FHE/PBS statements or a
reviewed whole-security match. Both serial and parallel run sets verify 36
serialized packets each, including all 1/4/16 groups over both fields and both
native-capacity execution orders. All corresponding proof and statement digests
match between implementations and across reversed sessions. Fifteen targeted
Rust tests, 79 Python tests, release build and workspace check pass. Evidence is
under `target/performance/mw-multi-root/` and
`target/performance/mw-multi-root-parallel/`. Complete PBS aggregation, hiding,
Fiat-Shamir composition and security-matched promotion remain open.

## Packed relation frontend with aggregated factor authentication

`snarks::packed_relation::aggregate` now composes ordinary packed ZeroCheck with
one multi-root terminal opening, using a separate type/domain and canonical
state references. This moves aggregation into a real relation frontend; the
complete PBS formats and default relation backend remain unchanged.

Two reversed 16-thread sessions at native source capacity measure entire dense
synthetic sum-of-products relation proving plus serialization. For sixteen
products (33 roots), BabyBear times fall 1,167.12/1,061.00→872.88/901.42 ms and
Goldilocks 855.68/801.80→585.34/620.06 ms. Proof bytes fall
138,869,899→61,724,817 and 127,026,140→53,893,256 respectively. Verification
is faster in both sessions. Four-product groups improve too; one-product
cases can regress. Preparation/commitment and verification are measured
separately, so this is not a complete-PBS latency claim or a whole-security match.

All 36 relation certificates decode and verify, with stable per-mode proof and
statement hashes across sessions. Six Rust tests include eighteen new positive
fixtures, two unchanged legacy tests and two genuine fake-factor attacks with
valid algebra and actual-root paths that fail the production linear equations.
All 79 Python tests, the release build and workspace check pass. See
`packed-multi-root.md` and `target/performance/aggregate-relation/` for complete
scope, raw evidence and limits. Complete-PBS factor integration, cross-statement
aggregation, hiding and Fiat-Shamir/security-matched promotion remain open.

## Complete version-4 Hadamard aggregation

The opt-in `--aggregate-hadamard` path now uses the aggregate relation frontend
inside a complete extension-comparison PBS proof. Its new type and version-4
domain retain the original expected bootstrapping-key roots and canonical
source linkage. Every other stage keeps its prior backend; versions 2/3 remain
the defaults. This is factor authentication within one PBS, not cross-statement
aggregation. See `packed-aggregate-pbs.md` for protocol and validation scope.

Two reversed native 16-thread comparisons reduce BabyBear proof size
405,612,783→378,478,271 bytes (6.69%) and Goldilocks
614,289,399→559,825,723 bytes (8.87%). Reused complete BabyBear times are
18.446/18.444→18.250/18.249 s; Goldilocks times are
32.049/31.947→32.113/32.135 s. The latter does not show a speedup. The smaller
proofs do not meet a new >=10% complete latency gate or justify promotion.
Original FHE/key/statement digests and all four Q544 layouts match across modes.
Default v3 native/toy proof bytes still match archived fixtures exactly.

All 66 measured serialized certificates verify: sixteen original-size controls,
eight repeated toy controls and 42 fresh version-4 toy cases. All sixteen Rust
complete-proof tests and 81 Python tests pass, as do both selected release
builds and the workspace/example check. The conditional budget retains old
Hadamard PCS terms plus an explicit full-field cancellation term, with geometry
checks; it is not a hash/Fiat-Shamir/knowledge certificate. The follow-up below
adds full-size fresh v4 validation and the malicious-child audit.
Evidence is under `target/performance/aggregate-pbs/`; full security, hiding,
cross-statement aggregation and security-matched promotion remain open.


## Version-4 fresh native validation and binding audit

All 42 fresh complete version-4 NAND proofs pass at original ring-1024/LWE-728
dimensions, in independent groups 1/4/16 per field with shared setup. The audit
matches every original parameter, key, statement and PCS layout against archived
fresh version-3 fixtures; version-specific proof hashes are intentionally new.
Both original output keys and all NAND truth cases are verified through public
decoded verification and native decryption. Root-inventory records are linked to
each accepted proof digest. Conditional per-field 21-proof inventories remain
130.5089/130.1606 bits, with a 129.3243-bit conditional union over all 42. These
concurrent runs are correctness validation, not additional latency measurements.
Sources, reused binary digests, commands, logs and exact fixture checks are in
`target/performance/aggregate-pbs-native-fresh/`.

The independent malicious-child reconstruction fixture now supports the new
Hadamard type/domain while preserving the legacy key-switch product format.
Nine audit tests pass across versions 2/3/4: ninety fresh certificates, nine
valid controls and 81 expected rejections. The twenty v4 cases cover both fields,
requested input/output changes, blind/switching-key substitutions, endpoints,
continuity splices and duplicate witness views. Local algebra and actual-root
openings verify before production rejects the intended inconsistent binding;
this is not honest-proof replay under changed transcript bytes. Test geometry
is small and the result is not a full security proof. Evidence is under
`target/performance/aggregate-v4-binding-audit/`. The existing 81 Python tests
pass. Cross-statement aggregation, hiding/direct packed FRI, concrete
Fiat-Shamir/hash composition and security-matched promotion remain incomplete.
