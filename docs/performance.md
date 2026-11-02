# Performance work and packed-protocol experiments

Measured results and implementation status are in
[performance-results.md](performance-results.md).

The target is lower complete single-PBS proof latency, unchanged TFHE parameters
and output-key semantics, 128-bit proof security, and at most twice the baseline
proof bytes. No experimental backend is promoted to that target yet.

## What is implemented

* Complete BabyBear and Goldilocks PBS benchmark executables, using the artifact
  parameters and all four proof stages: modulus switching, blind rotation, key
  switching, and sample extraction.
* A deterministic key-generation entry point for repeatable benchmark fixtures.
  Normal key generation continues to obtain fresh randomness.
* Optimizations in the existing sumcheck prover: in-place folding, one reusable
  product buffer per product, in-place reduction, and identity-affine fast paths
  that avoid full extension-field multiplication by one. An independent
  direct-interpolation regression checks every round message over BabyBear, its
  extension, and Goldilocks. This changes neither the protocol nor proof layout.
* Tiled PCS linear aggregation over base and extension tables, avoiding one
  temporary response allocation per matrix row and allowing independent output
  tiles to run in parallel. Direct matrix multiplication tests check the result.
* Packed sumcheck and packed ZeroCheck, following sections 3.2 and 5.1 of the
  supplied `2025-719.pdf`. The implementation supports sums of products with
  shared factors, independent lane challenges, forward-difference extrapolation,
  and the ZeroCheck-specific initial equality tests and mixing matrix.
* Ordered matrix-weighted Boolean tables and queries, plus a non-hiding
  Brakedown-style opening backend. It supports the original scalar row encoders
  and Algorithm 2's block-level RS encoding using base-field NTTs. Entire block
  symbols are authenticated and checked, with distance measured in block symbols.
  Non-power-of-two packing widths use explicit zero padding of coefficient blocks.
  Sampled column indices are deduplicated only after all independent samples
  have been drawn, preserving the sampling experiment without sending duplicates.
* A block-aware row/column layout chooser, base-field direct-evaluation tests
  over BabyBear and Goldilocks, parameter/domain binding, in-place matrix folding,
  reusable forward-difference scratch buffers, and parallel independent column
  checks. Suffix query evaluation folds vectors rather than expanding a matrix
  tensor, keeping its arithmetic at O(k² times the column count).
* An authenticated packed vector-relation API, serialization/tampering tests,
  and an adapter for external-product Hadamard relations from native PBS traces.
  The verifier receives public commitments and proof data, not the private tables.

* Canonical coefficient/NTT linkage with tensor-row checks and shared batched
  openings, tested against native full-size Hadamard roots (`packed-ntt.md`).
* Scalar and joint tuple reciprocal lookups, with multiplicities fixed before
  challenges, explicit pole-domain accounting and authenticated original columns.
  Canonical radix reconstruction uses borrow-transition tuples to reject x+p
  integer representations, and a shared linear check ties the same digit roots
  to native external-product inputs (`packed-decomposition.md`). These components
  verify; lane batching authenticates broadcast values via pullbacks to existing
  roots and substantially reduces helper proof bytes. Complete performance gates
  remain unmet (`lookup-batching-design.md`).

* Prover phase counters for lane-batched lookups and canonical decomposition,
  constant-factor interpolation caches and repeated-cell matrix-fold fast paths.
  Direct Lagrange and ordered-matrix references validate the kernels; paired
  original-size component measurements are in `lookup-profiling.md`.

* Accumulator additions, actual-round continuity, expected endpoints and links to
  the existing decomposition roots. Shift/half views use canonical query maps
  and shared openings instead of new view commitments (`packed-accumulator.md`).
  Public monomial multiplication, initialization and key/output binding remain.

The packed sumcheck APIs return opening obligations. Their success alone does
not authenticate a witness. `snarks::packed_relation` discharges those obligations
with matrix-weighted openings. Its commitments still need to be connected to
the rest of PBS before this component can establish PBS correctness.

## Reproduce measurements

From the repository root:

```bash
python3 tools/bench_pbs.py --fields babybear goldilocks --threads 1 16
```

The default is one warm-up plus ten measured executions per field/thread/mode.
Use `--output target/performance/session-name` for a unique output directory.
The tool builds release binaries, captures their copies, source, lockfile,
compiler/CPU/revision information, raw JSONL, logs, and median/min/max/standard
deviation summaries. Linux GNU time additionally records whole-process peak RSS.
RSS covers setup and verification as well as proving; it is not a per-stage peak.
Use a second unique session directory to confirm a performance result.

To compare already captured BabyBear binaries without rebuilding either one:

```bash
python3 tools/confirm_pbs.py target/performance/baseline target/performance/optimized --threads 16
```

This verifies the saved executable hashes, reruns both binaries with the same
settings, and reports latency and proof-size thresholds separately from security.

Both modes generate the same seeded ciphertext fixture once per process:

* `warm`: reuse the bootstrapping-key commitment; per-input preparation remains
  inside `complete_ns`.
* `cold`: regenerate that commitment for each execution. This means uncached
  key-commitment preprocessing, not a fresh OS process or a fresh keypair per input.

`complete_ns` includes evaluation/trace generation, finalization, per-input
preparation, any newly required key commitment, all proof stages, and complete
proof serialization. Key generation and verification are reported separately.
`proof_bytes` measures the serialized complete proof tuple. PCS/PIOP byte
breakdowns use the artifact's existing methods and are diagnostic, not additional
bytes to add to `proof_bytes`.

`pcs_commit_ns` and `pcs_open_ns` partition the tracked PCS prover time.
`tracked_extension_ns` measures explicitly instrumented trace and bit-polynomial
conversions in blind rotation and indexed lookups; it is a subset of proving time,
not a measurement of every conversion or allocation. `RUST_LOG=info` captures
the artifact's finer PIOP timings in the session logs.

The benchmark binds its public ciphertext fixture and key commitment into a
separate transcript domain. This makes it a versioned benchmark invocation, not
a new public PBS verification API. The artifact's existing wrappers have not
been audited here for complete statement/stage binding.

The label `artifact-unbudgeted` is intentional. The existing parameter names
describe FHE parameters; they do not constitute a whole-proof soundness analysis.
The BabyBear artifact also supplies `32` as the code specification's field-bits
parameter, although the actual prime has approximately 31 bits. Preserve that
setting for artifact reproduction; use the actual prime in any security analysis.

## Exercise packed components

```bash
cargo test -p sumcheck -p pcs -p piop -p snarks --lib --tests
cargo run --release -p vfhe --example packed_pbs_hadamard
RAYON_NUM_THREADS=16 cargo run --release -p vfhe --example packed_pbs_hadamard -- --full
python3 -m unittest discover -s tools -p 'test_*.py'
python3 tools/packed_budget.py
```

The Hadamard example defaults to a small insecure FHE fixture for fast smoke
testing. `--full` uses the existing BabyBear parameters, but still proves only
the Hadamard component. It uses eight packed lanes, block-RS encoding and an
explicit query count. These settings do not establish complete 128-bit PBS
security or zero knowledge. The fixture seed is public and deterministic.
The proof excludes its separately supplied commitments; compare its sizes only
with equivalently scoped component measurements.

The `HB_COMPONENT` record includes the actual padded RS message-symbol count,
encoded-symbol count, block width, repetitions, phase timings and artifact bytes.
Check the fixed component's experimental algebraic budget with:

```bash
python3 tools/packed_budget.py --component target/performance/block-rs/full.log
```

This must use block-symbol distance, not the number of flattened scalar entries.
The component budget is not a complete PBS or Fiat-Shamir security argument.

Packing places distinct consecutive vector rows into lanes. Partial lanes and
the Boolean domain are zero padded. Every relation term contains at least one
factor, so this padding satisfies the expression. Table indices are little
endian and matrix weights act in the order `M[last] ... M[first]`.

`packed_budget.py` uses exact rational arithmetic to select widths and query
counts under conservative experimental **interactive algebraic** error bounds.
It does not validate an arbitrary supplied prime, establish security of the
row-code adaptation, include all PBS lookups/reductions, or account for the
Fiat-Shamir transformation, hash assumptions, or hiding. Its output is not a
security certificate. Width five is a starting point, not a fixed global choice.

## Ordinary PipFRI reference

`pcs::rolling_fri` implements Protocol 1 of `refs/2025-1354.pdf`:
all original roots precede challenges, derived roots precede query indices,
adjacent bit-reversed values represent x/-x, and the last fold is a constant.
`pcs::pipfri` implements the non-hiding Protocol 2 fragment reduction and batch
PolyFRIM evaluation checks. A single Merkle leaf contains every fragment's pair
at one location. Public-point folded codewords receive a rolling low-degree
certificate. Independent consistency queries authenticate their initial random
combination and every public-point fold, including the claimed scalar terminal.

This reference variant explicitly commits the random combined first oracle;
it has an extra tree and does not yet reuse virtual-oracle/query openings as in
the optimized paper construction. It supports the paper's monomial coefficient
basis, with weights (1,x), and HasteBoots' Boolean table basis, with weights
(1-x,x). Low variables come first. Boolean coordinates 0 and 1 require no
conversion or division. Trusted parameter constructors check power-of-two
geometry, overflow and the exact order of the domain root; verifier inputs
exclude private trees/codewords and deserialized trusted configurations.

Tests compare encoding to native NTTs and independent Horner evaluation, compare
folding to coefficient arithmetic, and evaluate whole tables by an independent
tensor formula. Fresh malicious certificates preserve every Merkle opening and
pass low-degree verification but fail either public evaluation or source-to-
combination binding. A degree-bound violation is separately rejected by rolling
FRI despite genuine oracle openings. BabyBear and Goldilocks, together with
their degree-4 and degree-2 extensions, are covered. Extension tests use non-base
coefficients/points and compare with native dense multilinear evaluation.

```bash
cargo test -p helper -p pcs --lib --tests --locked --jobs 2
cargo build --release -p pcs --example pipfri --locked --jobs 2
RAYON_NUM_THREADS=16 target/release/examples/pipfri babybear 18 14 64 3
RAYON_NUM_THREADS=16 target/release/examples/pipfri goldilocks 18 14 64 3
RAYON_NUM_THREADS=16 target/release/examples/pipfri babybear-ext4 18 14 64 3
RAYON_NUM_THREADS=16 target/release/examples/pipfri goldilocks-ext2 18 14 64 3
```

These synthetic scalar-table smokes check deserialized proofs against the
repository's native dense multilinear evaluation. The JSON records separate
commit, open, serialization and verification time. They are not complete PBS
measurements. Base-field batch/folding challenges and 64 queries are experimental
parameters, not a 128-bit setting. Extension-field challenge sampling now draws
each base coefficient directly from Merlin. Its distinct domain binds the base
characteristic, extension degree and complete canonical basis multiplication
table. An independent binomial/byte-decoding reference checks this framing and
sampling. Prime-direct and legacy transcript outputs remain unchanged. The
current example uses uniform points in its declared scalar field and records
the transcript protocol identifier; previous saved base-field smokes used fixed
integer points and retain their original executable/source snapshots.

Sampling every coefficient removes the legacy 128-bit seed wrapper, but field
size is still not a complete security level: BabyBear^4 has fewer than 2^124
elements and Goldilocks^2 fewer than 2^128. Batching, folding degrees, proximity
queries and composition must all be included when choosing concrete parameters.

Protocol 3 masking, a concrete composed security argument, fully bound PBS integration,
packed matrix-query compatibility and security-matched comparisons remain open.
The existing PBS backend is unchanged.

## Ordinary PipFRI PCS adapter and native experiments

`pcs::multilinear::pipfri::PipFRIPCS` implements the existing scalar PCS trait.
It commits both base and extension inputs in the extension field, using Boolean
MLE semantics. Its first reference implementation keeps separate proofs for
different points. Logical zero-variable tables use a duplicated constant table
and a fixed dummy coordinate; the opening transcript binds the original logical
dimension. The trait-required default parameters are an uninitialized sentinel
that verification rejects. Initialized empty batches have no evaluation claims;
nonempty batch verification checks all three vector lengths before iteration.

The public PCS verifier takes expected trusted parameters and commitment. Tests
cover native dense evaluations, serialization, wrong roots/values/configuration,
base/extension mode separation, constants, and batches of 1/4/16 with truncated
and reordered proof rejection. Existing scalar LogUp SNARKs verify with the
adapter over both fields. `open_at` computes the claimed evaluation from private
state without traversing the fragment table twice; the verifier still requires
the expected public value.

```bash
cargo test -p pcs --lib --tests --locked --jobs 2
cargo test -p snarks --test pipfri_adapter --locked --jobs 2
cargo build --release -p vfhe --example pipfri_pbs_babybear --example pipfri_pbs_goldilocks --locked --jobs 2
RAYON_NUM_THREADS=16 RUST_LOG=info target/release/examples/pipfri_pbs_babybear --iterations 2 --warmups 0 --seed 42
RAYON_NUM_THREADS=16 RUST_LOG=info target/release/examples/pipfri_pbs_goldilocks --iterations 2 --warmups 0 --seed 42
```

The opt-in native executables use the original FHE parameters, key/output
semantics and all four existing scalar proof wrappers. Their separate
`HB_PIPFRI_BENCH` records specify the unbudgeted backend, direct extension
transcript, proof geometry, phase costs and serialized bytes. They also record
hashes of the full public FHE configuration and ciphertext statement, plus the
actual trusted BSK root. Every run checks native NAND decryption, all four stage
verifiers, and final transcript agreement. The first proof includes key
commitment generation; subsequent proofs reuse it unless `--cold` is supplied.

These are functional/performance experiments through the existing four-stage
wrappers, with in-memory verification. They do not provide a new standalone
complete-PBS verifier or a complete audit of public statement/stage binding.
They do not replace `packed_pbs` or meet the security-matched promotion gate.
The scalar adapter's extension-field embedding/encoding is deliberately a
reference path; its measured commitment cost is a target for optimization.
Artifacts and source/binary/lock hashes are under
`target/performance/ordinary-pipfri-native/`.

## Coordinate-wise ordinary PipFRI encoding

The scalar adapter now selects a base-field coordinate encoder for its extension
oracles. For an extension basis b_j, write each coefficient as
`a_i = sum_j a_ij b_j`. Every domain point x is in the base field, so
`sum_i a_i x^i = sum_j b_j (sum_i a_ij x^i)`. The implementation therefore runs
one base-field DIF FFT per nonzero coordinate and reconstructs extension values
in the original bit-reversed order. Entirely zero coordinates skip the FFT;
this benefits the adapter's embedded base-field tables. Squared domains retain
the same property, including domains smaller than the native NTT plan minimum.

`with_base_field_encoder<Base>` checks that the trusted root is in Base and
rejects genuine extension-only roots. The generic extension-arithmetic encoder
remains available as the default for direct core constructors. The implementation
selector is excluded from serialized parameters. Tests compare parameter bytes,
all original commitments, complete scalar proof bytes, and subsequent transcript
challenges across both encoders on zero, base, sparse and dense extension tables.
Either verifier parameter object accepts the same proof. Independent Horner and
coefficient-fold references remain in the PCS suite. This is an arithmetic
optimization, with no new proximity or security claim.

The saved native reference and optimized executables can be compared with:

```bash
python3 tools/compare_pipfri_pbs.py target/performance/ordinary-pipfri-native target/performance/ordinary-pipfri-coordinate --output target/performance/pipfri-paired-check --sessions 2 --iterations 2 --threads 16
```

The tool alternates execution order, validates saved executable hashes, requires
exact public statement/configuration/key-root and protocol metadata agreement,
and rejects differing serialized proof/PCS/PIOP sizes. Each process verifies an
initial proof and then reuses the key commitment. The default measures only one
reused-key proof per process; these are paired engineering smokes, not ten-run
medians or security-matched promotion evidence. Use a new output directory for
each comparison. The original baseline archives remain intact.

## Extension fields for concrete parameter selection

The algebra crate now provides `BabyBearExtension8`, `GoldilocksExtension4`,
`BabyBearExtension5` and `GoldilocksExtension5`. The degree-8/degree-4 fields
provide room for field-dependent errors when selecting a composed 128-bit
configuration; degree-5 fields support further lookup experiments. Existing
BabyBear^4 and Goldilocks^2 aliases and default proof configurations are unchanged.

| Alias | Defining polynomial | Frobenius multiplier W^((p-1)/d) | Cardinality bound |
|---|---|---:|---|
| BabyBearExtension8 | X^8-11 | 420899707 | 2^247 < p^8 < 2^248 |
| GoldilocksExtension4 | X^4-7 | 281474976710656 | 2^255 < p^4 < 2^256 |
| BabyBearExtension5 | X^5-2 | 815036133 | 2^154 < p^5 < 2^155 |
| GoldilocksExtension5 | X^5-3 | 1041288259238279555 | 2^319 < p^5 < 2^320 |

`BinomialExtensionParameters` requires arithmetic parameters but no primitive
multiplicative generator. Existing `BinomiallyExtendable` implementations delegate
through a blanket implementation, retaining their API. New fields do not claim
unverified generator constants or extension-only NTT roots. Scalar PCS domains
continue to use embedded base-field roots. The previously unimplemented extension
`pow(u128)` now performs binary exponentiation; it does not truncate the exponent.
Frobenius-based inversion supports field orders exceeding u128 without requiring
a full-order integer exponent.

`algebra/tests/extension_parameters.rs` checks the prime candidates by an integer
2-power-order certificate and verifies each defining polynomial with the
[Rabin irreducibility criterion](https://www.jmilne.org/math/Books/FT0.pdf#page=85)
(Milne, Exercise 4-8). Its integer polynomial division, modular powers, gcd and
extended-Euclidean inverse are independent of the extension implementation.
Reducible control polynomials are rejected. Multiplication, squares, exponents
through u128::MAX, Frobenius, inverses and serialization are checked over both old
and new fields. Separate direct-sampling references and scalar PCS/SNARK tests
exercise non-base coordinates, malformed claims, batches and encoder equivalence.

The new malformed-input tests also reproduced an inherited BabyBear decoding
bug: the derived decoder accepted internal representatives >=p. The checked
newtype decoder rejects them, including inside extension coefficients. Valid
Montgomery bytes retain their prior format; no valid protocol encoding is changed.
The new fields alone do not establish 128-bit proof security: proximity/query
counts, algebraic degrees, batching, composition, Fiat-Shamir and hiding remain
part of the full gate. The scalar example marks all configurations unbudgeted.

```bash
cargo test -p algebra -p helper -p pcs --lib --tests --locked --jobs 2
cargo test -p snarks --test pipfri_adapter --locked --jobs 2
cargo run --release -p pcs --example pipfri -- babybear-ext8 18 14 64 3
cargo run --release -p pcs --example pipfri -- goldilocks-ext4 18 14 64 3
```

The scalar example also accepts `babybear-ext5` and `goldilocks-ext5`. Extension
modes now explicitly select the validated coordinate encoder and record its name;
older saved scalar examples retain their original binaries and metadata.

## Research gates and remaining implementation

1. **Complete packed PBS:** compose the implemented decomposition/lookups and NTT
   components with accumulator continuity, modulus/key switching and extraction,
   linking every relation to
   canonical commitments and the public statement. The current scalar-point PIOP
   interfaces cannot simply be reused with matrix queries. Block-RS encoding is
   implemented; validate the complete composed commitment/PIOP analysis before
   promotion.
2. **Security-matched baseline:** inventory every actual degree, round count,
   lookup repetition, opening and proximity test, then budget the complete
   composition and Fiat-Shamir compilation. Preserve FHE security and the exact
   output-key contract. A 100-bit paper reproduction is a separate configuration.
3. **PipFRI:** the ordinary scalar reference exists in `pcs::pipfri`, with a
   separate experimental masked implementation in `pcs::pipfri::masked`.
   The latter adds private padding, a virtual source oracle, shared queries and
   bounded opening sessions; see `masked-pipfri.md`. Finish the masking/security
   argument and complete native-workload integration/comparison.
   Matrix-weighted openings then require a separate consistency/evaluation-binding argument. For a split query, the
   reconstruction is `sum_j R_j * z_j`, with each `z_j` a matrix-weighted fragment
   value and `R_j` an ordered matrix suffix weight. Scalar fragment coefficients
   cannot replace these noncommuting matrices. MW-Basefold is the paper-backed
   FRI comparison; no packed PipFRI implementation or security claim is included.
4. **Convolution:** investigate only if NTT/product certification remains material
   after packing. For TFHE use the negacyclic quotient identity
   `a(X)b(X)-c(X)=(X^N+1)q(X)`, not the integer paper's ordinary convolution check.
   Bind all four degree-bounded polynomials before evaluation challenges and
   account for identity-testing and opening errors. No integer-PCS replacement
   is included.

Promote a new cryptographic backend only after the complete 128-bit argument,
all adversarial/correctness checks, proof bytes at most 2x the security-matched
baseline, and at least 10% lower median complete single-PBS latency in two
independent measurement sessions. Current component tests and artifact timings
do not meet that promotion gate by themselves.

## Reference revisions

The local files are the specification used here: `2025-261(1).pdf`
is the HasteBoots paper (no `(2).pdf` is present in the current refs directory); `2025-719.pdf` contains packed sumcheck and
MW-MLE; `2025-1354.pdf` contains PipFRI; `2026-347.pdf` contains relaxed modular
PCS and integer convolution checks. The local packed-paper revision reports
2.2 seconds at 100-bit security with about 133 MB proofs and different FHE
parameters, on a dual 48-core EPYC server. Its modulus-switching workload is
omitted from that evaluation. Its headline is not a complete, security-matched
performance target for this implementation.

## Public rotation linkage

`--with-monomial` includes lane decomposition, accumulator continuity and
public monomial products from x+y. Its initial accumulator is derived from the
public NAND LUT/body rather than accepted from the trace. See
[packed-monomial.md](packed-monomial.md). Key and final-output binding, complete
PBS composition and promotion remain outstanding.

`--with-public-key` additionally derives reusable expected bootstrapping-key
roots from the native public evaluation key. Hadamard verification consumes
those roots. See [packed-bootstrap-key.md](packed-bootstrap-key.md); final
key-switching-key/output binding and complete-PBS composition are still pending.

`--with-key-switch` enables canonical negative-a key-switch decomposition,
trusted switching-key products and signed extraction against the actual original
output ciphertext, linked to the accumulator endpoint. See
[packed-key-switch.md](packed-key-switch.md). This still needs a standalone
complete proof/verifier API and complete security/performance validation.

## Complete binary NAND proof API

`snarks::packed_pbs` provides trusted native-key preprocessing, an owned
serializable `Proof`, and `prove`/`verify` functions. The verifier receives trusted
PCS parameters, a public verifier setup and the expected input/output ciphertexts.
It receives no native trace or PCS prover states. A single proof-owned final
accumulator is constrained by continuity and passed to final key switching; the
initial accumulator and rotations are derived from the public NAND inputs.

Canonical private roots are the 2d digit columns and sum-product, four accumulator
columns, and two decomposition inputs. The same roots are used by every child
relation. Public bootstrapping-key NTT tables/states are prepared once and reused;
there are no coefficient/NTT proofs for already trusted public key columns.
For the original BabyBear profile this reduces private NTT links from 17 to nine.
The native witness adapter accepts raw or zero-padded traces without needing the
old trace finalizer, and key columns from a trace are never trusted.

```sh
cargo test -p vfhe --test packed_pbs --locked
RAYON_NUM_THREADS=16 cargo run --release -p vfhe --example packed_pbs
RAYON_NUM_THREADS=16 cargo run --release -p vfhe --example packed_pbs -- --full
python3 tools/full_pbs_budget.py target/performance/complete-packed-pbs/full.log
```

The two native test suites generate fresh complete proofs in groups of 1, 4 and
16 over BabyBear and Goldilocks, including all NAND plaintext combinations,
serialization, changed roots/endpoints, missing children, cross-proof child swaps
and expected keys. They also attempt proving a valid foreign trace while binding
the requested public mask, and reject it in the actual equations. These are
independent single-PBS proofs with reusable setup, not an aggregated batch proof.
Four public-key/relation regression tests and 13 Python tool tests also pass.
Complete foreign-trace forgery construction now covers both fields as described
below. Global key/endpoint variants and independent adversarial review remain;
the existing child protocols also have genuine-subproof forgery tests.

The original-size BabyBear release smoke verifies from a serialized complete
proof of 556,173,638 bytes. Warm complete time is 48.976 s (native trace, private
preparation, proving and serialization), of which proving is 48.561 s. Reusable
public setup is 0.624 s and is excluded from that warm number. Verification is
2.751 s and deserialization is 0.126 s, both reported separately. Process wall
time is 52.71 s and peak RSS is 5,640,492 KiB. This is a one-session smoke, not a
matched performance promotion result. The phase profile puts 44.184 s (91% of
proving) in canonical decomposition; private NTT links take 0.774 s. This defers
the optional convolution experiment until lookup optimization changes the profile.

The complete interactive inventory reads actual `HB_FULL_PCS` metadata for all
four PCS layouts and the private-root/NTT inventory in `HB_FULL_PBS`. Its exact
rational union bound totals approximately 3.358e-40 under the experimental child
models. This excludes Fiat-Shamir, knowledge soundness, hash binding and hiding,
and does not certify 128-bit security. That original version-1 helper path expands a 128-bit seed into challenge
vectors. Complete packed version 2 now uses direct canonical sampling as
described below; concrete Fiat-Shamir losses and hash assumptions still need
review. The old baseline remains unbudgeted, so its
raw bytes/timings are not a security-matched comparison. All logs, binaries and
source provenance are under `target/performance/complete-packed-pbs/`.

## Retain terminals already computed by packed folding

`packed::prove_with_terminal_values` and
`packed_zero::prove_with_terminal_values` return the original factors' final
vectors alongside the existing proofs/subclaims. Their ordinary `prove` APIs
remain available. ZeroCheck also reuses its final EQ-factor vector instead of
folding that table a second time. These are prover outputs only: every canonical
PCS opening and verifier terminal equation remains in place.

Lane-batched lookups reuse helper terminals and broadcast-source terminals when
the pulled-back canonical query has no post-matrix. Zero-variable sources keep
the original evaluation path: a broadcast post-matrix can be singular, so its
output must not be treated as the original canonical value. The Hadamard,
monomial and final extraction provers also retain their already-folded values.
No proof fields, roots, challenge sampling or verification equations change.

Dense original-table references cover both fields, zero/one/multiple variables,
widths 1/2/5/8, constant factors, returned EQ values and transcript agreement.
The sumcheck/SNARK run passes 56 tests, and the native complete-proof suites add
two passing tests over both fields and fresh ciphertext groups 1/4/16. Sixteen
Python performance/inventory tests pass.

Saved executables are compared using manifests and alternating order:

```sh
python3 tools/compare_packed_pbs.py \
  target/performance/complete-packed-pbs/complete.bin \
  target/performance/terminal-reuse/complete.bin \
  --baseline-manifest target/performance/complete-packed-pbs/provenance.sha256 \
  --candidate-manifest target/performance/terminal-reuse/provenance.sha256 \
  --output target/performance/terminal-reuse/new-comparison \
  --threads 16 --sessions 2 --full
```

The tool checks the full native metadata and all four PCS layouts/inventories.
The two original-size BabyBear complete smokes measure 48.814→41.231 s (15.5%)
and 49.051→41.169 s (16.1%). Bytes remain 556,173,638 in every run. Decomposition
proving changes from about 44.07 s to 36.57 s. Peak RSS changes from roughly
5,638,000 KiB to 4,155,000 KiB in both pairs. This is a two-pair engineering
comparison within the experimental backend; it is not the ten-run,
security-matched baseline/promotion result. Reported seed/FHE/layout metadata
match, but these saved executables do not report direct ciphertext/key digests.
The interactive inventory is unchanged. Artifacts and provenance are under
`target/performance/terminal-reuse/`.

## Complete packed protocol version 2: direct field challenges

`helper::Transcript::new_direct` is a prime-field constructor for the complete
packed protocol. It uses Merlin challenge bytes directly, without the legacy
16-byte AES seed expansion. Each scalar/vector request binds the request kind,
label, characteristic as 16 little-endian bytes and length as eight little-endian
bytes. The constructor uses a separate transcript domain. Field samples read
ceil(log2(p)/8) bytes, mask to ceil(log2(p)) bits, and reject values >=p; accepted
residues are canonical. This is exact rejection sampling in the ideal-uniform-byte
model and does not depend on rand's bounded-integer distribution implementation.
The stream is extracted in fixed 256-byte blocks; unused bytes are discarded at
the end of each request. Empty vectors still bind their request frames.

`snarks::packed_pbs::PROTOCOL_VERSION` is now 2, with transcript identifier
`merlin-direct-canonical-rejection-v1`. Proofs carry the checked version, and the
parent domain is `HasteBoots complete binary NAND PBS v2`. The verifier chooses
its own direct transcript and rejects unsupported proof versions before reading
canonical source vectors. Archived version-1 proofs require their archived
verifier; changing a proof's version tag does not migrate its transcript. Native
FHE parameters, key commitments, operation and output-key contract are unchanged.

`Transcript::new` and `Default` retain the original empty-domain, 16-byte AES
sampling path for the old artifact and component callers. Independent reference
tests check that legacy sampling and subsequent transcript bytes remain identical
over BabyBear, Goldilocks and the existing BabyBear extension. Other tests force
rejection at the modulus (including u128 boundary arithmetic), cross buffer
boundaries, compare direct samples against explicit Merlin frames/decoding, and
check separation by kind, label, count, empty requests and characteristic.

The native complete suites pass over both fields for independent ciphertext
groups 1/4/16 and reject version-tag changes. The original-size BabyBear release
smoke verifies version 2 from serialized bytes: 555,651,057 bytes, 41.473 s warm
complete time, 2.928 s verification and 4,155,308 KiB peak RSS. Public setup and
deserialization remain separate. These are functional version-2 smoke results,
not a same-protocol speed comparison against archived v1. The comparison tool
normalizes historical unversioned logs as v1 and rejects mixed transcript
versions; inventory tooling validates the version/identifier pair. Eighteen
Python tool tests pass. Artifacts are under `target/performance/direct-transcript/`.

The interactive error inventory is unchanged (approximately 3.358e-40 under the
experimental component models). This sampler change is a prerequisite, not a
complete whole-proof 128-bit result. Concrete Fiat-Shamir/RO analysis, hash-binding
assumptions, independent MW adaptation review and the matched baseline remain
open. The backend stays explicitly experimental and unpromoted.

## Complete foreign-trace forgery validation

The native test module `complete_foreign_trace_case` reconstructs the complete
version-2 prover from component APIs over BabyBear and Goldilocks. Each field
runs one honest control and three independently regenerated malicious proofs. It uses a valid
native witness from one ciphertext, changes a requested input mask by a modulus-
switch rotation step, and confirms that the correct native output for that new
ciphertext differs from the forged output. The false statement is therefore
checked explicitly, rather than relying only on a changed transcript message.

Every child proof is regenerated after the requested complete parent context is
bound. The monomial child also binds the requested plan and expected coefficient
roots. Its malicious ZeroCheck uses the actual foreign public rotation factor.
Two additional variants keep the native inputs fixed but change either the
expected output body or the last retained output-a coefficient. Their key-switch
child binds that requested output and uses the actual native extraction target
only inside the malicious ZeroCheck.
An independent transcript replay verifies every Hadamard, NTT, decomposition,
accumulator, monomial ZeroCheck/private PCS opening and final key-switch proof
when supplied that actual factor. The complete production verifier instead
computes the requested public rotation/extraction factor and rejects at its
terminal equation. The output variants check that rejection occurs specifically
in final key switching.
The test checks the exact rejection class, serializes/deserializes the assembled
proof and includes an independently assembled honest positive control that the
production verifier accepts. This guards against a false positive from framing,
stage order or serialization drift. No honest child proof is merely replayed
under a different prefix.

```sh
RAYON_NUM_THREADS=16 cargo test -p vfhe --test packed_pbs --locked
```

All four native suites pass: two independent-proof suites with fresh groups
1/4/16 and two complete malicious-construction suites. Production prover/verifier
code is unchanged in this validation step. Whole-proof security and independent
adversarial review are still open; the tests do not establish either.

## Source snapshots and lockfile recovery

`tools/archive_sources.py` captures Git's tracked/untracked source inventory and
explicitly adds the ignored `Cargo.lock`. Its embedded bytes are returned to the
benchmark script for the sidecar copy and hash check. Existing archives are not
overwritten. Source capture tests check the ignored lock, untracked source,
excluded artifacts, preservation of existing archives and missing-lock failure.
The benchmark records the archive hash and rejects a lock change during capture.

The original complete artifact benchmark already preserved its Cargo.lock as a
sidecar. Ten later manually captured component snapshots recorded a lock hash
but omitted the ignored file. They now have `Cargo.lock`/`lockfile.sha256` sidecars
whose bytes match those originally recorded hashes exactly. One group uses the
existing baseline sidecar; the other is recovered by removing only the newly
added `vfhe -> sumcheck` development dependency from the current lock. Equality
with the pre-existing SHA-256 is required before any recovery is accepted.
Original archives and provenance records remain unchanged. The recovery audit is
`target/performance/lockfile-recovery.json`.

The current test/source snapshot embeds its exact lock and is preserved under
`target/performance/complete-forgery/`. Twenty Python tool tests pass, including
the archive checks. This repairs reproducibility packaging; it makes no new
cryptographic or performance claim.

## Fresh complete global-key and endpoint audit

The shared malicious-prover fixture in
`vfhe/tests/support/packed_pbs_forgery.rs` now assembles ten complete certificates
for each BabyBear/Goldilocks and version-2/version-3 combination. Four honest
assembled controls are accepted; all 36 false certificates are rejected after
serialization. Eight additional honest native proofs validate the two underlying
traces in each combination. The final filtered run passes all four test functions
and emits forty `HB_BINDING_CASE` records with exact per-case coverage.

The six added cases are:

- A foreign trusted blind-rotation key with the original witness key.
- A foreign trusted key-switch key with the original witness key.
- A changed public initial body with the original accumulator trace.
- A changed final accumulator body and matching changed public output body,
  preserving the final key-switch equations while violating the shared endpoint.
- A splice between two valid traces at an internal active-round boundary.
  Every local round relation remains valid, the initial/final endpoints match,
  and only accumulator continuity fails.
- Canonical digit/decomposition sources from one valid trace combined with
  accumulator sources from another, giving disagreeing views of the witness.

These extend the original wrong-input-mask, wrong-output-body and
wrong-retained-output-coefficient cases. Each requested public setup, statement,
root set and endpoint is fixed before newly generating the children. The
independent replay checks every local algebraic child and authenticates every
supplied opening against its actual source root. For a foreign-key case, the
relation domain declares the requested trusted roots, while the actual-source
opening still belongs to the witness key. The replay does **not** claim a valid
opening against a different root: production must reject that mismatch when it
uses the trusted key. Both key cases fail at matrix-weighted PCS authentication;
the switching-key case also confirms the final-stage error context.

For accumulator cases, the test independently derives the ordered row-selection,
carry-partition and half-selection queries under the requested endpoints. It
verifies every resulting canonical opening while bypassing the claimed
accumulator equation. Production rejects the initial/final/view cases at the
arithmetic/duplicated-half/endpoint check and the spliced trace specifically at
round continuity. The independently assembled honest control is accepted by the
production complete verifier, protecting against a framing mismatch that would
turn these into weaker transcript-replay tests.

Fixtures use native N=32, LWE dimension 21 (including inactive padding), widths
4/8 for lane/extension versions and two independently generated test keys.
This audit changes test code only; it does not change the benchmarked prover or
verifier. Exact logs, coverage JSON, source/lock snapshots and hashes are under
`target/performance/packed-binding-audit/`. Independent adversarial review and the
whole-proof security argument remain open.

## MW-Basefold scheduling constraint

[2025/719, Appendix D.1](../../refs/2025-719.pdf), printed pages 52–53, places the
folding commitment and its query checks **between** successive packed-sumcheck
challenges. The committed oracle is fixed before the next challenge; after each
fresh challenge vector the prover commits the resulting folded oracle before
receiving later vectors. The final small codeword is decoded and the remaining
log2(k) packed rounds are completed locally.

The current MW-Brakedown `open` API receives a complete matrix query after
sumcheck has finished. Building all Basefold roots at that point does not inherit
the paper's interleaved-protocol guarantee. A paper-backed comparison therefore
needs a streaming round interface that fixes each fold root before future
challenges, or a separate argument for an after-query protocol. Its block layout
must also preserve this repository's little-endian variable order and ordered
matrix products; a noncommuting reference test is required before timing it.

The paper's structured guarantee uses the packed-sumcheck challenge distribution.
It must not silently be applied to the GF-multiplication matrices in the new
extension lookup bridge. That use needs its own proximity/binding argument. The
following section describes the subsequently implemented streaming reference.
The schedule requirement alone does not establish its security.

## Streaming structured MW-Basefold implementation

`pcs::mw_basefold` now implements the Appendix D.1 construction as a separate
streaming primitive. Initial coefficients group the last log2(k) Boolean
variables into symbol coordinates, while the low variables index polynomial
coefficients. Each symbol is a row-major k-by-k array of base-field scalars.
Odd-power coset RS encoding is foldable under the paper's diagonal-generator
condition: paired evaluations at x/-x recover the even/odd parts before applying
the freshly supplied lane matrices. No extension-field multiplication is used.

`sumcheck::packed::prove_with_rounds/verify_with_rounds` and the corresponding
`packed_zero` functions expose callbacks after every fresh challenge, including
ZeroCheck's special first round. Oracle roots and query responses enter the
transcript before the next challenge. Existing APIs use empty callbacks and
retain the original framing; an independent transcript replay checks this.
The new `snarks::packed_basefold` relation driver derives the structured challenge
pairs itself, streams every canonical factor through that schedule, and checks
the final relation against decoded/authenticated values. It accepts no external
matrix query or verifier witness table.

The prover borrows reusable original state and retains only the current folded
word. Whole block symbols are Merkle-authenticated with field/parameter/layer/
index separation. All independent with-replacement query draws are retained;
only duplicate certificates are removed, in first-occurrence order. Exact query
counts, dimensions, path depths and final-tail presence are checked. The final
constant codeword is reconstructed against its root, decoded into the remaining
Boolean table, and folded locally for the last log2(k) challenges. Lazy prime-field
representatives are normalized when constructing committed words so constant
codewords have deterministic wire representations.

Independent Horner evaluation, re-encoding of directly folded tables and
noncommuting matrices test the index/order convention over BabyBear and
Goldilocks, widths 1/2/4/8 and zero/nonzero oracle-round counts. Fresh high-degree
oracles with genuine Merkle paths are rejected at the fold equation, despite a
genuine constant final root. Fresh false-source relation certificates have valid
ZeroCheck children and streamed openings under the actual root/transcript, then
fail the production terminal relation. The callback tests also check failure
propagation and that oracle messages change future challenges.

Native comparison examples are `mw_basefold_babybear` and
`mw_basefold_goldilocks`; `--brakedown` selects the existing backend. Both prove
only the external-product Hadamard relation of the same actual native PBS trace,
with matching factor/ciphertext and FHE-configuration digests. They serialize
both the roots and complete component proof, check those roots against the
expected commitments, and verify after decoding. Commitment construction and
proof/serialization/verification are timed separately. Reused proof times are
measurements with already committed factors, not complete PBS latency.
`tools/compare_mw_basefold.py` alternates saved binaries/modes, checks exact
fixtures and profiles, and explicitly labels the comparison experimental.

This reference is non-hiding and is not integrated into complete PBS. A shared
query count/rate is not a security-matched choice between the two protocols.
Concrete proximity/composition/Fiat-Shamir analysis, independently reviewed
adaptation and a GF-query argument remain open. In particular the structured
matrix distribution is supplied only by the coupled packed driver; this code
must not be used as an after-query GF-bridge PCS while citing Appendix D.1.

The native comparison is now measured in two alternating-order sessions. The
reference verifies but loses on reused proving time and proof size at the common
experimental settings; Brakedown remains selected. See `performance-results.md`
for exact timings, scope, validation and source/binary provenance. This does not
close the security-matched analysis or authorize complete-PBS integration.

## Masked scalar PipFRI reference

`pcs::pipfri::masked` is separate from the current scalar adapter and complete
packed PBS versions. It removes the individual fragment evaluation vector,
authenticates a virtual initial batch from the source commitment and reuses
rolling FRI queries for public-fold consistency. A cumulative opening budget
limits mask reuse. See [masked-pipfri.md](masked-pipfri.md) for its tested
numerical disclosure model and remaining security/integration requirements.

```sh
cargo test -p pcs --lib masked --locked -- --nocapture
cargo build --release -p pcs --example masked_pipfri --locked --jobs 2
RAYON_NUM_THREADS=16 target/release/examples/masked_pipfri babybear-ext5 21 14 64 4
RAYON_NUM_THREADS=16 target/release/examples/masked_pipfri goldilocks-ext5 21 14 64 4
```

These are synthetic scalar-table smokes with fresh private masks and direct
extension-field transcripts. A query count of 64 asserts no concrete security
level. They must not be compared to complete PBS or called a security-matched
comparison with the earlier non-hiding reference.

The separate scalar adapter is available as
`pcs::multilinear::masked_pipfri::MaskedPipFRIPCS`. Its private locked state
enforces a single lifetime budget across all trait calls, including concurrent
batches. Trait verification is stateless; it checks bounded indices and ordered
batches, while ordered replay detection requires the core verifier session.
Checked opening methods reject invalid batch geometry/capacity before transcript
mutation. Small tables use dummy-coordinate repetition.

```sh
cargo test -p pcs --test masked_pipfri_adapter --locked --jobs 2
cargo test -p snarks --test masked_pipfri_adapter --locked --jobs 2
```

Those tests establish scalar-interface and LogUp integration over both quintics.
They do not measure a complete masked PBS or establish that the enclosing
SNARK is zero knowledge. Adapter validation is archived separately under
`target/performance/masked-pipfri-adapter/`; the earlier scalar smoke retains its
original source snapshot.

## Native masked PipFRI wrapper experiment

```sh
cargo build --release -p vfhe --example masked_pipfri_pbs_babybear --example masked_pipfri_pbs_goldilocks --locked --jobs 2
RAYON_NUM_THREADS=16 RUST_LOG=info target/release/examples/masked_pipfri_pbs_babybear --iterations 2 --warmups 0 --seed 42
RAYON_NUM_THREADS=16 RUST_LOG=info target/release/examples/masked_pipfri_pbs_goldilocks --iterations 2 --warmups 0 --seed 42
```

These experiments select the degree-five adapter for all existing scalar native
wrappers. Each cached-key iteration consumes one opening of the same private
mask session. The default capacity is four total iterations, including warmups;
`--opening-budget`, `--fragment-vars` and `--queries` explicitly select another
geometry, which must pass the mask-capacity check. `--cold` requests a fresh
commitment each time. The benchmark rejects excess reused-key iterations rather
than refreshing masks silently. Before/after counters and the proof index are
recorded with actual fixture and native key hashes.

The verification scope is `legacy-four-stage-wrapper-in-memory`. The wrappers
serialize a tuple for byte accounting and verify the retained in-memory proofs;
they still carry witness-derived evaluation fields skipped by serialization.
Their key/global/endpoints binding and standalone verifier remain separate work.
This is neither the complete packed-PBS protocol nor security-matched evidence
for promotion. Preserve the original FHE settings and output key when comparing
future implementations.

The current masked implementation parallelizes independent fragment FFTs and
packed-leaf hashes, and tiles linear combinations into disjoint output blocks.
Random draws and per-coordinate addition order are preserved. The archived
sequential scalar/native binaries remain under `masked-pipfri-reference/` and
`masked-pipfri-native/`; the parallel source, binaries, test logs, commands and
comparison records are separate under `masked-pipfri-parallel/`. Reproduce the
same scalar/native commands above with 16 threads. The wire/entropy compatibility
checks run as part of:

```sh
cargo test -p pcs --lib parallel_schedule --locked --jobs 2
```

Scalar comparisons use four openings per commitment in two reversed process
orders. The native comparison has one first/reused process per field for each
implementation and retains the legacy in-memory verification scope. Neither
comparison supplies the missing whole-proof security/binding gates.

## Ordered matrix scalar-opening research reference

`snarks::packed_scalar_opening` batches arbitrary ordered base-matrix responses
through a public matrix-product kernel, a degree-two sumcheck and one original
masked scalar opening. It has a standalone public-input verifier and a
conditional interactive reduction argument. The first-coordinate projection
contract is explicit; the bridge is demonstrably non-hiding. It is not selected
by complete PBS and has no native timing or security-matched comparison yet.

```sh
cargo test -p snarks --lib packed_scalar_opening --locked --jobs 2
cargo test -p pcs --test masked_pipfri_adapter --locked --jobs 2
```

See [packed-scalar-opening.md](packed-scalar-opening.md) for matrix order, the
conditional bound, base projection, the Goldilocks exact-value API regression
and the hiding counterexample. Evidence is separate under
`target/performance/packed-scalar-bridge/`. Direct packed PipFRI research and
complete canonical-root/statement integration remain open.

The bridge capacity benchmark compares identical public tables, query matrices
and responses through both implementations. It commits once and opens batches
of 1/4/16; commitment time is repeated as metadata, not charged per opening.

```sh
cargo build --release -p snarks --example packed_scalar_opening --locked --jobs 2
RAYON_NUM_THREADS=16 target/release/examples/packed_scalar_opening babybear brakedown 18 64
RAYON_NUM_THREADS=16 target/release/examples/packed_scalar_opening babybear bridge 18 64
RAYON_NUM_THREADS=16 target/release/examples/packed_scalar_opening goldilocks bridge 18 64
RAYON_NUM_THREADS=16 target/release/examples/packed_scalar_opening goldilocks brakedown 18 64
```

The saved `packed-scalar-comparison/commands.json` repeats both fields in reversed
backend/process order. The 18-variable/eight-lane table has 2^21 scalar entries;
this is native capacity, with synthetic values and dense independent queries.
Both settings remain unbudgeted. Claim construction is reported separately,
while bridge proving includes its witness/claim preflight, weight expansion,
sumcheck and scalar opening. Certificates contain the entire reduction proof;
verification uses decoded proofs and retained expected roots. Raw bytes favor the
bridge at large batches, but proving is about 62x slower at 16 queries. Keep
MW-Brakedown on the complete path; no bridge integration is justified by this
experiment. See `performance-results.md`.

## Goldilocks cubic lookup and four-lane profile

An opt-in complete-PBS profile now uses `GoldilocksExtension3`, defined by
X^3-7, and four base-field lanes. Independent irreducibility/arithmetic and
transcript-byte references cover the new field; no primitive generator is
asserted. The existing quintic/eight-lane default is retained. The shared example
accepts `--width`; extension helper layouts require width at least the degree.
Native FHE parameters and keys remain unchanged (ring 1024, LWE 728).

```sh
cargo build --release -p vfhe --example packed_extension_pbs_goldilocks3 --locked --jobs 2
RAYON_NUM_THREADS=16 RUST_LOG=info target/release/examples/packed_extension_pbs_goldilocks3 --full --iterations 2 --width 4
PYTHONPATH=tools python3 tools/compare_extension_profiles.py target/performance/goldilocks-cubic-pbs
```

The saved comparison uses two reversed profile orders, each with a first/reused
proof, serialized public verification and decryption checks. Its strict analyzer
checks actual FHE/key/statement hashes, per-profile deterministic proof bytes,
all four oracle layouts and the complete interactive bound inventory. The
archived/default quintic toy control reproduces identical proof bytes. The
inventory includes degree-three algebra and width-four base PCS obligations;
it does not supply the missing Fiat-Shamir/composition analysis or a
security-matched baseline. See `performance-results.md` for measured costs.

## Native fresh-input validation groups

The complete extension PBS examples accept `--validation-batches`, which runs
21 independent proofs in groups of 1, 4 and 16 with one preprocessed key. Every
case encrypts fresh inputs; the four-case and sixteen-case groups cycle through
all four NAND plaintext pairs. Every output is decrypted, and every complete
proof is serialized, decoded and checked by the public verifier. Encryption is
outside the complete-PBS timer. `batch_size` remains 1: these are not aggregated
proofs. Group size/index, plaintexts and the decrypted result are explicit log
metadata. This mode rejects `--iterations` to keep the schedule unambiguous.

```sh
RAYON_NUM_THREADS=16 RUST_LOG=info target/release/examples/packed_extension_pbs_babybear --full --validation-batches --width 8 > babybear-batches.log
RAYON_NUM_THREADS=16 RUST_LOG=info target/release/examples/packed_extension_pbs_goldilocks3 --full --validation-batches --width 4 > goldilocks-batches.log
PYTHONPATH=tools python3 tools/validate_full_batches.py babybear-batches.log --field babybear --output babybear-batches.json
PYTHONPATH=tools python3 tools/validate_full_batches.py goldilocks-batches.log --field goldilocks --output goldilocks-batches.json
```

The strict analyzer requires exactly the ordered 1/4/16 schedule, distinct
statement/proof digests, unchanged native keys/FHE parameters/preprocessing,
all four trusted oracle layouts, native dimensions, NAND truth-table results
and complete decoded verification. It checks per-proof interactive bounds and
reports their sum across all 21 proofs separately. `--reference-log` additionally
checks actual native parameter/key hashes against a prior complete run.
It does not interpret a
per-proof threshold as an equal-strength joint batch guarantee. Fiat-Shamir,
independent composition review, security-matched baseline and aggregated batch
validation remain separate gates. Saved artifacts are under
`target/performance/full-native-batches/`.

## Stronger BabyBear interactive batch profiles

`BabyBearExtension6` uses the independently checked polynomial X^6-31.
It supplies polynomial-basis arithmetic, without a claimed primitive generator
or a composed security certificate. Degree six and the existing degree eight
can use `--helper-left-extra 1`, which shifts both helper splits one variable
from columns to rows. The encoder retains its minimum 32-symbol domain.
The original quintic/eight-lane default and native FHE parameters are unchanged.
The shift is an explicit part of the stronger profile; selecting the degree-six
example alone does not select it.

```sh
cargo build --release -p vfhe --example packed_extension_pbs_babybear6 --example packed_extension_pbs_babybear8 --locked --jobs 2
RAYON_NUM_THREADS=16 RUST_LOG=info target/release/examples/packed_extension_pbs_babybear6 --full --validation-batches --helper-left-extra 1 > babybear6-batches.log
PYTHONPATH=tools python3 tools/validate_full_batches.py babybear6-batches.log --field babybear --profile babybear6-helper1 --output babybear6-batches.json
```

The analyzer's stronger profiles (`babybear6-helper1` and `babybear8-helper1`)
require the actual native helper geometry, correct field degree/shift metadata,
and a summed interactive error no greater than 2^-128 across all 21 proofs.
This conditional interactive gate does not replace Fiat-Shamir/composition
analysis. Reversed-order degree-five/six/eight controls and selected-profile
fresh-input validation are saved under
`target/performance/babybear-batch-budget-pbs/`; see `performance-results.md`.

## Degree-six multiplication kernel

The degree-six field multiplies A=A0+X^3 A1 and B=B0+X^3 B1 using three
quadratic-polynomial products. Each uses six base products. The cross term is
(A0+A1)(B0+B1)-A0B0-A1B1; five high coefficients then reduce with X^6=31.
The implementation uses stack arrays and leaves the other extension-degree
branches unchanged. Its field tests compare all basis products, boundary cases
and 512 deterministic random pairs with independent integer-polynomial arithmetic
and the previous kernel's serialized output.

Complete before/after comparisons, with reversed process orders and 16 threads,
are saved under `target/performance/sextic-kernel-pbs/`. The runner requires
identical actual FHE/key/statement hashes, layouts, proof bytes and conditional
interactive inventories before accepting a speedup. Fresh 1/4/16 validation
additionally compares every proof hash with the archived degree-six profile.
No FHE or protocol parameters change. See `performance-results.md` for measured
results; whole-proof security/composition and aggregation gates remain open.

## Common conditional-target lane/extension comparison

The BabyBear lane baseline can use the same shifted-helper geometry as the
optimized degree-six extension path. Both keep width eight and 544 raw column
queries, with all four PCS layouts identical. Their repetition/field choices
differ: version-two lanes use 16 base-field pairs, while version-three extension
lookups use one full degree-six pair. The selected conditional interactive
inventory must sum to no more than 2^-128 over 21 complete proofs for either
profile. This is not a reviewed whole-proof security match.

```sh
RAYON_NUM_THREADS=16 RUST_LOG=info target/release/examples/packed_extension_pbs_babybear6 --full --lanes --helper-left-extra 1 --iterations 2
RAYON_NUM_THREADS=16 RUST_LOG=info target/release/examples/packed_extension_pbs_babybear6 --full --helper-left-extra 1 --iterations 2
PYTHONPATH=tools python3 tools/compare_joint_target_profiles.py target/performance/joint-target-pbs
PYTHONPATH=tools python3 tools/validate_full_batches.py target/performance/joint-target-pbs/native-lanes-fresh.log --field babybear --profile babybear-lanes-helper1 --output target/performance/joint-target-pbs/native-lanes-fresh.json
```

The saved runner executes lane/extension and extension/lane orders, then the
native fresh 1/4/16 lane schedule. Comparison checks complete decoded verification,
actual FHE/key/statement hashes, fixed layouts, stable per-profile proof hashes
and each profile's full conditional target. It reports latency/byte engineering
gates separately from the missing Fiat-Shamir, extraction, composition, hiding
and promotion analysis. See `performance-results.md` for the measured evidence
and `block-rs.md` for the source-to-implementation audit boundary.
