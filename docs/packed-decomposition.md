# Canonical packed decomposition

`snarks::packed_decomposition` proves a complete canonical radix decomposition
against caller-supplied source and digit commitments. It combines a packed linear
identity check with repeated public tuple lookups. It does not recompute a
private source in the verifier or accept an unlinked digit view.

For radix B=2^b, the digit count d derives from the field characteristic p.
The shared linear check proves `x = sum_i B^i * digit_i` in the field. This alone
would allow the integer digit string x+p, so it is not sufficient.

To prove an integer value below p, auxiliary borrow columns describe subtraction
of the digits from p-1. At each limb the public table contains precisely
`(digit, borrow_in, borrow_out)` with `0 <= digit < B`, both borrows Boolean, and
`borrow_out = (digit + borrow_in > (p-1)_i)`. The linear check also proves that
the first and last borrow columns are zero. These conditions make the integer
digit string at most p-1. Combined with field reconstruction, it is the canonical
integer representative of x. The table avoids any assumed no-wrap condition on
a field arithmetic implementation of the borrow recurrence.

All source/digit roots, trusted radix and length are bound before auxiliary
challenges. All borrow roots precede the linear check and tuple proofs. Each
transition refers to the same borrow root as its neighbor, and each tuple proof
uses exactly the digit root consumed by NTT/Hadamard relations. A valid tuple
proof for a different final-borrow root cannot satisfy the enclosing statement.
Linear reconstruction includes padding; tuple membership covers the configured
active prefix. Use consistent zero padding in canonical trace extraction.

## Linear check

`snarks::packed_linear` fixes all roots and trusted linear relations before
sampling one common ordered matrix query. It authenticates every source vector
and checks every specified relation separately at that point; there is no weak
single-field random combination of different constraints. For a fixed nonzero
residual table, one fold becomes zero with probability at most
`((2k-1)/p)^k`: its interpolating polynomial is nonzero and the k lane challenges
are independent. Union bound over mu folds gives `mu*((2k-1)/p)^k`, before PCS
and Fiat-Shamir errors. Multiple fixed relations share the same query; if any
is false, choose a fixed nonzero residual before challenges.

## Tuple lookup

`snarks::packed_tuple_lookup` extends reciprocal lookup directly over original
canonical columns. Original tuple multiplicities are fixed before all
independent (Y,r) pairs. Y hashes a tuple as `a_0 + Y*a_1 + ...`; r excludes zero
and all negative hashed public entries. All reciprocal roots are committed before
algebraic challenges. Packed sumcheck checks their total against public-table
multiplicities; a cubic masked ZeroCheck uses the original columns directly:
`f * (r + mask * sum_j Y^j*a_j) = mask`. No compressed-source view is committed.
Each helper's sum/ZeroCheck openings are batched; all ZeroCheck queries against
each original source root are authenticated together.

This is a conservative adaptation of the vector lookup in Appendix H.1 of the
local small-prime-fields paper. Fix one bad original row and a table of M distinct
l-tuples. Its hash collides with some public tuple with probability at most
`M*(l-1)/p`. Otherwise, with N<p, its invalid hashed pole has nonzero multiplicity,
so no fixed public-table multiplicities can make the rational functions equal.
Conditional on Y, a false rational identity agrees at r with probability at most
`(N+M-1)/(p-M-1)`. Independent pairs give the conservative lookup-only bound
`(M*(l-1)/p + (N+M-1)/(p-M-1))^s`. Hash collisions among public entries only reduce
the number of excluded r values; using M+1 exclusions is conservative.
This argument deliberately separates tuple collision error from packed lane
amplification. Add sumcheck, ZeroCheck, PCS and Fiat-Shamir contributions.

## Native integration and validation

`packed_pbs_hadamard --with-decomposition` links the native external-product
input halves, duplicated into the physical layout of the digit factors, to the
exact digit coefficient roots used by NTT checks. It replaces standalone range
checks with canonical borrow-transition lookups. The external-product inputs
still need provenance from accumulator relations; keys, continuity and public
ciphertext endpoints require the enclosing complete PBS protocol.

```sh
RAYON_NUM_THREADS=16 cargo run --release -p vfhe --example packed_pbs_hadamard -- --with-decomposition
RAYON_NUM_THREADS=16 cargo run --release -p vfhe --example packed_pbs_hadamard -- --full --with-decomposition
python3 tools/packed_budget.py --decomposition-component target/performance/packed-decomposition/full.log
```

The component budget includes tuple hash/rational tests, every repeated sumcheck
and ZeroCheck, shared helper/source opening responses, and canonical linear
checks/openings. It does not establish a complete PBS or Fiat-Shamir budget.
Original FHE dimensions and output-key behavior of trace generation are retained.

Regression tests cover BabyBear and Goldilocks boundaries 0,1,p-1,p-2, radix
boundaries, malformed proofs, changed canonical roots/coefficients, partial
padding, and congruent noncanonical strings p and p+1. Joint tuple membership
rejects data whose separate marginal columns are valid. A composition test
constructs genuine reconstruction and tuple subproofs using inconsistent final
borrow roots and verifies that the enclosing proof rejects them.

## Recorded validation

The five-crate Rust run (algebra, PCS, sumcheck, PIOP and SNARKs, libraries and
integration tests) passes 112 tests. Six Python tool tests pass. The native toy
and original-size release examples both verify canonical decomposition and NTT
linkage using seed 42 and 16 threads.

At original BabyBear FHE sizes, the canonical decomposition component adds
1,162,351,774 bytes and takes 66.693 s including preparation, commits, proving,
verification and serialization. With Hadamard and NTT it totals 1,347,164,944
component bytes. The whole process takes 73.39 s and peaks at 5,806,732 KiB RSS.
These single smoke results demonstrate correct composition of these components,
not the requested complete-PBS performance target.

The emitted-shape interactive component budget totals 8.1157e-41, below 2^-128,
including tuple collision/rational terms and linear-check obligations. The
remaining PBS stages and Fiat-Shamir analysis are not covered. Logs, exact
budget JSON, saved binaries and source/binary hashes are under
`target/performance/packed-decomposition/`.

The new tuple test exposed an existing lazy-representation Goldilocks bug:
exponentiation asserted that a lazy inversion intermediate was canonical.
Reduction now maps p to zero, negation and exponentiation normalize their inputs,
and inversion normalizes before its zero check. Boundary and signed-denominator
regressions pass. The original complete Goldilocks artifact PBS also verifies
with its 64-bit code specification after this fix (one seed-42 release smoke,
artifact-unbudgeted security label retained).

The independent repeated-helper construction remains available as a reference.
`prove_lanes/verify_lanes` now batch independent pairs into helper lanes without
committing broadcast sources; the native example enables it with `--lane-lookups`.
The original-size smoke reduces canonical decomposition to 376,277,702 bytes and
53.253 s; full-PBS promotion is still outstanding. See
`lookup-batching-design.md` for the mapping, separate-domain budget and evidence.

## Experimental extension-field comparisons

`packed_extension_lookup` runs the tuple rational identities in an extension
field while authenticating each terminal claim against the existing base-field
matrix-weighted commitments. `packed_decomposition::prove_extension` /
`verify_extension` compose it with the same canonical radix reconstruction and
borrow endpoints. The lane and independent APIs retain their existing proofs.
`ExtensionProof<F, EF, O>` is an opt-in proof type; this backend is not selected
by complete packed PBS.

For width k >= extension degree D, a helper cell stores the D basis coefficients
of one extension value. Unused committed lanes are ignored by projection. A
matrix represents multiplication by an extension scalar in that basis. For a
canonical scalar source, the low log2(k) coordinates first select the scalar
lanes; the remaining coordinates select Boolean cells. The lane-selection map
must multiply the first pair on the **right**, because query products act as
`M_last ... M_0 T`. Constant sources authenticate the original vector before
applying T locally. No compressed-source or broadcast-source root is introduced.

Each configured repetition is one independent extension pair (Y,r), with full
coefficient-wise sampling. It is not D independent base-field repetitions.
Multiplicities and original roots precede the pairs, and all reciprocal roots
precede the algebraic challenges. A 64-byte seed from the base-field parent
initializes a direct-extension child. The child's final 32-byte digest binds its
roots, algebraic messages and terminal claims back into the parent before the
base-field PCS challenges. This transcript composition still needs analysis.

On the full domain, ordinary extension-field sumcheck checks the cubic identity
`Eq_R * (H * (r + G) - 1)`. For an active prefix with public mask m, it checks
`Eq_R * (r*H + m*G*H - m)`, of degree four. Since r excludes zero, the latter
forces H=0 outside the prefix even when inactive source values are poles. Simply
multiplying the entire reciprocal identity by m would fail to constrain those
helper entries. The other sumcheck checks sum(H) against the fixed public-table
multiplicities. All terminal source values and both helper values are opened
through the canonical base-field PCS.

The tuple/rational argument above uses q=|EF| in place of p for its challenge
probabilities; the noncancellation requirement on integer row multiplicities
still uses the **base characteristic** p. A field of order p^D does not change
that characteristic. Sumcheck, equality reduction, canonical reconstruction,
PCS, transcript composition and Fiat-Shamir terms must also be counted before
any whole-proof security claim. The existing complete-PBS budget script does
not budget this opt-in backend.

Tests cover BabyBear and Goldilocks quintics, independent scalar MLE evaluation,
nonzero ignored helper padding, a noncommuting wrong-order counterexample,
constant sources, multiple widths, full/partial domains, wire roundtrips,
malformed sumcheck dimensions, changed roots and changed terminal claims.
Private adversarial tests generate fresh false-source proofs with genuine
sumchecks and genuine helper/source openings under the actual requested source
root. A reference replay confirms those children verify; the public terminal
identity rejects the forgery. Canonical decomposition tests additionally cover
0,1,p-1,p-2, radix boundaries, swapped limb proofs and changed repetition counts.

A synthetic borrow-transition profiler is available:

```sh
cargo build --release --locked -p snarks --example extension_lookup
RAYON_NUM_THREADS=16 target/release/examples/extension_lookup babybear extension 18
RAYON_NUM_THREADS=16 target/release/examples/extension_lookup babybear lanes 18
```

It reports proving phases, verification and serialized bytes after an actual
wire roundtrip. Sources have 2^21 scalar entries at source dimension 18 and
width 8, matching the dominant native lookup's capacity. These are deterministic
synthetic public-table tuples, not native PBS traces. The extension setting uses
one quintic pair and the lane setting uses sixteen base-field pairs. Their
comparison is an experimental component measurement, not a security-matched
complete-PBS result. Source preprocessing is outside its proving timer.

The first saved profiling session verifies twelve proofs: both backends over
both fields at source dimensions 12 and 18, then a reversed-order repeat at 18.
At the native capacity, the two pairs give:

| Field | Lane proving, seconds | Extension proving, seconds | Lane / extension bytes |
|---|---|---|---|
| BabyBear | 4.354 / 4.316 | 1.559 / 1.554 | 43,347,859 / 20,791,157 |
| Goldilocks | 5.760 / 5.673 | 2.210 / 2.210 | 76,723,649 / 36,533,387 |

This is about 64% and 61% less lookup proving time, respectively, with about
52% fewer serialized lookup bytes. The settings and scope above apply; these
numbers do not establish a complete-PBS speedup or equal composed security.
Artifacts are in `target/performance/extension-lookup-quintic/`, including
`summary.json`, per-run phase/RSS logs, the exact saved binary, Cargo.lock and
source archive. Source archive SHA-256 is
`3ab5def1e48da7e836bc0e75d0384fdbff0f8a871bbeb90aa8b23b71a79a2700`;
lock SHA-256 is
`293790853366e0bc0562752d17999bab335368dd6e0c33823f1afaee8c214718`.
The source snapshot precedes this results paragraph. Adding the malformed-message
test's bincode dev dependency accounts for the lock change from the earlier
extension-field snapshot. Older artifacts retain their own exact lockfiles.

The accompanying checks pass 19 SNARK library tests, 16 sumcheck library and
integration tests, 9 selected decomposition/extension integration tests and all
4 complete packed-PBS regression tests (48 total). The shared scalar sumcheck
verifier now rejects missing/extra rounds and wrong message dimensions before
indexing or transcript mutation; valid message/transcript formats are unchanged.

### Complete-PBS extension composition

`packed_pbs::prove_extension/verify_extension` now compose the extension backend
through every native NAND PBS stage, including the final key-switch canonical
negative-a decomposition. `ExtensionProof<F, EF, O>` carries checked protocol
version 3 and uses the parent domain
`HasteBoots complete binary NAND PBS extension comparisons v3`. The verifier
accepts only trusted public setup/PCS parameters, public ciphertexts and the
serialized proof. Default `prove/verify` continue to select version-2 lane
comparisons. Shared stage code selects the comparison backend without changing
the default proof's field order or transcript messages.

Trusted setup's repetition count is interpreted as independent GF pairs in the
extension API. The example selects one quintic pair; lane mode selects sixteen
prime-field pairs. These choices are explicit experimental parameters. They do
not assert a completed whole-proof security argument.

```sh
cargo build --release --locked -p vfhe --example packed_extension_pbs_babybear --example packed_extension_pbs_goldilocks
RAYON_NUM_THREADS=16 target/release/examples/packed_extension_pbs_babybear --full --iterations 2
RAYON_NUM_THREADS=16 target/release/examples/packed_extension_pbs_babybear --full --lanes --iterations 2
```

The new complete examples retain original FHE parameters and output dimension,
authenticate every PBS stage, and verify each proof after serialization. They
emit actual ciphertext, FHE-configuration, public evaluation-key and proof
SHA-256 digests. Initial and reused iterations share preprocessing and the same
public input fixture. The complete timer includes native evaluation, preparation,
all proof stages and serialization; key generation/preprocessing and verification
are separate. `tools/compare_extension_pbs.py` alternates the two protocol modes
and requires matching fixtures and all four physical PCS layouts. It explicitly
labels this as a comparison of different experimental protocols. The older
same-protocol comparison tool continues to reject cross-version pairing.

`tools/full_pbs_budget.py` accepts the version-3 metadata and inventories its
ordinary GF sumcheck, equality reduction, tuple/rational and base-field PCS
obligations. It uses q=p^D for extension challenges, p for characteristic and
base-field PCS tests, and exactly the configured GF repetition count. This is
an experimental interactive inventory; seeded child/parent composition,
Fiat-Shamir, hiding and the MW adaptation review remain outside its claims.

Complete original-size measurements now confirm the extension composition over
both fields: BabyBear reused complete time is 41.921→18.483 s and
41.298→18.384 s; Goldilocks is 104.714→48.252 s and 104.354→48.314 s in two
alternating-order sessions. Every proof verifies after serialization with exact
public fixture/key checks. Complete proof sizes drop by 30% / 33%. These are
experimental protocol comparisons with one reused observation per process;
security-matched promotion remains open. See `performance-results.md` and
`target/performance/packed-extension-pbs/` for complete scope and evidence.
