# Public monomial product and initialization

`snarks::packed_monomial` proves the negacyclic multiplication
`monomial_product[t] = X^rotation[t] * input_acc[t]` against the two canonical
coefficient commitments already used by `packed_accumulator`. A trusted `Plan`
fixes N, the public rotations, and padding to M rows. Both RLWE halves use the
same rotations; padded public-factor rows are zero.

The proof derives two NTT commitments, fixes them before challenges, and links
each to its original coefficient root through `packed_ntt`. Packed ZeroCheck
then checks input-NTT times public-monomial-NTT equals product-NTT. Both private
terminal vectors have authenticated openings. The verifier computes the public
terminal itself; no prover-supplied monomial root or terminal is trusted.

For a native bit-reversed NTT, a monomial's entry at index i is
`root^(rotation * (2*bit_reverse(i)+1))`. Each active row's lane vector starts
with the low-index contribution. Ordered coefficient matrices fold each
remaining bit, multiplying its one branch by the appropriate root power.
Row matrices then fold the M row vectors, and the final half matrices add the
two identical halves. This costs O(M*k^2*log(N/k)), rather than materializing
both full N*M arrays on the verifier. Dense noncommuting matrix references over
BabyBear and Goldilocks check the native order, including k=1, k=N, sign changes
at rotation N, and partial row padding.

## Public NAND preprocessing

`Plan::from_field_mask` exactly switches the public mask to modulus 2N.
`nand_lut` uses the native q/8 NAND LUT and configured stride;
`initial_accumulator` rotates its b polynomial by minus the switched public
body, with zero a polynomial. The native example's `--with-monomial` computes
these from x+y and trusted FHE parameters and supplies the resulting initial
polynomial to the accumulator proof. Keys, final extraction/key switching and
complete PBS statement composition remain outstanding.

The shared `algebra::modulus_switching::round_modulus_u128` computes nearest
integer rounding with half ties upwards, including an overflow-safe wide path.
All four native FHE-core modulus-switch entry points use it. The previous f64
implementation rounded `(p-1)/(2*2048)` upward for Goldilocks because conversion
loses the +1 in p; the exact result is zero. This is a correctness fix to rare
boundary behavior. The original FHE parameter sets are unchanged.

## Error inventory and validation

The interactive component model unions two NTT row tests, two NTT coefficient
compression tests, one quadratic packed ZeroCheck, six opening random tests,
and all response proximity events. Repeated roots still count separate tests.
NTT batch queries share one W response per root only when the left PCS prefix
fits entirely within coefficient variables; otherwise the budget uses k W
responses per NTT opening. This does not establish composed PBS or Fiat-Shamir
security.

The adversarial test creates genuine NTT proofs and PCS openings under the
requested transcript prefix while using a different monomial. All child proofs
are valid for the actual factor; the requested public-factor equation rejects
it. Tests also alter roots, terminals, proof counts and opening authentication,
check serialization, and exercise exact public rounding boundaries.

```sh
RAYON_NUM_THREADS=16 cargo run --release -p vfhe --example packed_pbs_hadamard -- --with-monomial
RAYON_NUM_THREADS=16 cargo run --release -p vfhe --example packed_pbs_hadamard -- --full --with-monomial
python3 tools/packed_budget.py --monomial-component target/performance/public-monomial/full.log
```

The flag includes the lane decomposition, NTT and accumulator components on the
same roots. Its timings and bytes are component measurements, not complete PBS
performance or a promoted backend.

## Recorded native smoke

At the original BabyBear dimensions (N=1024, LWE dimension 728, k=8), the linked
release run verifies with 16 Rayon threads. The new monomial proof adds
21,747,637 bytes and takes 0.698 s to prepare/prove/verify/serialize. The full
set of implemented components totals 608,029,435 bytes, takes 51.72 s process
wall time, and peaks at 4,804,160 KiB RSS. These are one-session component smoke
measurements; they exclude the unimplemented final stages and key binding.
The monomial-only interactive model totals approximately 1.435e-42, excluding
composition and Fiat-Shamir. Logs, executable copies, source archive and hashes
are under `target/performance/public-monomial/`.

The regression run passes 132 Rust tests across algebra, FHE core, sumcheck, PCS,
PIOP and SNARK crates, plus nine Python tests. Both the small native and original
BabyBear fixtures verify with the public-input monomial flag.
