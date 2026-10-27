# Packed final key switching and output extraction

`snarks::packed_key_switch` proves the final native RLWE key switch and sample
extraction for N=next_power_of_two(output LWE dimension). Both original BabyBear
and Goldilocks parameter sets use this path. Configurations requiring the extra
native ring/chunk permutation are explicitly rejected; they are not silently
mapped to this path.

The input is the final a||b accumulator vector already consumed by the
accumulator continuity proof. This is a shared witness endpoint, not another
public ciphertext or a trusted native recomputation. The enclosing protocol must
supply exactly the same endpoint to both stages. The final output LWE ciphertext
is an expected verifier input, including its original unpadded dimension.

## Canonical sources and equations

Trusted public setup commits the switching key's native NTT RLWE columns in
least-significant-digit order, independently of the trace. Prover setup retains
the corresponding PCS tables/states for reuse. Expected verifier setup contains
only the configuration, parameter context and public key roots and cannot be
deserialized from untrusted proof bytes.

Private coefficient sources are d duplicated digit tables followed by the
key-product a||b sum table. All coefficient roots and their derived NTT roots
are bound before any subproof challenges. The protocol proves:

* d+1 coefficient/NTT links against those same canonical roots;
* the NTT sum of digit times expected public key equals the sum-product root;
* canonical integer decomposition of minus the final accumulator a polynomial,
  duplicated into both RLWE halves, using the exact same digit coefficient roots;
* the expected output coefficients equal the signed, reversed and truncated
  extraction of the sum's a polynomial;
* output b equals sum_b[0] + final_acc_b[0] + floor(q/8).

The input decomposition commitment is derived deterministically from the shared
endpoint. Verification computes this linear input layout and public extraction
mask; it does not evaluate a native key switch or PBS. Digit bounds and integer
canonicity use the existing lane-batched borrow-transition lookups.

For output index i>0, extraction requires `sum_a[N-i] = -output_a[i]`; index zero
requires `sum_a[0] = output_a[0]`. Other a entries correspond to truncated padded
output coefficients. The b constraint uses only coefficient zero. A quadratic
packed ZeroCheck checks the masked sum against the public target, and its source
terminal is opened against the same coefficient sum root used by the NTT proof.
No independently committed extraction view is introduced.

The shared relation prover now accepts borrowed PCS states from different setup
and witness owners. This uses the existing relation protocol and transcript,
rather than a separate implementation for key switching. Existing serialization
and instrumentation reference tests still pass.

## Validation and scope

Round-trip tests cover BabyBear and Goldilocks, a non-power-of-two output
dimension, serialization, every private source root, malformed child proofs,
wrong expected keys, changed accumulator endpoints and changed output entries.
The extraction adversarial test constructs genuine ZeroCheck proofs and PCS
openings under the requested output transcript context but uses another output
as its public factor. The actual-output child verifier succeeds; the requested
public equation rejects the same proof. It covers index zero, signed reversal,
the last retained coefficient and the body constraint.

The current run passes 21 SNARK library/integration tests, including the two new
full final-stage round-trips and this stronger extraction forgery. Ten Python
performance/budget tests pass. The small native and original-size BabyBear
fixtures both verify through the final stage using the original evaluation key
and actual output ciphertext.

```sh
RAYON_NUM_THREADS=16 cargo run --release -p vfhe --example packed_pbs_hadamard -- --with-key-switch
RAYON_NUM_THREADS=16 cargo run --release -p vfhe --example packed_pbs_hadamard -- --full --with-key-switch
python3 tools/packed_budget.py --key-switch-component target/performance/key-switch-linkage/full.log
```

At N=1024, output dimension 728, radix bits 5 and k=8, the new final-stage proof
adds 5,824,846 bytes. Preparation, public setup, proving, verification and
serialization take 0.226 s in one 16-thread release smoke. The implemented
components total 613,854,281 bytes; process wall time is 52.97 s and peak RSS is
4,796,244 KiB. The final-stage-only conservative interactive algebraic model
totals approximately 1.806e-44, excluding composition and Fiat-Shamir. Actual
parameters, logs, executable, source archive and hashes are preserved under
`target/performance/key-switch-linkage/`.

The native component example links the stages in a shared transcript.
`snarks::packed_pbs` now also supplies a standalone complete binary NAND
proof/verifier API with one owned shared accumulator endpoint; see
`performance.md`. Stronger complete-protocol adversarial review remains open. Whole-proof 128-bit security, security-matched
baseline comparison, further backend work and performance promotion remain open.
