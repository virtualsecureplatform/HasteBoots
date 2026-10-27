# Trusted public bootstrapping-key binding

`snarks::packed_bootstrap_key` derives canonical NTT table commitments from a
trusted public binary bootstrapping key, independently of any execution trace.
The source is the native RGSW array in input-mask order. All c_neg_s_m digit
columns precede all c_m digit columns, matching native external-product trace
ordering. Each table contains a rows followed by b rows, padded with zeros to
M=next_power_of_two(input dimension). N, radix and both RLWE halves are checked
for consistent dimensions. Public native-key accessors expose these ciphertexts
without exposing secret key material.

`preprocess` computes reusable expected roots and binds them to the PCS parameter
context. The resulting public-key object has private fields and intentionally
cannot be deserialized from untrusted proof bytes. The verifier must authenticate
the public native key used for this setup, just as it must authenticate other
trusted parameters.

The verification wrapper accepts private digit roots and the sum-product root.
It interleaves the expected key roots itself and constructs the canonical
sum-of-products relation. It never accepts replacement key roots from the
prover. Thus the normal Hadamard PCS openings authenticate the actual key
factors; no extra algebraic relation or new opening protocol is introduced.
For a complete PBS protocol the trusted radix/input dimensions must also agree
with the decomposition and accumulator plans. This is a binary blind-rotation
key component, not yet key-switching-key or final-output binding.

Tests compare every coefficient of each native public key table, both halves,
digit ordering and padding; malformed dimensions/radices are rejected. A valid
Hadamard proof for an entirely different key is generated under the requested
public-key parent context and verified successfully against its own sources.
The wrapper rejects it against the expected key. Wrong PCS contexts and missing
private sources are also rejected.

```sh
RAYON_NUM_THREADS=16 cargo run --release -p vfhe --example packed_pbs_hadamard -- --with-public-key
RAYON_NUM_THREADS=16 cargo run --release -p vfhe --example packed_pbs_hadamard -- --full --with-public-key
```

The flag enables the existing monomial, accumulator, canonical decomposition and
NTT components. The new trusted setup is timed separately in the log but is also
included in the Hadamard preparation/commit timer. Actual and expected public
key commitments are both computed in this reference example; a final reusable
setup integration should avoid duplicate key commitment work. No complete PBS,
Fiat-Shamir or performance promotion claim follows from this example.

## Recorded validation

Both small and original-size BabyBear native fixtures verify with
`--with-public-key`. At N=1024 and input dimension 728, the reusable public setup
has eight roots and takes 0.276 s in one 16-thread release smoke. No additional
proof protocol or proof bytes are introduced: the existing Hadamard verifier
now uses the expected public roots. The run still includes duplicate key commit
work as described above. This is a functional component smoke, not a security
or latency promotion. Logs, executable, source archive and hashes are in
`target/performance/public-bootstrap-key/`.

The two new public-key tests pass in addition to the preceding 132-test Rust
regression and nine Python tests. The preceding complete Goldilocks proof smoke
also verifies after the exact modulus-switch fix; its artifact is preserved in
`target/performance/public-monomial/`.

The complete `snarks::packed_pbs` API uses `prepare` to retain these public
key tables and prover states across invocations, rather than committing key
columns from traces. Its verifier setup owns only the expected public roots.
The original `preprocess` root-only component API remains available and passes
its existing reference tests.
