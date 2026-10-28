# Transient masked source codewords

The masked PCS and both matrix adapters expose
`Parameters::with_transient_source_values()`. The default retains encoded source
values. The opt-in owner retains the exact polynomial coefficients and Merkle
tree, discards encoded values after commitment, regenerates them on first use,
and discards them after each independent opening or joint batch. A joint batch
regenerates once, rather than once per member. Returned errors after reservation
also discard the cache; mask allowances remain spent. Preflight errors do not
materialize the codeword. Panics have no new recovery guarantee.

This is a memory/time tradeoff for original-size experiments. It adds FFT work;
no latency improvement is claimed. The policy is stored with the private owner,
so passing mathematically identical parameters with a different policy cannot
change its retention behavior. It is skipped by parameter serialization and
changes no trusted context, dimensions, mask capacity, RNG consumption, public
root, proof format, verifier behavior or transcript inputs. Coefficients and
Merkle authentication remain resident. Commitment and active opening peaks
still include an encoded source, and other temporary allocations remain.

For logical physical message length m, lane width k and blowup b, the discarded
paired source has 4*m*b*k extension-field elements. At b=2, the original native
BabyBear source role (m=2^18,k=8) and Goldilocks role (m=2^19,k=4) each discard
16,777,216 elements. For their 24-byte extension representations this is 384 MiB
of vector payload per idle source owner. This is an allocation calculation,
not a measured RSS reduction or a complete native-PBS memory bound.

Validation compares retained and transient owners across 1/4/16-query batches
in both extension fields with dense extension-valued matrices. Tests require
identical serialized parameters, roots, post-commit RNG state, complete proof
bytes and final transcripts; decoded packets pass the existing verifier.
Independent openings also require exact proof bytes and cache eviction after
every call. A false last batch claim leaves allowance, cache and transcript
untouched. A canonical adapter test checks identical trusted backend contexts
and packets when the retained parameters open a transient owner.

Executed sources and validation logs are archived under
`target/performance/transient-source-cache/`. The full original-size encrypted
PBS experiment, whole proof-security and hiding arguments, full query/FRI
aggregation, latency/byte gates and independent review remain open.

Reproduction:

```sh
RAYON_NUM_THREADS=8 cargo test -p pcs --release -- --test-threads=8
cargo check --workspace --all-targets
```

The release PCS run passed 109 tests with zero failures or ignored tests.
The executed source archive SHA-256 is
`212c696ca9ff19e5768d28a22e22b07e3dec1dc1e11fd3d649c2313383e1e077`;
the validated archive is
`f5b2299704139951dcacfa13545a6ef3ff002e643b03d6b70afad598075d6164`.
Their 455 Rust and Cargo source/build files match byte for byte. Cargo.lock is
pinned to `293790853366e0bc0562752d17999bab335368dd6e0c33823f1afaee8c214718`.
The workspace check also passed; existing unused-macro warnings remain in VFHE
integration tests.
