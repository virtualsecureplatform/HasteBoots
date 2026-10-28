# Original-size native masked key ownership

`vfhe/examples/native_masked_setup_profile.rs` provisions the retained canonical
joint-source owners from actual native bootstrapping and switching keys. It uses
the repository's original `BABYBEAR_BINARY_128_BITS_PARAMETERS` and
`GOLDILOCKS_BINARY_128_BITS_PARAMETERS`, including their noise distributions,
ring dimension 1024, LWE dimension 728, blind-rotation radix bits 8 and switching
radix bits 5. These are named FHE parameter sets; their names do not certify
128-bit security of the proof system.

The trusted PBS configuration and native preprocessing validate the original
key shapes and bases. The harness commits every native source: eight
bootstrapping and seven switching sources for BabyBear; sixteen and thirteen
for Goldilocks. All retain one lifetime allowance, blowup 2 and 128 sampling
queries. Helpers are provisioned with the original logical shapes but are not
committed during key setup. The existing numerical mask-capacity guard chooses
the smallest accepted physical dimension:

| Field | Logical source / helper / final source / final helper | Physical dimensions |
|---|---|---|
| BabyBear degree 6, width 8 | 18 / 21 / 8 / 11 | 18 / 21 / 18 / 18 |
| Goldilocks degree 3, width 4 | 19 / 21 / 9 / 11 | 19 / 21 / 17 / 17 |

Each isolated process opens the first actual bootstrapping source and the first
actual switching source with dense ordered matrix queries. Both packets are
serialized, decoded and publicly verified against their original roots. Final
transcript challenges agree. Those two owners each spend one allowance; every
other original owner stays unspent. Every transient owner has zero cached
encoded source elements both before and after openings. The default owners
retain their full caches.

The serial driver compares retained/transient native parameter, trusted PCS
parameter, complete native table inventory, complete source-root inventory,
both proof and transcript fingerprints, both proof lengths, and post-commit RNG
state. Public seeds are deterministic test controls. The runs are resource and
correctness evidence for native key ownership, not a complete encrypted PBS,
full hiding, robust vector proximity, proof-security certification or a
security-matched performance result. Complete original-size masked PBS memory
and latency remain unmeasured.

Reproduction (fresh output directory, no concurrent benchmarks):

```sh
cargo build -p vfhe --release --example native_masked_setup_profile
cp target/release/examples/native_masked_setup_profile /tmp/native-setup-profile
python3 tools/profile_native_masked_setup.py /tmp/native-setup-profile /tmp/native-key-runs
```

The driver fixes Rayon at eight threads and runs four isolated processes:
BabyBear retained/transient, then Goldilocks transient/retained. There is one
sample per policy and field; no repeated timing improvement is claimed. It
refuses to overwrite raw logs, GNU time outputs or checked records. Archived
sources, frozen executable and raw validation logs are under
`target/performance/native-masked-key-setup/`.

## Measured result

All four processes finished successfully. Together they committed 88 source
owners (44 native sources, each instantiated under both cache policies), with
eight serialized/decoded opening packets verified. The checked comparison
requires exact native parameters, native tables, roots, trusted PCS parameters,
proofs, transcripts and RNG tails across cache policies in each field.

| Field | Setup RSS retained / transient (GiB) | Peak RSS retained / transient (GiB) | Two opening round trips retained / transient (s) |
|---|---:|---:|---:|
| BabyBear | 9.100 / 3.475 | 9.731 / 4.482 | 16.610 / 21.932 |
| Goldilocks | 12.540 / 5.337 | 13.350 / 6.506 | 8.572 / 9.999 |

Setup RSS savings are 5.625 GiB and 7.203 GiB, respectively. Exact discarded
codeword payloads are 5.625 GiB (251,658,240 elements) and 7.21875 GiB
(322,961,408 elements); process RSS also reflects allocator retention. Peak RSS
falls because the other key owners stay idle while one source is opened.
Regeneration increases the cost of the two opening round trips. These timings
include query/claim construction, proving, serialization, decoding and public
verification, and are single observations per policy. They are not complete PBS
latencies or evidence of the required repeated speed improvement.

The two native opening packets have exactly 6,635,251 / 6,634,997 bytes for
BabyBear and 5,467,351 / 4,641,815 bytes for Goldilocks, unchanged across cache
policies. Both the native setup phase and opening phase preserve each original
owner's lifetime; unselected key owners remain unspent.

The release build, development example check, Python syntax check and Rust
format check pass. Frozen executable SHA-256:
`ba7f2d7e50a3e5ef524ffce134e11658f57ee485276a0181bdcdafc37a0ddc9c`.
Executed source archive SHA-256:
`767eb88b1d436403bde4b51fbb88f62172f5733eed8428fee6cda26ffd50d21a`.
Cargo.lock remains
`293790853366e0bc0562752d17999bab335368dd6e0c33823f1afaee8c214718`.
