# Source-cache measurements at native key-source dimensions

Eight isolated synthetic source openings compare retained and transient caches
at the original key-source dimensions: BabyBear degree 6, width 8, 18 Boolean
cell variables; Goldilocks degree 3, width 4, 19 variables. Each uses blowup 2,
128 sampling queries and one lifetime allowance, with no extra physical padding.
These dimensions follow `Config::variables(width)` for ring 1024/LWE 728.
The tables and public test-seeded masks are synthetic. No native encryption key
is generated and no complete PBS is proved here. The sampling count does not
certify 128-bit proof security.

The serial driver runs retained then transient in repetition one, and transient
then retained in repetition two, with Rayon fixed at eight threads. Every proof
is serialized, decoded and publicly verified. Across all four processes per
field, the driver requires exact fixture, parameter, root, query, proof and
transcript fingerprints, RNG tails, bytes, geometry and spent allowances.
It also checks the discarded allocation count against the geometry.

| Field | Retained after-commit RSS (MiB) | Transient after-commit RSS (MiB) | Retained proving (s) | Transient proving (s) |
|---|---:|---:|---:|---:|
| BabyBear | 642.75 / 642.77 | 258.80 / 258.84 | 7.857 / 7.331 | 10.732 / 10.653 |
| Goldilocks | 698.91 / 699.00 | 314.88 / 314.93 | 6.247 / 6.417 | 6.709 / 8.078 |

Values are repetition one / two. Each transient owner removes exactly
16,777,216 extension elements (384 MiB), before and after its opening. Proof
bytes stay 6,635,239 for BabyBear and 5,467,351 for Goldilocks. Single-source
process peak RSS stays essentially unchanged: 1357.7–1358.1 MiB for BabyBear,
1581.6–1581.9 MiB for Goldilocks. Active proving still materializes the encoded
oracle. The result supports reducing memory across idle retained owners, while
showing the extra proving cost. It establishes neither a complete native-PBS
memory bound nor a latency improvement. Native-key setup and complete original-
size PBS resource measurements remain necessary.

The existing five-argument profiler CLI remains supported. Its non-timing output
matches the frozen prior profiler exactly on the archived compatibility smoke
fixture. The extended syntax is:

```sh
cargo build -p pcs --release --example masked_joint_profile
# Freeze the executable before collecting isolated measurements.
cp target/release/examples/masked_joint_profile /tmp/source-profile
python3 tools/profile_native_source_cache.py /tmp/source-profile /tmp/source-cache-runs
# Individual invocation:
RAYON_NUM_THREADS=8 /tmp/source-profile babybear joint 18 18 1 128 transient
```

The output directory must be fresh: the driver refuses to overwrite raw logs,
timing files or its checked result. Raw `/usr/bin/time -v` outputs, eight proof
records, checked invariants, compatibility comparisons and the frozen binary
are under `target/performance/native-source-cache/`. Binary SHA-256:
`db4ca85b6f3bf080aea6e0d2d774f058682b123ba832dcee83743958b01a13fd`.
The profiled source archive SHA-256 is
`e729331e446efc60117b4b457ab6864365b63566534860b35cdeb471431de739`.
Cargo.lock remains
`293790853366e0bc0562752d17999bab335368dd6e0c33823f1afaee8c214718`.

All original complete-PBS/security, hiding, full query/FRI aggregation,
security-matched byte/latency, and independent-review gates remain open.
