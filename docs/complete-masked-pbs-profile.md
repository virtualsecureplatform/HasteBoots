# Repeatable complete masked PBS profiling

The encrypted canonical shared-PBS integration test now emits complete version-11
and version-10 phase records. Both proofs use the same native NAND statement,
trusted native key owners and masked PCS geometries. The native output decrypts
to NAND(1,1)=0 under the original output key. Each proof is serialized, decoded
and publicly verified; retained bootstrapping and switching key counters advance
from zero to one to two across the versions. Existing shape, binding, public
statement and child-value mutation rejection checks still run.

Each `HB_COMPLETE_CANONICAL_MASKED_PROFILE` record includes:

- Protocol version, prime, extension degree, width, native dimensions, query count
  and lookup repetitions.
- Native FHE parameter, complete PCS geometry, ciphertext statement and trusted
  setup fingerprints, plus the complete serialized proof hash.
- Setup, proving, serialization, decoding and verification times, proof size and
  actual child-opening count.

The setup clock covers canonical preprocessing after native key generation.
The proving clock covers the complete proof routine, including witness
preparation and PCS work. Native key generation, encryption and evaluation of
NAND to obtain its trace are outside these clocks. The record is therefore a
complete-proof profile, not an end-to-end application latency claim.

Build and repeat with:

```sh
cargo test --release --locked -p vfhe --test packed_canonical_shared_pbs --no-run
python3 tools/profile_complete_masked_pbs.py \
  --executable target/performance/complete-masked-pbs-profile/complete-profile \
  --source-archive target/performance/complete-masked-pbs-profile/executed-sources.tar.gz \
  --output target/performance/complete-masked-pbs-profile/new-runs
```

Freeze the built integration executable at the indicated path and archive the
executed sources before starting. The runner requires a new output directory,
executes serially with eight Rayon threads, saves raw GNU time logs, and checks
that all four proof records and both integration tests complete successfully.
The second process must reproduce every non-timing field, including full proof
hashes. Each version pair must share fixture, geometry, FHE parameter and trusted
setup fingerprints. Binary and source-archive SHA-256 fingerprints are retained
in the run metadata. Raw logs and per-run JSON retain all timings and process
peak RSS; `summary.json` contains paired version comparisons.

These deterministic tests use public mask seeds, N=32, LWE dimension 21, one PCS
query and one lookup repetition. Neither the FHE parameters nor the whole-proof
security match the original-size promotion target. Versions always execute in
order 11 then 10, so their timings do not control for execution order. A repeated
process alone does not satisfy the original two-confirmation performance gate.
Robust proximity, complete Fiat–Shamir/hash/knowledge composition, hiding,
genuine 1/4/16 joint aggregation and independent review remain separate open
requirements. The emitted promotion/security flags remain false.
Process peak RSS includes both retained proofs and mutation-test clones as well
as native setup, proving and verification. It is not the isolated peak of a
single prover invocation.

## Verified repeated profiles

The frozen current executable completed two serial processes, each with two
passing integration tests, four decoded complete proofs and 26 mutation/public
statement rejection checks. In total eight complete proofs and 3,924 actual
child openings verify, with 52 rejection checks. Every non-timing record,
including each complete proof SHA-256, matches across processes. These are
mutation checks, not additional fresh malicious-proof security certificates.

| Field | Run | Version 10 prove (s) | Version 11 prove (s) | Reduction |
| --- | --- | --- | --- | --- |
| BabyBear6 | 0 | 201.914 | 197.755 | 2.06% |
| Goldilocks3 | 0 | 23.638 | 24.054 | -1.76% |
| BabyBear6 | 1 | 200.894 | 198.803 | 1.04% |
| Goldilocks3 | 1 | 26.455 | 22.858 | 13.60% |

BabyBear improves only 1.0–2.1%; Goldilocks is mixed. These results do not establish
the required repeatable >=10% complete-PBS latency improvement, even before
considering the original-size/security and execution-order limitations.

| Field | Version 10 bytes / children | Version 11 bytes / children |
| --- | --- | --- |
| BabyBear6 | 17,552,895 / 468 | 16,771,685 / 441 |
| Goldilocks3 | 12,523,853 / 554 | 11,444,568 / 499 |

Complete proof fingerprints, identical in both runs:

| Field | Version | SHA-256 |
| --- | --- | --- |
| BabyBear6 | 11 | `c2507b9977b54a22fe6afff605480a5c0e8e7a8198bd7fa2367c95fe515f69a4` |
| BabyBear6 | 10 | `080039647eb69cf4e7b966656796c1c88d646f0d63df0fa2e92502b920509ce6` |
| Goldilocks3 | 11 | `d0bb93b486ff11655b16927f05b5132cf91bad1d033ecb123e0835c00b188157` |
| Goldilocks3 | 10 | `da0a5dc79c9ce9f313a5cc7f5875d2a4d99c4c9f0e9f3abd0b06d284e5ecfaae` |

Process peak RSS is 1,793,292 KiB, 1,774,272 KiB in the two runs.
These peaks include the retained proofs and mutation-test clones. The executable,
executed-source archive, final validated-source archive and immutable raw results
are retained under `target/performance/complete-masked-pbs-profile/`.
