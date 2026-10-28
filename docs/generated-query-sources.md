# Regenerating initial virtual sources

Masked query aggregation previously retained all full-size virtual source
coefficient/codeword arrays while retaining their consistency ladders. The
prover now generates one initial virtual source at a time in each of four
phases: ladder construction, consistency certificates, joint projection and
sampled packed paths. A batch of B members holds at most one such initial source
at once, rather than B. All intermediate ladders still remain retained.

The retained source owner, paired source cache, mask reservations, RNG usage,
root identifiers, message ordering and verifier are unchanged. Regeneration
repeats coefficient/codeword linear combinations four times per member; this
trades additional work for a smaller live set. It does not stream all ladders
or establish that every native batch fits available RAM.

All 70 PCS core tests pass. The six masked 1/4/16-query reports over BabyBear and
Goldilocks match the prior archived records exactly, including full proof
hashes. Seven joint-kernel tests also pass after adding retained-versus-generated
comparisons for 1/4/16 queries over both fields. Those comparisons check proof
bytes, every sampled source index, all 32 transcript bytes and exactly four
source generations per member. The old retained virtual-source path remains
available only to tests and adversarial fixture constructors.

Logs and source snapshots are under
`target/performance/generated-query-sources/`. The first executed core snapshot
is SHA-256 `f1fd298b946b7c1de40eef4971c3a7f79d720a351e58eb309ac120bdc4eebbd5`;
the differential-test snapshot is
`2465f5e020576539b6773aac679730670d851bb1274dc3bc5f0267a1c99585dd`.
The latter adds the direct differential checks and makes the reference entry
point test-only; the production generator is unchanged.

All five canonical context/adapter tests pass. Full PBS regression remains
pending. No latency improvement, whole-security or original-size validation is
claimed.
The native Goldilocks run and complete fresh-proof audit launched before this
change execute their preserved previous binaries, not this generator.

## Separate-process resource control

An ignored test compares retained versus regenerated initial virtual sources
with 2^15 message rows, width 2, blowup 4, eight sampled queries and dense
extension-field matrices. It runs each field/batch/mode in a separate process.
Each child decodes and verifies the proof, including expected virtual-source
sample values. The driver checks identical fixtures, serialized proofs and
transcript fingerprints for each pair and captures GNU time peak RSS.

| Field | Queries | Retained peak KiB | Generated peak KiB |
| --- | ---: | ---: | ---: |
| BabyBear degree 6 | 1 | 53,904 | 46,712 |
| BabyBear degree 6 | 4 | 117,004 | 87,620 |
| BabyBear degree 6 | 16 | 369,540 | 245,868 |
| Goldilocks degree 3 | 1 | 53,964 | 46,832 |
| Goldilocks degree 3 | 4 | 117,172 | 86,528 |
| Goldilocks degree 3 | 16 | 369,116 | 245,880 |

All twelve processes pass. The checked manifest, raw logs, per-process PIDs,
exit codes and resource records are in `resource-run-1/` under the artifact
directory above. The frozen `resource-profile` executable and source archive
hashes are linked by its manifest. `resource-executed-sources.tar.gz` has SHA-256
`46436771b7a8bd630f3a412d40d4613976f5ea1bb7d5e691ab99bb4bf837d6b4`.

```sh
cargo test -p pcs --release --lib generated_source_resource_profile --no-run
python3 tools/profile_generated_sources.py --executable target/performance/generated-query-sources/resource-profile --source-archive target/performance/generated-query-sources/resource-executed-sources.tar.gz --output target/performance/generated-query-sources/resource-run-new
```

This fixture isolates the virtual-source kernel and directly checks expected
initial values; it is not the original paired masked-source verifier or a full
PBS. Production masked component proof hashes are checked separately above.
These are per-process memory controls taken during other validation work. No
isolated timing or extrapolated native-size memory result follows from them.
