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

Canonical adapter and full PBS regression runs are pending. No measured RSS,
latency improvement, whole-security or original-size validation is claimed.
The native Goldilocks run and complete fresh-proof audit launched before this
change execute their preserved previous binaries, not this generator.
