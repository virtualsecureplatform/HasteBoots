# Complete original-size masked PBS control

`vfhe/examples/native_masked_pbs_profile.rs` runs canonical version 11 with the
joint-source masked PCS at the original ring-1024/LWE-728 dimensions, original
output key and original BabyBear or Goldilocks FHE constants, including noise.
It encrypts NAND inputs (1,1), executes the native evaluator, requires decrypted
output zero and proves the entire public input/output statement. Every PCS
role uses 128 sampling queries, blowup 2 and the unchanged mask-capacity guard.
The helper lookup repetition count is one. These choices do not certify
128-bit whole-proof security. All source owners use transient codeword caches.

The harness provisions each role at the smallest accepted physical dimension,
retaining the original logical dimensions and opening allowances. Original key
owners receive one allowance each and must be exhausted exactly once after the
complete proof. The prover releases completed blind-rotation witness states
before allocating final key-switching witnesses. No dimension, noise parameter,
lookup/proximity check or original output-key requirement is reduced.

A completed proving run writes the exact proof, statement, trusted setup,
trusted parameters, FHE parameter description and geometry. It decodes the saved
proof bytes, runs the production public verifier and rejects an altered output.
Only afterward does it write `verified-record.json`. The separate replay mode
regenerates trusted native setup and the encrypted fixture from the public test
seeds, requires exact trusted-artifact/statement bytes, and publicly verifies
the saved proof without producing another proof or spending a key allowance.
Public seeds are reproducibility controls, not private cryptographic randomness.

```sh
cargo build -p vfhe --release --example native_masked_pbs_profile
# Archive sources and freeze the executable before collecting a run.
python3 tools/archive_sources.py /tmp/native-pbs-sources.tar.gz
cp target/release/examples/native_masked_pbs_profile /tmp/native-pbs-profile
python3 tools/profile_native_complete_masked_pbs.py \
  --executable /tmp/native-pbs-profile --source-archive /tmp/native-pbs-sources.tar.gz \
  --field goldilocks --output /tmp/native-pbs-goldilocks-run
```

The serial driver fixes Rayon at eight threads, records executable/source
hashes, captures GNU time output, and saves each subprocess PID and terminal
return code. A PID file identifies a process to inspect; it does not prove that
it is live. Run directories and artifacts must be fresh. A long observation
interval is not a failed experiment: continue observing the same process.

`tools/check_native_complete_masked_pbs.py` checks artifact hashes, exact native
geometry, unchanged numeric capacity guard, completed runtime reports and fresh-
process replay fingerprints. It is a report checker, not an independent
cryptographic verifier. The Rust public verifier performs proof verification.

This harness measures complete native correctness and resources only after the
run actually finishes. Pending process metadata or a compiled executable does
not establish a verified complete proof. Whole proof-security/composition,
robust vector proximity, hiding, genuine complete 1/4/16 aggregation,
security-matched byte/latency gates and independent review remain open.

The initial Goldilocks run is tracked at
`target/performance/native-complete-masked-pbs/goldilocks-run-1/`. At launch it
has no completed proof result; `verified-record.json`, successful subprocess
exit records and the replay checker output are the required completion
evidence. The frozen executable SHA-256 is
`c58d41543c0f1bc6c0f1df71099deba0e0b6780c6ac66053842a99a48c0cfec9`;
the executed source archive SHA-256 is
`bf1e286ffb78d18ec2fd03f2ae9fc5e366d23ea822db1db5192714fd10f32c20`.
The release build, workspace all-target check, Rust format check and Python
syntax checks pass. These checks validate the harness build; native proof and
replay completion require the runtime evidence above.

Concurrent aggregation development builds/tests are recorded in the initial
Goldilocks run's `timing-exclusions.json`. That run remains a correctness and
per-process resource control. Its raw times are ineligible for performance
comparison; the original requirement for isolated security-matched timing runs
is unchanged. The frozen native executable and its executed source archive
remain unchanged while development continues.
