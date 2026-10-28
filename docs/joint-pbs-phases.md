# Complete batch prover phases and repeated timing

`packed_pbs::batch::shared::prove_with_statistics` produces the same version-9
certificate as `prove`, while accumulating `Statistics` outside the transcript
and serialized proof. Both selected fields pass byte-equality checks between the
timed and untimed APIs in the complete 1/4/5/16 integration fixtures.

The counters distinguish partial-member work, outer binding/preparation, the
mandatory joint Hadamard proof, evaluation-state release, and the complete
blind-rotation/final-comparison phases. The latter include registry construction
and state release; their nested lookup counters measure preparation, commitments,
fused sum/identity sumcheck, terminal evaluation and authentication. Nested counts
are parts of their parent totals and must not be added twice. `zero_check` is zero
for the fused lookup frontend. The partial members' `hadamard` counts only the
omitted-obligation marker; their actual Hadamard proof has its own outer counter.
Their key-switch counter includes NTT/product/extraction and linear checks;
final comparisons are measured separately.

The native example adds `--iterations N` for repeated complete certificates with
one setup. It excludes `--validation-batches`, whose default 1/4/16 schedule stays
unchanged. `--separate` measures complete v5 certificates; `--joint-comparisons`
measures complete v9 certificates. Each is serialized, decoded and checked by its
public verifier before emitting digest-linked `HB_BATCH_PHASES`. Repetitions
record an explicit `timing_iteration`; all private traces remain outside verifier
inputs. Example:

```
RAYON_NUM_THREADS=16 target/release/examples/packed_batch_pbs_babybear --full --joint-comparisons --iterations 2
```

`batch_phase_statistics.py` checks field types, the proof digest and duration,
all phase inventories and parent/subphase inequalities. `joint_pbs_timing.py`
requires a caller-selected repeated-single schedule and matches native keys,
parameters, layouts and fresh statements against completed original-size
validation. It rejects missing/unlinked phases and provides an idle-process guard
before every timing process. The default batch validator still requires 1/4/16;
repeat schedules must be explicitly selected and do not carry its 21-member label.

Two complete integration tests and all 96 Python checks pass. Frozen instrumented
toy runs verify twelve archived packets (84 member instances) byte/hash exactly,
plus eight repeated single-PBS certificates with twenty checked phase records.
Both invalid validation/repetition combinations reject. Sources, frozen binaries,
commands, logs and checks are in `target/performance/joint-phase-profiling/`.
A separate two-order native experiment is under `target/performance/pooled-pbs-timing/`.
It runs sixteen complete single-PBS proofs in eight serial processes, two proofs
per reused setup, using the same binary per field for both modes. Builds and tests
remain idle during measurement. Complete time includes trace/prove/serialization;
verification and setup are measured separately. The profile is conditional
interactive security, not a hash/Fiat–Shamir/knowledge/hiding certificate or a
fully security-matched baseline. The 10% gate is checked only after both orders.

The pooled, sequential-message experiment completes all sixteen native proofs.
Its medians (trace/prove/serialization, seconds) are:

| Field | Order | Complete v5 | Pooled v9 | Improvement |
| --- | --- | ---: | ---: | ---: |
| BabyBear sextic | 0 | 18.2274 | 16.6920 | 8.42% |
| BabyBear sextic | 1 | 18.1380 | 16.6777 | 8.05% |
| Goldilocks cubic | 0 | 32.0173 | 29.4399 | 8.05% |
| Goldilocks cubic | 1 | 32.0613 | 29.5375 | 7.87% |

This misses the 10% latency gate. The measured BabyBear comparison sumcheck
occupies about 6.2 seconds per proof. That observation motivates parallelizing
independent scalar round messages; this experiment uses the earlier sequential
message build, not the new parallel implementation. No speedup for the parallel
build is inferred from these measurements.
