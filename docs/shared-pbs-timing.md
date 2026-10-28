# Paired native shared-comparison timing

The serial v5/v8 experiment completed all sixteen original-size PBS proofs.
Both field profiles use ring dimension 1024, LWE dimension 728, the same native
keys and statements, and the decoded complete public verifier. Each field uses
one frozen binary for both modes, with sixteen Rayon threads. Builds and tests
were kept idle throughout measurement. Order 0 runs deferred then shared; order
1 runs shared then deferred. Each cell is the median of two iterations, including
trace construction, proof generation and serialization, with setup reused.

| Field | Order | Deferred v5 (s) | Shared v8 (s) | Improvement |
| --- | --- | ---: | ---: | ---: |
| BabyBear sextic | 0 | 18.1573 | 17.7851 | 2.05% |
| BabyBear sextic | 1 | 18.1580 | 17.8462 | 1.72% |
| Goldilocks cubic | 0 | 32.2972 | 31.2122 | 3.36% |
| Goldilocks cubic | 1 | 32.3053 | 31.5187 | 2.43% |

These measurements **do not meet the 10% latency gate**. They compare conditional
interactive profiles; whole-proof Fiat–Shamir/hash security matching remains
open. They measure independent complete v8 proofs with comparisons shared within
each proof, not the new cross-statement v9 batch format. Two iterations per mode
are engineering observations, not a statistical significance claim.

Raw logs, resources, commands, frozen binaries, provenance and the terminal
status are in `target/performance/shared-pbs-timing/`. Frozen build sources are
linked by that directory's provenance. Reproduce its checked summary with:

```
python3 tools/summarize_shared_pbs_timing.py target/performance/shared-pbs-timing
```
