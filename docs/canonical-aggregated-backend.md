# Canonical aggregated query backend

`masked_polyfrim::aggregated::Parameters` implements `CanonicalPcs` with one
shared query-ladder FRI per retained source group. It retains the original key
owner, root, opening allowance and transient-cache policy. Its trusted context
and seven transcript domains differ from both independent and previous joint
backends. Parameter geometry alone does not identify the backend.

The context tests check cross-backend rejection, all 21 domains, shared budget
exhaustion and cache-policy equivalence. Complete PBS integration tests cover
both fields and protocol versions 10 and 11, serialization and production
verification, malformed packets and statements, and exhausted native owners.
All four cases use ring size 32, LWE dimension 21, one query and one lookup
repetition. Native key roots, fixture, FHE parameters and geometry match the
archived previous joint backend; trusted setup contexts differ.

| Field | Version | Previous bytes | Aggregated bytes | Query FRI certificates |
| --- | --- | ---: | ---: | ---: |
| BabyBear | 11 | 14,847,856 | 12,738,293 | 441 → 165 |
| BabyBear | 10 | 15,551,355 | 13,356,106 | 468 → 177 |
| Goldilocks | 11 | 10,392,079 | 9,219,868 | 499 → 291 |
| Goldilocks | 10 | 11,347,630 | 10,037,020 | 554 → 317 |

Raw results and checked comparisons are under
`target/performance/canonical-aggregated-backend/`. The executed source archive
is `executed-sources.tar.gz`, SHA-256
`5863fbdef22cfff54924d89abe7c5d3f2e70b300a1b4034ec5186a0da0f8aa7c`.
`tools/check_canonical_aggregated_profile.py` checks report consistency against
the prior archive; cryptographic verification runs in the integration tests.

```sh
cargo test -p pcs --release --test canonical_aggregated_context --test canonical_joint_context --test masked_aggregated_adapter
RAYON_NUM_THREADS=8 cargo test -p vfhe --release --test packed_canonical_aggregated_pbs -- --nocapture --test-threads=2
cargo check --workspace --all-targets
```

These measurements ran concurrently with native validation and establish no
latency improvement. This is aggregation of queries within a source group;
complete 1/4/16-statement aggregation remains open. Original-size validation,
large-batch memory improvements, robust proximity and security composition,
whole-PBS hiding, security-matched size and latency gates, fresh full-proof
adversarial audits for this backend, and independent review remain open.
