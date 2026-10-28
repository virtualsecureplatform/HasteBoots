# Joint rolling proximity across ordered matrix queries

`pcs::packed_polyfrim::authenticated::proximity::batch` implements a non-hiding
kernel with one rolling-FRI certificate for multiple ordered matrix-query
ladders on the same retained packed source. It is separate from the existing
masked joint-source backend, whose query-specific FRIs remain independent.
No existing proof format, backend selection or parameter context changes.

All query/claim pairs and every intermediate packed root are bound before the
first consistency sampling challenge. Each query then retains its existing
strict authenticated matrix consistency certificate. After all these roots and
ordered statements are fixed, the transcript samples independent query/lane
projection rows for each layer. For committed vector oracles V[i,l], the scalar
original at layer l is

```text
A[l](X) = sum_i dot(weights[l][i], V[i,l](X)).
```

One rolling FRI checks all A[l]. Every virtual-original callback authenticates
each member's actual packed values at that layer against its original Merkle
root, then checks the weighted sum. There is no recommitted projected copy whose
root could substitute for the actual member roots. The source root is a caller
input, shared by all queries. Ordered batch statements, member positions and
joint projection identifiers use distinct transcript domains. Public matrices,
claims and opened values must use canonical field representatives.

The prover preflights all claims before changing the transcript. Empty batches,
mismatched shapes and missing members/layers reject. Reordered queries and
certificates, foreign source roots, changed paths/values and replayed standalone
FRI certificates reject. A strict production prover never emits a nonconstant
FRI terminal. A private prover helper permits the existing cfg(test)-only FRI
audit generator to construct fresh malicious certificates; public verification
always uses the strict verifier.

Seven new tests cover BabyBear degree 6 and Goldilocks degree 3. Six joint packets
(1/4/16 queries in each field) are serialized, decoded and publicly verified,
with matching final transcripts. Each is compared with verified independent
openings of the same ordered claims and source. Dense matrix entries span the
extension coordinates. Two fresh degree-message forgeries use actual invalid-
degree source evaluations, genuine Merkle paths and zero matrix queries: every
strict matrix consistency check accepts, while the shared FRI rejects at the
rolling-fold equation. Goldilocks noncanonical encodings reject before
transcript mutation, including aliases of the true zero claim/opened value.

Two more fresh forgeries shift every projected scalar oracle by one and
construct genuine low-degree rolling-FRI certificates for those foreign values.
All matrix consistency checks and a selective strict FRI audit accept. Public
joint verification still rejects at the actual-root projection equation. The
audit omits only that equation and is confined to test code; the public verifier
has no option to disable it.

| Field | Batch | Joint bytes | Independent bytes | Reduction |
|---|---:|---:|---:|---:|
| BabyBear | 1 | 28,773 | 28,765 | +8 bytes |
| BabyBear | 4 | 90,171 | 115,057 | 21.63% |
| BabyBear | 16 | 335,759 | 460,223 | 27.04% |
| Goldilocks | 1 | 27,378 | 27,370 | +8 bytes |
| Goldilocks | 4 | 85,896 | 109,477 | 21.54% |
| Goldilocks | 16 | 319,968 | 437,905 | 26.93% |

These fixtures have message length 32, width 2, blowup 2 and eight proximity
samples, without private masking. They establish neither security-matched bytes
nor a latency win. The prover retains every query ladder until the joint FRI
sampling indices are known; its memory can exceed sequential independent
openings. Matrix consistency samples still remain per query.

The release core suite passes all 65 tests. The seven new tests also pass in a
second run of a frozen executable, with identical hashes and sizes for all six
joint packets. Reproduction:

```sh
RAYON_NUM_THREADS=1 cargo test -p pcs --release --lib -- --nocapture --test-threads=1
cargo check --workspace --all-targets
```

Raw logs and six checked proof-fingerprint records are archived under
`target/performance/joint-query-fri/`. The final executed source archive is
`executed-v6-sources.tar.gz`, SHA-256
`94dac64b773d91bcc22d6d1cdebd0936d026c2cf864e69bd97a24f258e023573`.
Earlier archived attempts preserve the compile-label and fixture root/table errors;
they are not the validated implementation.

Masked composition must authenticate every virtual-source pair against the
original paired source, bind all ordered claims/mask responses/identifiers, and
retain the original opening allowances. It also needs a memory strategy for
query-dependent sources and simultaneously retained ladders. The current kernel
does not implement that composition.

Masked virtual-source integration, lifetime/disclosure accounting for that
composition, canonical backend and complete-PBS integration, genuine complete
1/4/16-statement aggregation, robust vector-proximity reduction, whole
Fiat–Shamir/knowledge/security and hiding arguments, and the original native
performance/review gates remain open. Honest degree preservation under linear
combination alone is not a robust-distance or whole-protocol soundness theorem.

The final workspace all-target check passes, retaining only the existing VFHE
unused-macro warnings. Cargo.lock remains pinned to
`293790853366e0bc0562752d17999bab335368dd6e0c33823f1afaee8c214718`.
