# Deferred canonical source authentication

`packed_extension_lookup::deferred` proves a sequence of public-table lookup
requests against a registry of existing packed commitments. It retains immediate
reciprocal-helper authentication and collects the original-source opening
obligations for one final `open_many` packet per used canonical source.

The registry binds every slot's complete parameter context and commitment before
lookup algebra. A root aliases another slot only when both context and root
match. Each derived query/value claim is bound immediately with its ordinal and
source slot; the final seal binds the claim and used-source counts. The public
verifier reconstructs every obligation from the lookup equations and trusted
request mapping. Proofs contain authentication packets, not an unchecked list of
obligations. Missing packets, injected standalone openings and malformed claim
shapes are rejected. The collector is consumed by authentication.

`packed_decomposition::deferred` applies this mechanism across canonical radix
limbs. Its registry contains the expected digit roots followed by the committed
borrow roots. Limb i uses slots `[i, d+i, d+i+1]`; this routing is derived from the
trusted configuration. The linear reconstruction and zero borrow endpoint checks
remain in place. There is exactly one outer comparison packet, containing all d
lookup proofs and final source authentication. Existing decomposition backends
retain one packet per limb and their original transcript ordering.

Both APIs are experimental and non-hiding. Deferred authentication requires the
same fixed-source-word assumptions as the underlying PCS and an analysis of the
composed transcript. Tests do not establish a Fiat-Shamir or 128-bit whole-proof
security certificate. Complete PBS integration, cross-statement aggregation and
promotion remain pending.

Validation covers BabyBear degree 6/width 8 and Goldilocks degree 3/width 4
canonical decomposition with full and partial domains, zero and p-1 endpoints,
every radix limb, serialized public verification and matching post-transcripts.
Missing/extra comparison packets, reordered or missing limb proofs, altered
claims, missing authentication, changed configurations and swapped digit roots
are rejected. Eleven integration regressions and nine lookup unit tests pass;
the latter include fresh false-source certificates with genuine Merkle paths.
Eight complete v3/v4 compatibility certificates preserve archived wire bytes,
and workspace/example checks, release builds and 81 Python tests pass.

## Native-capacity component comparison

The archived `deferred_lookup --full` executable compares sequences of immediate
lookups with the deferred API. Three deterministic pseudorandom source columns
share 1/4/16 two-column lookup requests. Each source has 2^21 scalar cells.
Source commitment/setup time is excluded; complete time below includes proving
and serialization. Every resulting packet is deserialized and publicly verified.
This is a shared-source lookup component, not a complete PBS benchmark.

Both methods use Q=544 and identical source/helper contexts. BabyBear uses degree
6, width 8, source/helper left dimensions 3/6, and 8192/8192 encoded blocks.
Goldilocks uses degree 3, width 4, left dimensions 4/5, and 16384/32768 blocks.
These synthetic helper geometries must not be substituted for complete-PBS
security profiles. Rayon uses its default thread count (24 logical CPUs reported;
no RAYON_NUM_THREADS override). Processes ran serially, with no concurrent build
or test load. A second session reverses field and method ordering.

| Field | Lookup groups | Immediate bytes | Deferred bytes | Byte reduction | Complete time reduction, two orders |
|---|---:|---:|---:|---:|---|
| BabyBear | 1 | 20,059,177 | 20,278,064 | -1.09% | 1.41%, 0.11% |
| BabyBear | 4 | 80,477,703 | 66,346,103 | 17.56% | 2.02%, 1.11% |
| BabyBear | 16 | 322,170,609 | 238,752,843 | 25.89% | 1.88%, 0.64% |
| Goldilocks | 1 | 15,444,833 | 15,427,942 | 0.11% | 0.41%, 0.43% |
| Goldilocks | 4 | 61,699,789 | 48,349,345 | 21.64% | 1.54%, 0.59% |
| Goldilocks | 16 | 246,828,673 | 169,364,605 | 31.38% | 2.60%, -3.69% |

At sixteen groups, verification changes from 1.091/1.003 s to 0.712/0.693 s
(BabyBear), and 0.904/0.896 s to 0.562/0.546 s (Goldilocks). The result supports
an opt-in size optimization. It does not establish a robust proving speedup,
the 10% complete-PBS target, or security-matched promotion.

Evidence: `target/performance/deferred-lookup/native/` contains four raw logs,
resource reports, exact executable, commands/provenance, terminal controller
status and checked summary. All 24 native packets (168 lookup instances) verify;
proof bytes/hashes repeat exactly across ordering, and both methods bind the
same expected statement per group count. Twelve earlier toy packets also verify.
The benchmark build snapshot is `../build-sources.tar.gz`, SHA-256
`52f8443d4cc6f39b3feb2aa6da12e9608d558d3eae2a67c4986e225898754e29`;
342 Rust/manifest/lock inputs matched at run start. The executable hash is
`70a47389c0bac422575b14479b3c2f7763fd214c084723db98b48f1a8b232b2e`.
The snapshot precedes the subsequent decomposition API and statistics wrapper;
those changes are not represented by these performance measurements.
