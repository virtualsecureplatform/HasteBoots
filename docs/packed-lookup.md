# Packed public-table lookup

`snarks::packed_lookup` implements the scalar small-public-table specialization
of the reciprocal lookup in Appendix H.1 of 2025/719. Its verifier takes a
trusted `Config`, canonical source commitment and parameters; no source witness
is passed to the verifier. The configuration fixes the logical scalar length N,
distinct public table T of size M, and number s of rational repetitions.

Protocol order:

1. Bind the field/code/layout parameter digest, canonical source root and trusted
   configuration. Send and bind M field-valued multiplicities h.
2. Independently sample s scalar challenges r, excluding zero and all -t for
   t in T. Commit all reciprocal helper tables before algebraic challenges.
3. For each r, use degree-one packed sumcheck to certify the lane sums of f;
   their total must equal sum_t h[t]/(r+t).
4. Use packed ZeroCheck for `f * (r + mask*a) - mask = 0`, then authenticate f
   at both terminal queries with one batched opening. The public mask marks
   precisely the first N scalar entries; evaluate it in O(k² log(domain)).
5. Authenticate all source ZeroCheck evaluations together against the same
   canonical root. Every subclaim is checked before accepting the lookup.

The cubic mask term is intentional. The superficially simpler
`f * (r+a) = mask` would permit arbitrary inactive f whenever a padded source
entry equals -r. Our identity forces inactive f=0 because r is nonzero. No
constraint on inactive source values is required. Honest multiplicities count
only active entries. They are fixed before r, preventing adaptive rational
interpolation using the public table. Since N+M-1 < p, a nonempty collection of
invalid entries cannot disappear through characteristic-p count cancellation.

For fixed false input and fixed h, a nonzero numerator has degree at most
N+M-1. The lookup-only conditional-domain error is bounded by
`((N+M-1)/(p-E))^s`, where E is the number of distinct excluded challenge values.
E=M when zero is in T, otherwise M+1. The API exposes these exact counts as
`rational_degree_bound` and `challenge_domain_size`. This bound does not include
packed sumcheck/ZeroCheck, MW-Brakedown, Fiat-Shamir or the rest of PBS. Increasing
packed lane width does not independently amplify the rational challenge.

Current scope is one scalar source column and an explicit small public table.
Tuple hashing, large committed tables, digit reconstruction, and canonical
binding to accumulator/key-switch inputs require further work. A valid range
lookup does not prove that digits reconstruct the intended field element or
integer representative.

Tests cover BabyBear and Goldilocks, partial lanes with arbitrary padding,
single active entries, serialization/transcript agreement, malformed shapes,
altered multiplicities and claims, wrong canonical roots and code parameters,
and genuine proofs for different valid source data. A focused unit test checks
that an inactive pole cannot hide a nonzero reciprocal.

The native example's `--with-lookup` flag enables NTT linkage and adds range
lookups for all digit coefficient factors, reusing exactly their coefficient
roots. It uses 16 rational repetitions and the existing FHE gadget base; this
is a component experiment, not a complete proof-security setting or promotion.

```sh
RAYON_NUM_THREADS=16 cargo run --release -p vfhe --example packed_pbs_hadamard -- --with-lookup
RAYON_NUM_THREADS=16 cargo run --release -p vfhe --example packed_pbs_hadamard -- --full --with-lookup
```

## Initial native evidence and remaining cost

The original-parameter native trace passes all eight digit range lookups with
16 rational repetitions. At 544 column queries, the automatic layout selector
chooses left_vars=3, message blocks=4096 and encoded blocks=8192. Each digit
source has 2,097,152 active scalar entries (the trace is already padded).
The initial helper implementation adds 856,907,878 bytes and takes 66.031 s
including helper preparation, commits, proving, verification and serialization.
Process wall time is 72.45 s, peak RSS 2,374,456 KiB. The Hadamard/NTT bytes are
additional. This composition is not ready for performance promotion.

The prover now indexes active entries in the public table once and uses only M
inverses per repetition, reusing each inverse for all matching entries. A direct
per-entry-division reference test checks the resulting helper commitment roots,
including nonconsecutive table ordering. This optimization does not change the
protocol or helper contents. The original-size repeat takes 46.599 s for the lookup portion (29.4% below
the initial 66.031 s smoke), with exactly the same 856,907,878 serialized bytes.
These are single component measurements, not the repeated full-PBS promotion
benchmark. The three lookup integration tests pass after the cache optimization,
including independently reconstructed helper roots; the prior full SNARK run
passes 19 tests, including the inactive-pole regression. Five Python tool tests
pass. Logs, budget JSON and saved comparison binaries are under
`target/performance/packed-lookup/`.

Run the conditional-domain component budget against emitted dimensions:

```sh
python3 tools/packed_budget.py --lookup-component target/performance/packed-lookup/full-q544.log
```

That lookup-only conservative interactive budget totals approximately
5.2865e-41, below 2^-128. It counts 16 sumchecks and ZeroChecks per factor,
shared-opening proximity events, helper/source random linear tests, and the
rational identity. It excludes NTT/Hadamard and the remaining PBS stages,
Fiat-Shamir, knowledge soundness and hiding. The earlier 512-query run is kept
under `full-q512.*`; reusing the Hadamard-only query budget was insufficient.
Further work must reduce helper proof size and proving cost, and select layout
for the actual shared-opening workload rather than a single opening.
