# Shared scalar challenges for lookup batching

`sumcheck::batch` proves independent scalar equations with a common terminal
point. It accepts different maximum degrees but requires one positive variable
count for every equation. Each round binds the complete ordered message array
before sampling a common field challenge. Every equation's recurrence is checked
separately; neither claims nor residuals are compressed with base-field weights.
The verifier returns one terminal obligation per equation.

The caller must bind trusted ordered source commitments before this component
and authenticate the returned terminal values afterward. Extension-field callers
must use full-coordinate sampling, such as
`Transcript::<EF>::new_direct_extension::<Base>()`. This API does not silently
replace the caller's transcript mode or claim 128-bit security from a field type.
It rejects empty or inconsistent batches, malformed polynomial states, message
dimensions and colliding interpolation nodes. Existing scalar sumcheck and
complete PBS protocols are unchanged.

Conditioned on fresh uniform interactive challenges and fixed source polynomials,
the usual per-equation sumcheck bounds can be union-bounded as
`n * sum(degree_i) / |EF|`. Sharing a challenge does not require independent
challenges between equations: each equation's message is fixed before that
round's common challenge. This is an algebraic component argument, not a
Fiat–Shamir, knowledge, hiding or complete-protocol certificate.

## Lookup integration

A reciprocal lookup currently proves the sum of its helper and a separate
pointwise reciprocal constraint with different terminal points. The new component
can schedule degree-one sums and degree-three equality-weighted constraints in
one batch, after all source/helper roots are fixed and the independent equality
points are sampled. This could give one common helper/source query instead of
two, permitting one canonical multi-root authentication packet per parameter
context. The verifier must derive both equations from the same authenticated
helper value; independent unauthenticated values would not suffice.

That lookup frontend, retained comparison witnesses, memory-bounded grouping and
complete PBS integration are not implemented by this component. They remain
required plan items. No complete proof size or speed claim follows from these
unit tests.

## Evidence

Both BabyBear GF(6) and Goldilocks GF(3) pass decoded tests with 1/4/16 equations,
one or three variables, and mixed degrees one through three: twelve fixtures
covering 84 equations. Direct polynomial evaluation checks every terminal claim;
prover states and verifier subclaims share the same full-extension point, and
post-proof transcript challenges agree. Malformed packets, changed ordering and
opposite false claims with unchanged aggregate sum reject. All eleven selected
sumcheck tests and all 86 Python checks pass; the SNARK library check passes too.
Artifacts are under `target/performance/shared-scalar-sumcheck/`.
