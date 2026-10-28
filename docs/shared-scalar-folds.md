# Shared scalar fold buffers

`sumcheck::batch::prove` now borrows each immutable multilinear source for the
first round and folds each distinct source object once per common challenge.
The reciprocal sum and identity use the same helper object, so they reuse its
folded buffer. Equal-valued sources in distinct `Rc` objects remain distinct;
private pointer routing is neither a root alias nor serialized proof metadata.

Every polynomial still has its own coefficients, affine wrappers, degree,
round messages, recurrence check and terminal claim. Sources fold with the same
arithmetic as the reference prover. The final public `ProverState` layout and
semantics remain available: each equation receives its own tiny terminal tables
and the full common point. All large pool buffers are dropped before returning.
Transcript frames, challenge calls, proof types and verifiers are unchanged.

For n variables and U unique source objects, the first fold allocates U*2^(n-1)
field elements. The old initialization copied M*2^n elements, where M counts
source references across equations. In a full-prefix shared lookup with C
helpers, M=4C and U=3C: the sum and identity share the helper, and the identity
also has equality and compressed-source tables. The large prover-state buffer
capacity falls from 4C*2^n to 1.5C*2^n elements. This is a buffer accounting
result, not a measured process-memory or latency improvement. Caller-owned
sources, PCS states, proof storage and other phases still consume memory.

The old per-equation implementation is retained only as a test reference. Four
scalar-batch tests pass over BabyBear sextic and Goldilocks cubic, with n=1/3,
1/4/16 equations, affine terms, repeated source objects and equal-but-distinct
objects. New reference fixtures compare exact proof bytes, post-proof transcript
challenges and terminal states. All fifty SNARK unit tests also pass, including
lookup/decomposition source-binding attacks and fresh complete-v9 helper attacks.
All 62 selected Rust tests pass: four scalar-batch tests, fifty SNARK unit tests,
six complete v8/v9 integration tests and two bounded decomposition fixtures.
All 210 toy wire-controlled member instances retain archived bytes/hashes:
84 standalone v5/v8 controls and 126 member instances across complete v6/v7/v9
batch controls. A separate original-size repeat now requires exact pre-pooling
v9 bytes/hashes as well as public verification at 1/4/16. That run is active
under `target/performance/scalar-shared-fold-native/`; tests, source archives,
binaries and wire-control evidence are recorded under `target/performance/scalar-shared-fold/`.

This optimization adds no algebraic compression and does not close the existing
Fiat–Shamir, hash, hiding, whole-security or promotion gates. Native v9 evidence
from `comparison-batches-native/` uses the separately frozen pre-pooling build.
