# Lazy Goldilocks residues at the concrete NTT boundary

The 64-bit concrete NTT wrapper now canonicalizes field inputs before passing
them to the integer forward/inverse kernels. Goldilocks arithmetic permits lazy
representatives at or above p, and those representatives denote the same field
elements as their reductions. Passing them directly through the raw u64 slice
could produce a different transform. A structured key-switch frequency sum
exposed a failing inverse/forward round trip at N=32.

The fix is confined to the 64-bit NTT boundary. Prime32 kernels, field arithmetic
and serialization conventions are unchanged. Canonical inputs enter the same
integer kernel with the same bits. Previously incorrect outputs for lazy inputs
can change to the correct field result; their old behavior is not retained as a
compatibility mode.

Two release/locked regression tests check N=32 and N=64 against independent
quadratic-time negacyclic DFT/inverse definitions, including bit-reversed
frequency order. Lazy aliases cover every input coordinate and the maximum u64
representative. Canonical and aliased inputs produce identical serialized
outputs in both directions. Both tests pass. The additional normalization pass
has not been separately benchmarked; prior native timing evidence still refers
to its archived source builds.
