# Experimental masking for direct packed PolyFRIM

`pcs::packed_polyfrim::authenticated::masked` implements a bounded-reuse masked
reference over ordered matrix queries. It is not selected by complete PBS and
has no zero-knowledge or concrete 128-bit security certificate. It extends the
same-root composition described in `packed-polyfrim.md`.

For an m-cell, k-lane Boolean table, convert each lane to multilinear monomial
coefficients. Append m private random coefficient vectors, producing P of size
2m. Independently sample a random size-2m vector polynomial S. One packed Merkle
tree commits all P and S lanes, with the exact padded degree/domain/width geometry
bound into every leaf. Commitment requires a caller-supplied private cryptographic
RNG. Public seeded RNGs in the tests are reproducibility fixtures.

An ordered matrix query appends the high-variable pair (I,0), so P's response
remains the original requested response y. Compute S's corresponding response
ys, bind the complete parameters/root/index/query/y/ys and draw nonzero alpha by
rejection sampling. The public-fold polynomial is P+alpha*S, with terminal
response y+alpha*ys. No unmasked intermediate lane-response vector is sent.

There are two mandatory proximity components. The first draws a separate row
over all 2k committed P/S lanes and uses virtual-original rolling FRI, with
subsequent original placeholders fixed to zero. Its queries authenticate against
the actual packed source root. This prevents relying solely on the particular
P+alpha*S combination for source/mask proximity. The second checks the masked
public-fold ladder and its same-root projected rolling proximity.

The initial P+alpha*S oracle is virtual: no replacement source tree is committed.
Its identifier binds the retained root, parameters, index and alpha. Both matrix
consistency queries and masked rolling queries carry empty virtual source paths;
an enclosing callback authenticates actual P/S pairs and recomputes every lane.
Intermediate masked vector and scalar oracles retain their own authenticated
roots. All statements and layer roots precede their relevant query coins.
Ordinary unmasked verification continues to require real source paths.

## Mask lifetime

`ProverSession` owns the retained private padding/mask state and cannot be cloned
or serialized. Its monotone counter covers the commitment's entire lifetime.
Wrong parameters, malformed queries, false original claims and exhaustion fail
before transcript mutation or spending. After successful preflight, an opening
attempt spends its allowance before publishing transcript data, even if a later
internal check fails. No method automatically recommits or refreshes exhausted
masks. A new commitment requires an explicit call with fresh private randomness.

Stateless verification bounds the proof index by the trusted lifetime and permits
independent replay verification. Optional `VerifierSession` additionally requires
consecutive indices from zero, rejects replay/reordering and advances only after
successful verification. Restarting verifier state does not refresh the honest
private prover's mask budget.

## Numerical disclosure allowance

Let r=log2(2m), q be each sampling count and B the lifetime budget. Setup requires

```
m >= B * (k + 8*q*(k+1)*(r+1)).
```

This deliberately conservative allowance bounds the number of publicly serialized
witness-dependent field elements, conditioned on public coins. Counting every
duplicate field entry in the complete proof gives

```
D = k + 2 + q*(12*k + 4*k*r + 8*r - 4).
```

The count includes ys, both scalar FRI transcripts, all original P/S pairs and
both vector-ladder query sets. The allowance exceeds D by
`4*k*q*(r-1)+12*q-2`, which is positive for the trusted r,q>=1. Tests count actual
serialized proof fields independently of this formula and check cumulative
capacity. Hashes and public challenge dependence are outside this count.

A field-element count alone does not establish hiding: observations can have
linear dependencies that cancel masks while exposing witness information.
The finite cumulative audit below checks selected actual ordered-matrix
transcripts. A general masking argument, random-oracle/Merkle hiding and adaptive
Fiat–Shamir analysis remain required. The conservative allowance can reject otherwise
interesting native profiles; it is not a security-matched parameter selector.
The same-root vector-proximity reduction and whole-proof composition also remain
open. No native complete-PBS latency or size result is claimed for this backend.

## Validation

All 63 selected release/locked tests pass: 44 PCS unit tests, four masked scalar
adapter tests, eight ordinary scalar adapter tests and seven encoder tests. The
new reference verifies sixteen serialized/decoded masked packets, with two
openings per retained source over BabyBear/Goldilocks and widths 1/2/4/8. Tests
exercise dense/noncommuting and singular selection queries, transcript agreement,
fresh commitments, unchanged counters/transcripts on failed preflight, exhaustion,
parameter mismatch, ordered acceptance/replay and malformed source/virtual data.
The capacity test counts actual field entries in each decoded proof.

Four fresh false original-claim or false mask-claim certificates reconstruct all
children under the requested parent. Independent replay accepts the source/mask
proximity proof, every actual source path and every child of the foreign virtual
ladder. Strict verification rejects specifically at the masked virtual-source
link. These are small reference fixtures, not native FHE proofs or a hiding rank
audit. Logs and validated sources are under
`target/performance/direct-packed-polyfrim-masked/`, source SHA-256
`8406f2e7f2644c78bf3636582da3a03ce453351ccd977664d6c001281ee32d6c`.

## Conditional cumulative linear-view audit

The test-only coefficient model reconstructs every disclosed field element from
one retained source's low coefficients, private high coefficients and independent
mask coefficients. It uses independent matrix/coefficient folds and Horner
polynomial evaluation, rather than production Polynomial/FFT routines. Actual
serialized/decoded proofs verify first. A transcript replay then recovers their
alpha, projection rows, rolling fold coins and query locations; its trailing
challenge must match the actual prover. Counterfactual coefficient views keep
those coins fixed. Their field values must match every decoded proof field before
any rank calculation is accepted.

Let A be the cumulative observation matrix for both openings, with columns
partitioned into original witness coefficients w and private randomness eta.
Let Y map w to the permitted ordered matrix responses. The test checks

```
rank([A; Y 0]) = rank(A_eta) + rank(Y).
```

For uniform eta and fixed coins, this says that the affine distribution of the
linear observations depends on w only through Y*w. Both openings use the same
randomness columns; the audit does not silently refresh masks between them.
Each separate schedule uses an independently seeded fixture commitment.

The cases cover both prime fields, width one/m=512 and width two/m=1024, with
one sample per stage and a trusted lifetime of two. Each geometry has two dense
queries and a separate dense/singular schedule. Width-two cases explicitly check
noncommuting matrices. The singular schedule puts its projector at the final
fold, so the permitted response rank is genuinely deficient; the audit computes
that rank rather than assuming one independent constraint per output lane.
A negative control adds an original witness coefficient outside the permitted
view and must increase the augmented rank.

This is a finite conditional field-value audit. It does not prove an adaptive
zero-knowledge theorem, Merkle/random-oracle hiding, a uniform vector-proximity
bound, or hiding of noncanonical serialized field representations. Hash values,
challenge dependence and representation bytes require separate analysis. The
small-prime/query fixtures are not concrete 128-bit parameter profiles.

All eight rank cases pass, covering sixteen decoded openings, and every negative
control increases rank. The genuinely singular schedules have permitted-response
ranks one and three for widths one and two, respectively; the dense schedules
have ranks two and four. All 65 selected release/locked regressions pass (46 PCS
unit tests, four masked adapters, eight ordinary adapters and seven encoders).
The eight checked records, full log and validated sources are under
`target/performance/direct-packed-polyfrim-disclosure/`; source SHA-256 is
`1785caaeefabb3ce6af5a3f785feab8897d4503c93fc21b6fc6e17133831ddac`.
