# Streamed shared-comparison decomposition batches

`packed_decomposition::batch` proves ordered independent canonical decompositions
against caller-supplied source and digit roots. The verifier derives all lookup
requests and group boundaries. `MAX_GROUP = 4` is a transcript-bound protocol
constant; proof fields do not choose routing or omit comparison obligations.
All sources and digits must share one complete PCS parameter context.

The transcript first binds every trusted configuration, source/digit root and
helper context. For each group, it independently verifies every member's
reconstruction and zero borrow endpoints, fixes that group's borrow roots, and
then checks the shared-query comparison packet. Every digit/borrow transition
remains a separate scalar equation. The next group starts only after the previous
comparison packet has been bound. Later borrow choices can depend on earlier
transcript messages, but each group's source/helper words are fixed before its
own fresh lookup challenges.

The prover moves private borrow commitment states into a group owner, lends their
immutable original words through `State::table()`, and drops those states after
the group's comparison proof. It neither clones nor recommits borrow words.
The older decomposition entry points delegate to the same implementation with
retention disabled. Member proofs carry comparison markers, and there is no
public standalone verifier for that partial member format; the public batch
verifier always checks the outer comparisons.

Grouping limits simultaneous additional borrow states and helper-polynomial
work to four decompositions. Digit counts and repetitions still determine group
cost, while caller-owned inputs and final proof size scale with the whole batch.
This is not a fixed total-memory guarantee. Separate parameter contexts require
separate calls. The component is experimental and non-hiding; integration into
complete cross-statement PBS remains unfinished.

## Evidence

Both selected fields pass decoded 1/4/5/16-member batches, including mixed radix
sizes 8/5, repetition counts 1/2, partial prefixes, zero, p-1 and p-2. The
five-member case exercises a partial final group. All eight batch certificates
cover 52 decompositions; prover and verifier post-proof transcript challenges
agree. Missing groups, partial-member markers, terminal mutations, root/parameter
changes and reordered groups reject.

Six reconstructed batch certificates pass their expected outcomes. Each has two
members with valid linear reconstruction and endpoint proofs. In four attacks,
one member's first digit is 256 in a radix-256 decomposition, while its source
is also 256, so the linear equation holds but digit membership is false. Fresh
foreign helper algebra and actual-root openings pass local reference checks;
the public batch verifier rejects the reciprocal identity. Both honest controls
pass, with attacks placed first and last. No honest-proof transcript replay is
used.

Seventeen targeted release tests pass, including existing decomposition formats
and four complete v8 tests with twenty reconstructed full certificates. All
84 current-source v5/v8 toy wire controls match archived proof bytes/hashes.
Evidence, frozen sources, commands and audit logs are under
`target/performance/batched-decompositions/`. Native batch-component memory,
complete PBS composition, full security and promotion remain open gates.
