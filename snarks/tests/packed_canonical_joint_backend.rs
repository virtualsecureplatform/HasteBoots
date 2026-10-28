use algebra::{
    AbstractExtensionField, NTTField,
    matrix_weighted::{Matrix, MatrixPair, PackedTable},
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::matrix_weighted::{
    backend::CanonicalPcs,
    masked_polyfrim::joint::{Parameters, Proof as MaskedProof},
};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_opening_batch::{CanonicalOpeningBatch, CanonicalProof},
    packed_oracle::CanonicalProverOracle,
};

fn exercise<F, EF>()
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let pp = vec![
        Parameters::<F, EF>::new(3, 2, 13, 2, 1, 12).unwrap(),
        Parameters::new(2, 2, 13, 2, 1, 10).unwrap(),
        Parameters::new(3, 2, 10, 2, 1, 1).unwrap(),
    ];
    let mut roots = Vec::new();
    let mut states = Vec::new();
    for (j, p) in pp.iter().enumerate() {
        let table = PackedTable::new(
            p.num_vars(),
            2,
            (0..(1usize << p.num_vars()) * 2)
                .map(|i| F::from(i * i + j + 7))
                .collect(),
        )
        .unwrap();
        let (root, state) = CanonicalPcs::<F, Sha256>::commit(
            p,
            &table,
            &mut StdRng::seed_from_u64(400 + j as u64),
        )
        .unwrap();
        roots.push(root);
        states.push(state);
    }
    let slots = [0, 1, 0, 2];
    let sources: Vec<_> = slots
        .iter()
        .map(|&i| CanonicalProverOracle::<F, Sha256, _> {
            parameters: &pp[i],
            commitment: &roots[i],
            state: &states[i],
        })
        .collect();
    let oracles: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    let references: Vec<_> = sources.iter().map(|s| s.state).collect();
    let mut start = 0;
    for count in [1, 4, 16] {
        let claims: Vec<_> = (0..count)
            .map(|i| {
                let slot = if i % 2 == 1 {
                    1
                } else if i % 4 == 0 {
                    0
                } else {
                    2
                };
                let source = &sources[slot];
                let query: Vec<_> = (0..source.parameters.num_vars())
                    .map(|v| MatrixPair {
                        zero: Matrix::new(
                            2,
                            (0..4).map(|j| F::from(start + i + v + 2 * j + 1)).collect(),
                        )
                        .unwrap(),
                        one: Matrix::new(
                            2,
                            (0..4)
                                .map(|j| F::from(2 * start + 3 * i + v + j * j + 3))
                                .collect(),
                        )
                        .unwrap(),
                    })
                    .collect();
                let value = source.table().evaluate(&query).unwrap();
                (slot, query, value)
            })
            .collect();
        let build = |t: &mut Transcript<F>, claims: &[(usize, Vec<MatrixPair<F>>, Vec<F>)]| {
            let mut batch = CanonicalOpeningBatch::<F, Sha256, _>::new(t, &oracles).unwrap();
            for (slot, query, value) in claims {
                batch.push(t, *slot, query.clone(), value.clone()).unwrap();
            }
            batch
        };
        let mut prover = Transcript::new_direct();
        let batch = build(&mut prover, &claims);
        assert_eq!(batch.claim_count(), count);
        assert_eq!(batch.used_sources(), if count == 1 { 1 } else { 2 });
        let proof = batch.prove(&mut prover, &references).unwrap();
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (CanonicalProof<MaskedProof<EF, [u8; 32]>>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(
            proof
                .openings
                .iter()
                .map(|p| p.responses.len())
                .sum::<usize>(),
            count
        );
        let mut verifier = Transcript::new_direct();
        build(&mut verifier, &claims)
            .verify(&mut verifier, &proof)
            .unwrap();
        assert_eq!(
            prover.get_challenge(b"canonical backend after"),
            verifier.get_challenge(b"canonical backend after")
        );
        assert_eq!(states[2].spent().unwrap(), 0);
        let mut changed = proof.clone();
        changed.openings.pop();
        let mut t = Transcript::new_direct();
        assert!(build(&mut t, &claims).verify(&mut t, &changed).is_err());
        let mut wrong = claims.clone();
        wrong[0].2[0] += F::one();
        let mut t = Transcript::new_direct();
        assert!(build(&mut t, &wrong).verify(&mut t, &proof).is_err());
        if count > 1 {
            let mut wrong = claims.clone();
            wrong.swap(0, 1);
            let mut t = Transcript::new_direct();
            assert!(build(&mut t, &wrong).verify(&mut t, &proof).is_err());
        }
        println!(
            "HB_CANONICAL_JOINT_MASKED_REGISTRY {{\"prime\":{},\"extension_degree\":{},\"claims\":{},\"used_roots\":{},\"root0_spent\":{},\"root1_spent\":{},\"unused_spent\":{},\"verified\":true,\"native_pbs\":false,\"shared_source_proximity\":true,\"full_query_aggregation\":false}}",
            F::MODULUS_VALUE,
            EF::D,
            count,
            proof.openings.len(),
            states[0].spent().unwrap(),
            states[1].spent().unwrap(),
            states[2].spent().unwrap()
        );
        start += count;
    }
    assert_eq!(states[0].spent().unwrap(), 11);
    assert_eq!(states[1].spent().unwrap(), 10);
    // Across roots, a later failure never refunds an already published opening.
    let mut t = Transcript::new_direct();
    let mut batch = CanonicalOpeningBatch::<F, Sha256, _>::new(&mut t, &oracles).unwrap();
    for slot in [0, 1] {
        let query = vec![
            MatrixPair {
                zero: Matrix::identity(2).unwrap(),
                one: Matrix::identity(2).unwrap()
            };
            sources[slot].parameters.num_vars()
        ];
        let value = sources[slot].table().evaluate(&query).unwrap();
        batch.push(&mut t, slot, query, value).unwrap();
    }
    assert!(batch.prove(&mut t, &references).is_err());
    assert_eq!(states[0].spent().unwrap(), 12);
    assert_eq!(states[1].spent().unwrap(), 10);
    assert_eq!(states[2].spent().unwrap(), 0);
    let mut t = Transcript::new_direct();
    let mut batch = CanonicalOpeningBatch::<F, Sha256, _>::new(&mut t, &oracles).unwrap();
    let query = vec![
        MatrixPair {
            zero: Matrix::identity(2).unwrap(),
            one: Matrix::identity(2).unwrap()
        };
        pp[0].num_vars()
    ];
    let value = sources[2].table().evaluate(&query).unwrap();
    batch.push(&mut t, 2, query, value).unwrap();
    assert!(batch.prove(&mut t, &references).is_err());
    assert_eq!(states[0].spent().unwrap(), 12);
}
#[test]
fn babybear_sextic_canonical_registry() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks_cubic_canonical_registry() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}

#[test]
fn masked_registry_binds_canonical_claim_encodings() {
    use algebra::{Field, Goldilocks as F, GoldilocksExtension3 as E};
    let pp = Parameters::<F, E>::new(1, 1, 9, 2, 1, 1).unwrap();
    let table = PackedTable::new(1, 1, vec![F::new(0); 2]).unwrap();
    let (root, a) = pp
        .commit::<Sha256, _>(&table, &mut StdRng::seed_from_u64(2001))
        .unwrap();
    let (other, b) = pp
        .commit::<Sha256, _>(&table, &mut StdRng::seed_from_u64(2001))
        .unwrap();
    assert_eq!(root.root, other.root);
    let source = CanonicalProverOracle::<F, Sha256, _> {
        parameters: &pp,
        commitment: &root,
        state: &a,
    };
    let oracles = [source.verifier()];
    let query = vec![MatrixPair {
        zero: Matrix::new(1, vec![F::new(0)]).unwrap(),
        one: Matrix::new(1, vec![F::new(1)]).unwrap(),
    }];
    let raw = vec![MatrixPair {
        zero: Matrix::new(1, vec![F::new(F::MODULUS_VALUE)]).unwrap(),
        one: Matrix::new(1, vec![F::new(1)]).unwrap(),
    }];
    let mut ta = Transcript::new_direct();
    let mut tb = Transcript::new_direct();
    let mut ba = CanonicalOpeningBatch::<F, Sha256, _>::new(&mut ta, &oracles).unwrap();
    let mut bb = CanonicalOpeningBatch::<F, Sha256, _>::new(&mut tb, &oracles).unwrap();
    ba.push(&mut ta, 0, query, vec![F::new(0)]).unwrap();
    bb.push(&mut tb, 0, raw, vec![F::new(F::MODULUS_VALUE)])
        .unwrap();
    let pa = ba.prove(&mut ta, &[&a]).unwrap();
    let pb = bb.prove(&mut tb, &[&b]).unwrap();
    assert_eq!(
        bincode::serde::encode_to_vec(&pa, bincode::config::standard()).unwrap(),
        bincode::serde::encode_to_vec(&pb, bincode::config::standard()).unwrap()
    );
    assert_eq!(
        ta.get_challenge(b"canonical alias after"),
        tb.get_challenge(b"canonical alias after")
    );
}
