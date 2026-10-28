use algebra::{AbstractExtensionField, NTTField, matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::packed_relation::batch;
use sumcheck::packed::PackedShape;

fn exercise<F, EF>(k: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    for count in [1, 4, 16] {
        let n = k.ilog2() as usize + 1;
        let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(n, k, 32, 2).unwrap();
        let mut shapes = Vec::new();
        let mut factors = Vec::new();
        for instance in 0..count {
            let coefficient = F::from(instance + 1);
            let a: Vec<_> = (0..(1 << n) * k)
                .map(|i| F::from(1 + (i * 3 + instance) % 11))
                .collect();
            let b: Vec<_> = (0..a.len())
                .map(|i| F::from(2 + (i * 7 + instance) % 17))
                .collect();
            let c = a
                .iter()
                .zip(&b)
                .map(|(&a, &b)| coefficient * a * b)
                .collect();
            shapes.push(PackedShape {
                num_vars: n,
                width: k,
                num_factors: 3,
                terms: vec![(coefficient, vec![0, 1]), (-F::one(), vec![2])],
            });
            factors.push(vec![
                PackedTable::new(n, k, a).unwrap(),
                PackedTable::new(n, k, b).unwrap(),
                PackedTable::new(n, k, c).unwrap(),
            ]);
            // Different trusted factor counts exercise grouped root/claim cuts.
            if instance % 2 == 1 {
                shapes.last_mut().unwrap().num_factors = 4;
                shapes.last_mut().unwrap().terms[0].1.push(3);
                factors
                    .last_mut()
                    .unwrap()
                    .push(PackedTable::new(n, k, vec![F::one(); (1 << n) * k]).unwrap());
            }
        }
        let pairs: Vec<Vec<_>> = factors
            .iter()
            .map(|t| {
                t.iter()
                    .map(|t| pp.commit::<F, Sha256>(t).unwrap())
                    .collect()
            })
            .collect();
        let roots: Vec<Vec<_>> = pairs
            .iter()
            .map(|p| p.iter().map(|(r, _)| r.clone()).collect())
            .collect();
        let states: Vec<Vec<_>> = pairs
            .iter()
            .map(|p| p.iter().map(|(_, s)| s).collect())
            .collect();
        let refs: Vec<_> = factors.iter().map(Vec::as_slice).collect();
        let mut prover = Transcript::new_direct();
        let proof =
            batch::prove::<F, EF, Sha256, _>(&mut prover, &shapes, &pp, &refs, &roots, &states)
                .unwrap();
        let borrowed: Vec<Vec<_>> = factors
            .iter()
            .map(|tables| tables.iter().collect())
            .collect();
        let borrowed_slices: Vec<_> = borrowed.iter().map(Vec::as_slice).collect();
        let mut borrowed_trans = Transcript::new_direct();
        let borrowed_proof = batch::prove_borrowed::<F, EF, Sha256, _>(
            &mut borrowed_trans,
            &shapes,
            &pp,
            &borrowed_slices,
            &roots,
            &states,
        )
        .unwrap();
        assert_eq!(
            bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap(),
            bincode::serde::encode_to_vec(&borrowed_proof, bincode::config::standard()).unwrap()
        );
        let after_owned = prover.get_challenge(b"borrowed equivalence");
        assert_eq!(
            after_owned,
            borrowed_trans.get_challenge(b"borrowed equivalence")
        );
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (batch::Proof<F, EF, [u8; 32]>, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let mut verifier = Transcript::new_direct();
        batch::verify::<F, EF, Sha256, _>(&mut verifier, &shapes, &pp, &roots, &proof).unwrap();
        assert_eq!(after_owned, verifier.get_challenge(b"borrowed equivalence"));
        assert_eq!(
            prover.get_challenge(b"after batch relation"),
            verifier.get_challenge(b"after batch relation")
        );
        let reject = |shapes: &[_], roots: &[_], proof: &_| {
            assert!(
                batch::verify::<F, EF, Sha256, _>(
                    &mut Transcript::new_direct(),
                    shapes,
                    &pp,
                    roots,
                    proof
                )
                .is_err()
            )
        };
        let mut bad = proof.clone();
        bad.zero.instances.pop();
        reject(&shapes, &roots, &bad);
        let mut bad = proof.clone();
        bad.values.pop();
        reject(&shapes, &roots, &bad);
        let mut bad = proof.clone();
        bad.values[0].pop();
        reject(&shapes, &roots, &bad);
        let mut bad = proof.clone();
        bad.values[0][0].pop();
        reject(&shapes, &roots, &bad);
        let mut bad = proof.clone();
        bad.values[0][0][0] += F::one();
        reject(&shapes, &roots, &bad);
        let mut bad = proof.clone();
        bad.opening.columns[0][0].values[0] += F::one();
        reject(&shapes, &roots, &bad);
        let mut wrong = roots.clone();
        wrong[0][0].root[0] ^= 1;
        reject(&shapes, &wrong, &proof);
        let mut wrong = shapes.clone();
        wrong[0].terms[0].0 += F::one();
        reject(&wrong, &roots, &proof);
        if count > 1 {
            let mut bad = proof.clone();
            bad.zero.instances.swap(0, 1);
            reject(&shapes, &roots, &bad);
            let mut bad = proof.clone();
            bad.values.swap(0, 1);
            reject(&shapes, &roots, &bad);
            let mut wrong = roots.clone();
            wrong.swap(0, 1);
            reject(&shapes, &wrong, &proof);
        }
        assert!(
            batch::prove::<F, EF, Sha256, _>(
                &mut Transcript::new_direct(),
                &shapes,
                &pp,
                &refs,
                &roots,
                &states[..count - 1]
            )
            .is_err()
        );
        reject(&[], &[], &proof);
    }
}
#[test]
fn babybear_joint_relation_batch() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
}
#[test]
fn goldilocks_joint_relation_batch() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}
