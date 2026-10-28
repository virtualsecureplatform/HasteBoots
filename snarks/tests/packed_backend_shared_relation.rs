use algebra::{AbstractExtensionField, NTTField, matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript, Transcript};
use pcs::matrix_weighted::{
    backend::CanonicalPcs,
    masked_polyfrim::{Parameters, Proof as MaskedProof},
};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_opening_batch::CanonicalOpeningBatch,
    packed_oracle::CanonicalProverOracle,
    packed_relation::{
        self,
        batch::backend::{self, Proof},
    },
};
use sumcheck::{packed::PackedShape, packed_zero::batch as zero};
fn shape<F: NTTField>() -> PackedShape<F> {
    PackedShape {
        num_vars: 2,
        width: 2,
        num_factors: 3,
        terms: vec![(F::one(), vec![0, 1]), (-F::one(), vec![2])],
    }
}
fn exercise<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    for (count, physical) in [(1, 10), (4, 11), (16, 13)] {
        let pp = Parameters::<F, EF>::new(2, 2, physical, 2, 1, count).unwrap();
        let a: Vec<_> = (1usize..8).map(F::from).collect();
        let b: Vec<_> = (1usize..8).map(|i| F::from(i + 5)).collect();
        let c: Vec<_> = a.iter().zip(&b).map(|(&a, &b)| a * b).collect();
        let tables = packed_relation::pack_rows(2, &[&a, &b, &c]).unwrap();
        let (roots, states): (Vec<_>, Vec<_>) = tables
            .iter()
            .enumerate()
            .map(|(i, t)| {
                CanonicalPcs::<F, Sha256>::commit(
                    &pp,
                    t,
                    &mut StdRng::seed_from_u64(320 + i as u64),
                )
                .unwrap()
            })
            .unzip();
        let sources: Vec<_> = (0..3)
            .map(|i| CanonicalProverOracle::<F, Sha256, _> {
                parameters: &pp,
                commitment: &roots[i],
                state: &states[i],
            })
            .collect();
        let groups: Vec<Vec<_>> = (0..count).map(|_| sources.iter().collect()).collect();
        let shapes = vec![shape(); count];
        let public: Vec<Vec<_>> = (0..count)
            .map(|_| sources.iter().map(|s| s.verifier()).collect())
            .collect();
        let mut prover = Transcript::new_direct();
        let proof = backend::prove::<F, Sha256, _>(&mut prover, &shapes, &groups).unwrap();
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (Proof<F, MaskedProof<EF, [u8; 32]>>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(proof.opening.openings.len(), 3);
        let mut verifier = Transcript::new_direct();
        backend::verify::<F, Sha256, _>(&mut verifier, &shapes, &public, &proof).unwrap();
        assert_eq!(
            prover.get_challenge(b"after"),
            verifier.get_challenge(b"after")
        );
        assert!(states.iter().all(|s| s.spent().unwrap() == count));
        let mut bad = proof.clone();
        bad.values[0][0][0] += F::one();
        assert!(
            backend::verify::<F, Sha256, _>(&mut Transcript::new_direct(), &shapes, &public, &bad)
                .is_err()
        );
        let mut bad = proof.clone();
        bad.opening.openings.pop();
        assert!(
            backend::verify::<F, Sha256, _>(&mut Transcript::new_direct(), &shapes, &public, &bad)
                .is_err()
        );
        let mut bad = proof.clone();
        bad.zero.instances.pop();
        assert!(
            backend::verify::<F, Sha256, _>(&mut Transcript::new_direct(), &shapes, &public, &bad)
                .is_err()
        );
        let mut bad_shapes = shapes.clone();
        bad_shapes[0].terms[0].0 += F::one();
        assert!(
            backend::verify::<F, Sha256, _>(
                &mut Transcript::new_direct(),
                &bad_shapes,
                &public,
                &proof
            )
            .is_err()
        );
        // A reused root cannot obtain a refreshed private mask through another group.
        assert!(
            backend::prove::<F, Sha256, _>(&mut Transcript::new_direct(), &shapes, &groups)
                .is_err()
        );
        assert!(states.iter().all(|s| s.spent().unwrap() == count));
        println!(
            "HB_BACKEND_SHARED_RELATION {{\"prime\":{},\"relations\":{},\"root_packets\":3,\"child_openings\":{},\"native_pbs\":false,\"joint_aggregation\":false,\"whole_security_certified\":false}}",
            F::MODULUS_VALUE,
            count,
            3 * count
        );
    }
}
fn opposite<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let pp = Parameters::<F, EF>::new(2, 2, 11, 2, 1, 4).unwrap();
    let actual: Vec<_> = [1usize, 0, 2]
        .map(|v| PackedTable::new(2, 2, vec![F::from(v); 8]).unwrap())
        .into();
    let (roots, states): (Vec<_>, Vec<_>) = actual
        .iter()
        .enumerate()
        .map(|(i, t)| {
            CanonicalPcs::<F, Sha256>::commit(&pp, t, &mut StdRng::seed_from_u64(931 + i as u64))
                .unwrap()
        })
        .unzip();
    let sources: Vec<_> = (0..3)
        .map(|i| CanonicalProverOracle::<F, Sha256, _> {
            parameters: &pp,
            commitment: &roots[i],
            state: &states[i],
        })
        .collect();
    let groups = vec![
        vec![&sources[0], &sources[0], &sources[1]],
        vec![&sources[0], &sources[0], &sources[2]],
    ];
    let public: Vec<Vec<_>> = groups
        .iter()
        .map(|g| g.iter().map(|s| s.verifier()).collect())
        .collect();
    let shapes = vec![shape::<F>(); 2];
    assert!(
        backend::prove::<F, Sha256, _>(&mut Transcript::new_direct(), &shapes, &groups).is_err()
    );
    assert!(states.iter().all(|s| s.spent().unwrap() == 0));
    let flat: Vec<_> = public
        .iter()
        .flatten()
        .map(|s| snarks::packed_oracle::CanonicalVerifierOracle {
            parameters: s.parameters,
            commitment: s.commitment,
        })
        .collect();
    let bind = |t: &mut Transcript<F>| {
        t.append_message(b"HasteBoots backend shared-challenge relations v1", &shapes);
        CanonicalOpeningBatch::<F, Sha256, _>::new(t, &flat).unwrap()
    };
    let mut prover = Transcript::new_direct();
    let mut registry = bind(&mut prover);
    let fake = vec![PackedTable::new(2, 2, vec![F::one(); 8]).unwrap(); 3];
    let (zero, claims, _) = zero::prove(&mut prover, &shapes, &[&fake, &fake]).unwrap();
    let values: Vec<Vec<_>> = groups
        .iter()
        .map(|g| {
            g.iter()
                .map(|s| {
                    s.table()
                        .evaluate(&claims[0].query)
                        .unwrap()
                        .into_iter()
                        .map(|v| v.canonicalized())
                        .collect::<Vec<_>>()
                })
                .collect()
        })
        .collect();
    for (s, v) in claims.iter().zip(&values) {
        assert!(s.check(&shapes[0], v).is_err());
    }
    // The two actual pointwise residuals are +1 and -1. Neither may be hidden by cancellation.
    for row in 0..4 {
        let left = shapes[0]
            .evaluate(&vec![
                actual[0].at(row).to_vec(),
                actual[0].at(row).to_vec(),
                actual[1].at(row).to_vec(),
            ])
            .unwrap();
        let right = shapes[1]
            .evaluate(&vec![
                actual[0].at(row).to_vec(),
                actual[0].at(row).to_vec(),
                actual[2].at(row).to_vec(),
            ])
            .unwrap();
        assert!(
            left.iter()
                .zip(right)
                .all(|(&a, b)| a != F::zero() && a + b == F::zero())
        );
    }
    prover.append_message(b"packed backend batch relation terminal values", &values);
    for (slot, value) in values.iter().flatten().enumerate() {
        registry
            .push(&mut prover, slot, claims[0].query.clone(), value.clone())
            .unwrap();
    }
    let opening = registry
        .prove(
            &mut prover,
            &groups.iter().flatten().map(|s| s.state).collect::<Vec<_>>(),
        )
        .unwrap();
    let proof = Proof {
        zero,
        values,
        opening,
    };
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (Proof<F, MaskedProof<EF, [u8; 32]>>, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut reference = Transcript::new_direct();
    let mut registry = bind(&mut reference);
    let checked = zero::verify(&mut reference, &shapes, &proof.zero).unwrap();
    reference.append_message(
        b"packed backend batch relation terminal values",
        &proof.values,
    );
    for (slot, value) in proof.values.iter().flatten().enumerate() {
        registry
            .push(
                &mut reference,
                slot,
                checked[0].query.clone(),
                value.clone(),
            )
            .unwrap();
    }
    registry.verify(&mut reference, &proof.opening).unwrap();
    assert_eq!(
        prover.get_challenge(b"after"),
        reference.get_challenge(b"after")
    );
    assert_eq!(
        states
            .iter()
            .map(|s| s.spent().unwrap())
            .collect::<Vec<_>>(),
        vec![4, 1, 1]
    );
    let err =
        backend::verify::<F, Sha256, _>(&mut Transcript::new_direct(), &shapes, &public, &proof)
            .unwrap_err();
    assert!(err.to_string().contains("terminal identity"), "{err}");
    println!(
        "HB_BACKEND_SHARED_FORGERY {{\"prime\":{},\"strict_child_openings\":6,\"production_accepted\":false,\"native_pbs\":false}}",
        F::MODULUS_VALUE
    );
}
#[test]
fn babybear() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}
#[test]
fn babybear_opposite() {
    opposite::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks_opposite() {
    opposite::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}

#[test]
fn brakedown_shared_backend() {
    use algebra::{BabyBear as F, Field};
    use pcs::matrix_weighted::{BatchOpening, Parameters as BaseParameters};
    let pp = BaseParameters::balanced_block_rs(2, 2, 8, 2).unwrap();
    let tables: Vec<_> = [1u32, 2, 2]
        .map(|v| PackedTable::new(2, 2, vec![F::new(v); 8]).unwrap())
        .into();
    let (roots, states): (Vec<_>, Vec<_>) = tables
        .iter()
        .map(|t| pp.commit::<F, Sha256>(t).unwrap())
        .unzip();
    let sources: Vec<_> = (0..3)
        .map(|i| CanonicalProverOracle::<F, Sha256, _> {
            parameters: &pp,
            commitment: &roots[i],
            state: &states[i],
        })
        .collect();
    let groups: Vec<Vec<_>> = (0..4).map(|_| sources.iter().collect()).collect();
    let public: Vec<Vec<_>> = groups
        .iter()
        .map(|g| g.iter().map(|s| s.verifier()).collect())
        .collect();
    let shapes = vec![shape::<F>(); 4];
    let mut prover = Transcript::new_direct();
    let proof = backend::prove::<F, Sha256, _>(&mut prover, &shapes, &groups).unwrap();
    // The two equal source roots alias under the same context.
    assert_eq!(proof.opening.openings.len(), 2);
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (Proof<F, BatchOpening<F, [u8; 32]>>, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut verifier = Transcript::new_direct();
    backend::verify::<F, Sha256, _>(&mut verifier, &shapes, &public, &proof).unwrap();
    assert_eq!(
        prover.get_challenge(b"after"),
        verifier.get_challenge(b"after")
    );
    let mut swapped = public;
    swapped[0].swap(0, 1);
    assert!(
        backend::verify::<F, Sha256, _>(&mut Transcript::new_direct(), &shapes, &swapped, &proof)
            .is_err()
    );
}
