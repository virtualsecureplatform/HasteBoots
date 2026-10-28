use algebra::{AbstractExtensionField, NTTField, matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript, Transcript};
use pcs::matrix_weighted::{
    backend::CanonicalPcs,
    masked_polyfrim::{Parameters, Proof},
};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_oracle::CanonicalProverOracle,
    packed_relation::{self, CanonicalRelationProof, ProverStatistics},
};
use sumcheck::{packed::PackedShape, packed_zero};
#[allow(dead_code)]
#[path = "support/legacy_packed_relation_v1.rs"]
mod legacy;

fn exercise<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let tables = packed_relation::pack_rows(
        2,
        &[
            &(1usize..14).map(F::from).collect::<Vec<_>>(),
            &(1usize..14).map(|i| F::from(i + 3)).collect::<Vec<_>>(),
            &(1usize..14)
                .map(|i| F::from(i) * F::from(i + 3))
                .collect::<Vec<_>>(),
        ],
    )
    .unwrap();
    let n = tables[0].num_vars();
    let shape = PackedShape {
        num_vars: n,
        width: 2,
        num_factors: 3,
        terms: vec![(F::one(), vec![0, 1]), (-F::one(), vec![2])],
    };
    let pp: Vec<_> = (0..3)
        .map(|i| Parameters::<F, EF>::new(n, 2, 10 + i % 2, 2, 1, 1).unwrap())
        .collect();
    let (roots, states): (Vec<_>, Vec<_>) = tables
        .iter()
        .enumerate()
        .map(|(i, t)| {
            CanonicalPcs::<F, Sha256>::commit(&pp[i], t, &mut StdRng::seed_from_u64(731 + i as u64))
                .unwrap()
        })
        .unzip();
    let sources: Vec<_> = (0..3)
        .map(|i| CanonicalProverOracle::<F, Sha256, _> {
            parameters: &pp[i],
            commitment: &roots[i],
            state: &states[i],
        })
        .collect();
    let refs: Vec<_> = sources.iter().collect();
    let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    let mut prover = Transcript::new_direct();
    let proof = packed_relation::prove_canonical::<F, Sha256, _>(
        &mut prover,
        &shape,
        &refs,
        &mut ProverStatistics::default(),
    )
    .unwrap();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (CanonicalRelationProof<F, Proof<EF, [u8; 32]>>, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut verifier = Transcript::new_direct();
    packed_relation::verify_canonical::<F, Sha256, _>(&mut verifier, &shape, &public, &proof)
        .unwrap();
    assert_eq!(
        prover.get_challenge(b"after"),
        verifier.get_challenge(b"after")
    );
    assert!(states.iter().all(|s| s.spent().unwrap() == 1));
    let mut bad = proof.clone();
    bad.values[0][0] += F::one();
    assert!(
        packed_relation::verify_canonical::<F, Sha256, _>(
            &mut Transcript::new_direct(),
            &shape,
            &public,
            &bad
        )
        .is_err()
    );
    let mut bad = proof.clone();
    bad.openings.pop();
    assert!(
        packed_relation::verify_canonical::<F, Sha256, _>(
            &mut Transcript::new_direct(),
            &shape,
            &public,
            &bad
        )
        .is_err()
    );
    let mut wrong = roots.clone();
    wrong[0].root[0] ^= 1;
    let mut public = sources.iter().map(|s| s.verifier()).collect::<Vec<_>>();
    public[0].commitment = &wrong[0];
    assert!(
        packed_relation::verify_canonical::<F, Sha256, _>(
            &mut Transcript::new_direct(),
            &shape,
            &public,
            &proof
        )
        .is_err()
    );
    // Independently compare borrowed and owned ZeroCheck messages and terminal data.
    let mut owned = Transcript::new_direct();
    let mut borrowed = Transcript::new_direct();
    let a = packed_zero::prove_with_terminal_values(&mut owned, &shape, &tables).unwrap();
    let b = packed_zero::prove_with_borrowed_terminal_values(
        &mut borrowed,
        &shape,
        &tables.iter().collect::<Vec<_>>(),
    )
    .unwrap();
    assert_eq!(
        bincode::serde::encode_to_vec(&(a.0, a.2), bincode::config::standard()).unwrap(),
        bincode::serde::encode_to_vec(&(b.0, b.2), bincode::config::standard()).unwrap()
    );
    assert_eq!(
        owned.get_challenge(b"after"),
        borrowed.get_challenge(b"after")
    );
    // Frozen legacy implementation establishes byte and transcript compatibility.
    let old = pcs::matrix_weighted::Parameters::balanced_block_rs(n, 2, 8, 2).unwrap();
    let (roots, states): (Vec<_>, Vec<_>) = tables
        .iter()
        .map(|t| old.commit::<F, Sha256>(t).unwrap())
        .unzip();
    let mut a = Transcript::new_direct();
    let mut b = Transcript::new_direct();
    let current =
        packed_relation::prove::<F, Sha256, _>(&mut a, &shape, &old, &tables, &roots, &states)
            .unwrap();
    let frozen =
        legacy::prove::<F, Sha256, _>(&mut b, &shape, &old, &tables, &roots, &states).unwrap();
    assert_eq!(
        bincode::serde::encode_to_vec(&current, bincode::config::standard()).unwrap(),
        bincode::serde::encode_to_vec(&frozen, bincode::config::standard()).unwrap()
    );
    assert_eq!(a.get_challenge(b"after"), b.get_challenge(b"after"));
    let mut a = Transcript::new_direct();
    let mut b = Transcript::new_direct();
    packed_relation::verify::<F, Sha256, _>(&mut a, &shape, &old, &roots, &current).unwrap();
    legacy::verify::<F, Sha256, _>(&mut b, &shape, &old, &roots, &frozen).unwrap();
    assert_eq!(a.get_challenge(b"after"), b.get_challenge(b"after"));
}
#[test]
fn babybear() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}

fn false_relation<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let pp = Parameters::<F, EF>::new(2, 2, 10, 2, 1, 1).unwrap();
    let shape = PackedShape {
        num_vars: 2,
        width: 2,
        num_factors: 3,
        terms: vec![(F::one(), vec![0, 1]), (-F::one(), vec![2])],
    };
    let actual: Vec<_> = [1usize, 2, 3]
        .map(|v| PackedTable::new(2, 2, vec![F::from(v); 8]).unwrap())
        .into();
    let fake: Vec<_> = [1usize, 2, 2]
        .map(|v| PackedTable::new(2, 2, vec![F::from(v); 8]).unwrap())
        .into();
    let (roots, states): (Vec<_>, Vec<_>) = actual
        .iter()
        .enumerate()
        .map(|(i, t)| {
            CanonicalPcs::<F, Sha256>::commit(&pp, t, &mut StdRng::seed_from_u64(991 + i as u64))
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
    assert!(
        packed_relation::prove_canonical::<F, Sha256, _>(
            &mut Transcript::new_direct(),
            &shape,
            &sources.iter().collect::<Vec<_>>(),
            &mut ProverStatistics::default()
        )
        .is_err()
    );
    assert!(states.iter().all(|s| s.spent().unwrap() == 0));
    let context = CanonicalPcs::<F, Sha256>::context(&pp).unwrap();
    let bind = |t: &mut Transcript<F>| {
        t.append_message(
            <Parameters<F, EF> as CanonicalPcs<F, Sha256>>::RELATION_DOMAIN,
            &(
                &shape,
                vec![context.clone(); 3],
                roots.iter().collect::<Vec<_>>(),
            ),
        )
    };
    let mut prover = Transcript::new_direct();
    bind(&mut prover);
    let (zero, subclaim, _) =
        packed_zero::prove_with_terminal_values(&mut prover, &shape, &fake).unwrap();
    let values: Vec<_> = actual
        .iter()
        .map(|t| {
            t.evaluate(&subclaim.query)
                .unwrap()
                .into_iter()
                .map(|v| v.canonicalized())
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(subclaim.check(&shape, &values).is_err());
    prover.append_message(b"packed relation terminal values", &values);
    let openings = (0..3)
        .map(|i| {
            CanonicalPcs::<F, Sha256>::open(
                &pp,
                &mut prover,
                &roots[i],
                &states[i],
                &subclaim.query,
                &values[i],
            )
            .unwrap()
        })
        .collect();
    let proof = CanonicalRelationProof {
        zero,
        values,
        openings,
    };
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (CanonicalRelationProof<F, Proof<EF, [u8; 32]>>, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    // Every child authenticates the actual requested root. Only the identity fails.
    let mut reference = Transcript::new_direct();
    bind(&mut reference);
    let terminal = packed_zero::verify(&mut reference, &shape, &proof.zero).unwrap();
    reference.append_message(b"packed relation terminal values", &proof.values);
    for i in 0..3 {
        CanonicalPcs::<F, Sha256>::verify(
            &pp,
            &mut reference,
            &roots[i],
            &terminal.query,
            &proof.values[i],
            &proof.openings[i],
        )
        .unwrap();
    }
    assert_eq!(
        prover.get_challenge(b"after"),
        reference.get_challenge(b"after")
    );
    let error = packed_relation::verify_canonical::<F, Sha256, _>(
        &mut Transcript::new_direct(),
        &shape,
        &sources.iter().map(|s| s.verifier()).collect::<Vec<_>>(),
        &proof,
    )
    .unwrap_err();
    assert!(error.to_string().contains("terminal identity"), "{error}");
}
#[test]
fn babybear_false_identity() {
    false_relation::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks_false_identity() {
    false_relation::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}
