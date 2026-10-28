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
    packed_linear::{self, CanonicalProof, Relation},
    packed_oracle::CanonicalProverOracle,
};
use sumcheck::packed::challenge_pair;

fn exercise<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    for (variables, width) in [(0, 1), (3, 2)] {
        let pp = Parameters::<F, EF>::new(variables, width, 10, 2, 1, 2).unwrap();
        let a: Vec<_> = (0..(1usize << variables) * width)
            .map(|i| F::from(i * i + 5))
            .collect();
        let b: Vec<_> = a.iter().map(|v| *v * F::from(7usize)).collect();
        let c: Vec<_> = a.iter().zip(&b).map(|(&a, &b)| a + b).collect();
        let mut roots = Vec::new();
        let mut states = Vec::new();
        for (i, values) in [a, b, c].into_iter().enumerate() {
            let table = PackedTable::new(variables, width, values).unwrap();
            let (root, state) = CanonicalPcs::<F, Sha256>::commit(
                &pp,
                &table,
                &mut StdRng::seed_from_u64(700 + i as u64),
            )
            .unwrap();
            roots.push(root);
            states.push(state);
        }
        let sources: Vec<_> = roots
            .iter()
            .zip(&states)
            .map(
                |(commitment, state)| CanonicalProverOracle::<F, Sha256, _> {
                    parameters: &pp,
                    commitment,
                    state,
                },
            )
            .collect();
        let references: Vec<_> = sources.iter().collect();
        let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
        let relations = vec![
            Relation {
                terms: vec![(F::from(7usize), 0), (-F::from(1usize), 1)],
            },
            Relation {
                terms: vec![
                    (F::from(1usize), 0),
                    (F::from(1usize), 1),
                    (-F::from(1usize), 2),
                ],
            },
        ];
        let mut prover = Transcript::new_direct();
        let proof =
            packed_linear::prove_canonical::<F, Sha256, _>(&mut prover, &references, &relations)
                .unwrap();
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (CanonicalProof<F, MaskedProof<EF, [u8; 32]>>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        assert!(proof.values.iter().flatten().all(|v| v.is_canonical()));
        let mut verifier = Transcript::new_direct();
        packed_linear::verify_canonical::<F, Sha256, _>(&mut verifier, &public, &relations, &proof)
            .unwrap();
        assert_eq!(
            prover.get_challenge(b"linear canonical after"),
            verifier.get_challenge(b"linear canonical after")
        );
        assert!(states.iter().all(|s| s.spent().unwrap() == 1));
        let mut changed = proof.clone();
        changed.values[0][0] += F::from(1usize);
        assert!(
            packed_linear::verify_canonical::<F, Sha256, _>(
                &mut Transcript::new_direct(),
                &public,
                &relations,
                &changed
            )
            .is_err()
        );
        let mut changed = proof.clone();
        changed.openings[0].openings.clear();
        assert!(
            packed_linear::verify_canonical::<F, Sha256, _>(
                &mut Transcript::new_direct(),
                &public,
                &relations,
                &changed
            )
            .is_err()
        );
        let mut changed = relations.clone();
        changed[0].terms[0].0 += F::from(1usize);
        assert!(
            packed_linear::verify_canonical::<F, Sha256, _>(
                &mut Transcript::new_direct(),
                &public,
                &changed,
                &proof
            )
            .is_err()
        );
        println!(
            r#"HB_MASKED_CANONICAL_LINEAR {{"prime":{},"extension_degree":{},"variables":{},"width":{},"source_count":3,"proof_bytes":{},"verified":true,"native_pbs":false,"whole_security_certified":false}}"#,
            F::MODULUS_VALUE,
            EF::D,
            variables,
            width,
            bytes.len()
        );
    }
}
fn fresh_false<F, EF>()
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
{
    let variables = 2;
    let width = 2;
    let pp = Parameters::<F, EF>::new(variables, width, 10, 2, 1, 1).unwrap();
    let mut roots = Vec::new();
    let mut states = Vec::new();
    for (i, value) in [1, 2, 4].into_iter().enumerate() {
        let table = PackedTable::new(variables, width, vec![F::from(value); 4 * width]).unwrap();
        let (root, state) = CanonicalPcs::<F, Sha256>::commit(
            &pp,
            &table,
            &mut StdRng::seed_from_u64(910 + i as u64),
        )
        .unwrap();
        roots.push(root);
        states.push(state);
    }
    let sources: Vec<_> = roots
        .iter()
        .zip(&states)
        .map(
            |(commitment, state)| CanonicalProverOracle::<F, Sha256, _> {
                parameters: &pp,
                commitment,
                state,
            },
        )
        .collect();
    let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    let relations = vec![Relation {
        terms: vec![
            (F::from(1usize), 0),
            (F::from(1usize), 1),
            (-F::from(1usize), 2),
        ],
    }];
    assert!(
        packed_linear::prove_canonical::<F, Sha256, _>(
            &mut Transcript::new_direct(),
            &sources.iter().collect::<Vec<_>>(),
            &relations
        )
        .is_err()
    );
    assert!(states.iter().all(|s| s.spent().unwrap() == 0));
    let prefix = |t: &mut Transcript<F>| {
        let contexts: Vec<_> = public
            .iter()
            .map(|s| {
                (
                    CanonicalPcs::<F, Sha256>::context(s.parameters).unwrap(),
                    s.commitment,
                )
            })
            .collect();
        t.append_message(
            <Parameters<F, EF> as CanonicalPcs<F, Sha256>>::LINEAR_DOMAIN,
            &(contexts, &relations),
        );
        (0..variables)
            .map(|_| {
                challenge_pair(&t.get_vec_challenge(b"packed linear independent challenges", width))
                    .unwrap()
            })
            .collect::<Vec<_>>()
    };
    let mut prover = Transcript::new_direct();
    let query = prefix(&mut prover);
    let mut values = Vec::new();
    let mut openings = Vec::new();
    for source in &sources {
        let value = source.table().evaluate(&query).unwrap();
        let (q, value) =
            CanonicalPcs::<F, Sha256>::normalize_claim(source.parameters, query.clone(), value)
                .unwrap();
        openings.push(
            CanonicalPcs::<F, Sha256>::open(
                source.parameters,
                &mut prover,
                source.commitment,
                source.state,
                &q,
                &value,
            )
            .unwrap(),
        );
        values.push(value);
    }
    let proof = CanonicalProof { values, openings };
    let mut reference = Transcript::new_direct();
    let query = prefix(&mut reference);
    for (i, source) in public.iter().enumerate() {
        let (q, v) = CanonicalPcs::<F, Sha256>::normalize_claim(
            source.parameters,
            query.clone(),
            proof.values[i].clone(),
        )
        .unwrap();
        CanonicalPcs::<F, Sha256>::verify(
            source.parameters,
            &mut reference,
            source.commitment,
            &q,
            &v,
            &proof.openings[i],
        )
        .unwrap();
    }
    assert_eq!(
        prover.get_challenge(b"fresh false linear after"),
        reference.get_challenge(b"fresh false linear after")
    );
    let error = packed_linear::verify_canonical::<F, Sha256, _>(
        &mut Transcript::new_direct(),
        &public,
        &relations,
        &proof,
    )
    .unwrap_err();
    assert!(error.0.contains("false canonical linear identity"));
    println!(
        r#"HB_MASKED_LINEAR_FORGERY {{"prime":{},"extension_degree":{},"genuine_children":3,"actual_roots_verified":true,"production_accepted":false}}"#,
        F::MODULUS_VALUE,
        EF::D
    );
}
#[test]
fn babybear_sextic_linear() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks_cubic_linear() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}
#[test]
fn babybear_fresh_false_identity() {
    fresh_false::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks_fresh_false_identity() {
    fresh_false::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}

#[test]
fn masked_linear_normalizes_trusted_coefficients_and_rejects_proof_aliases() {
    use algebra::{Field, Goldilocks as F, GoldilocksExtension3 as E};
    let pp = Parameters::<F, E>::new(0, 1, 9, 2, 1, 1).unwrap();
    let table = PackedTable::new(0, 1, vec![F::new(0)]).unwrap();
    let (root, state) =
        CanonicalPcs::<F, Sha256>::commit(&pp, &table, &mut StdRng::seed_from_u64(1701)).unwrap();
    let source = CanonicalProverOracle::<F, Sha256, _> {
        parameters: &pp,
        commitment: &root,
        state: &state,
    };
    let relations = vec![Relation {
        terms: vec![(F::new(1), 0), (-F::new(1), 0)],
    }];
    let mut prover = Transcript::new_direct();
    let proof = packed_linear::prove_canonical::<F, Sha256, _>(&mut prover, &[&source], &relations)
        .unwrap();
    let public = [source.verifier()];
    let alias = vec![Relation {
        terms: vec![(F::new(F::MODULUS_VALUE + 1), 0), (-F::new(1), 0)],
    }];
    let mut verifier = Transcript::new_direct();
    packed_linear::verify_canonical::<F, Sha256, _>(&mut verifier, &public, &alias, &proof)
        .unwrap();
    assert_eq!(
        prover.get_challenge(b"linear codec after"),
        verifier.get_challenge(b"linear codec after")
    );
    let mut changed = proof;
    assert_eq!(changed.values[0][0], F::new(0));
    changed.values[0][0] = F::new(F::MODULUS_VALUE);
    let error = packed_linear::verify_canonical::<F, Sha256, _>(
        &mut Transcript::new_direct(),
        &public,
        &relations,
        &changed,
    )
    .unwrap_err();
    assert!(error.0.contains("noncanonical public packed response"));
}
