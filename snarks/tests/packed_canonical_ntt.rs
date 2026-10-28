use algebra::{
    AbstractExtensionField, NTTField, matrix_weighted::PackedTable, transformation::AbstractNTT,
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::matrix_weighted::{
    backend::CanonicalPcs,
    masked_polyfrim::{Parameters, Proof as MaskedProof},
};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_ntt::{self, CanonicalProof, Shape},
    packed_oracle::CanonicalProverOracle,
};
use sumcheck::packed::challenge_pair;

fn exercise<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    for count in [1usize, 4] {
        let n = 32;
        let width = 2;
        let vars = (n * count / width).ilog2() as usize;
        let cp = Parameters::<F, EF>::new(vars, width, 10, 2, 1, width).unwrap();
        let ep = Parameters::<F, EF>::new(vars, width, 11, 2, 1, width).unwrap();
        let shape = Shape::new_canonical::<F, Sha256, _>(&cp, n).unwrap();
        assert_eq!(shape.num_polynomials(), count);
        let table = F::get_ntt_table(5).unwrap();
        let data: Vec<_> = (0..n * count).map(|i| F::from(i * i + 3 * i + 5)).collect();
        let (coefficients, evaluations) = if count == 1 {
            let mut ev = data.clone();
            for p in ev.chunks_exact_mut(n) {
                table.transform_slice(p);
            }
            (data, ev)
        } else {
            let mut co = data.clone();
            for p in co.chunks_exact_mut(n) {
                table.inverse_transform_slice(p);
            }
            (co, data)
        };
        let coefficients = PackedTable::new(vars, width, coefficients).unwrap();
        let evaluations = PackedTable::new(vars, width, evaluations).unwrap();
        let (cr, cs) =
            CanonicalPcs::<F, Sha256>::commit(&cp, &coefficients, &mut StdRng::seed_from_u64(310))
                .unwrap();
        let (er, es) =
            CanonicalPcs::<F, Sha256>::commit(&ep, &evaluations, &mut StdRng::seed_from_u64(311))
                .unwrap();
        let co = CanonicalProverOracle::<F, Sha256, _> {
            parameters: &cp,
            commitment: &cr,
            state: &cs,
        };
        let ev = CanonicalProverOracle::<F, Sha256, _> {
            parameters: &ep,
            commitment: &er,
            state: &es,
        };
        let mut prover = Transcript::new_direct();
        let proof =
            packed_ntt::prove_canonical::<F, Sha256, _>(&mut prover, &shape, &co, &ev).unwrap();
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (CanonicalProof<F, MaskedProof<EF, [u8; 32]>>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        assert!(
            proof
                .coefficients
                .iter()
                .chain(&proof.evaluations)
                .flatten()
                .all(|v| v.is_canonical())
        );
        let mut verifier = Transcript::new_direct();
        packed_ntt::verify_canonical::<F, Sha256, _>(
            &mut verifier,
            &shape,
            &co.verifier(),
            &ev.verifier(),
            &proof,
        )
        .unwrap();
        assert_eq!(
            prover.get_challenge(b"canonical NTT after"),
            verifier.get_challenge(b"canonical NTT after")
        );
        assert_eq!(cs.spent().unwrap(), width);
        assert_eq!(es.spent().unwrap(), width);
        assert_eq!(proof.coefficient_opening.openings.len(), width);
        assert_eq!(proof.evaluation_opening.openings.len(), width);
        let mut changed = proof.clone();
        changed.coefficients[0][0] += F::from(1usize);
        assert!(
            packed_ntt::verify_canonical::<F, Sha256, _>(
                &mut Transcript::new_direct(),
                &shape,
                &co.verifier(),
                &ev.verifier(),
                &changed
            )
            .is_err()
        );
        let mut changed = proof.clone();
        changed.coefficient_opening.openings.pop();
        assert!(
            packed_ntt::verify_canonical::<F, Sha256, _>(
                &mut Transcript::new_direct(),
                &shape,
                &co.verifier(),
                &ev.verifier(),
                &changed
            )
            .is_err()
        );
        assert!(
            packed_ntt::verify_canonical::<F, Sha256, _>(
                &mut Transcript::new_direct(),
                &shape,
                &ev.verifier(),
                &co.verifier(),
                &proof
            )
            .is_err()
        );
        if count > 1 {
            let other = Shape::new_canonical::<F, Sha256, _>(&cp, 64).unwrap();
            assert!(
                packed_ntt::verify_canonical::<F, Sha256, _>(
                    &mut Transcript::new_direct(),
                    &other,
                    &co.verifier(),
                    &ev.verifier(),
                    &proof
                )
                .is_err()
            );
        } else {
            assert!(Shape::new_canonical::<F, Sha256, _>(&cp, 64).is_err());
        }
        println!(
            r#"HB_MASKED_CANONICAL_NTT {{"prime":{},"extension_degree":{},"polynomial_size":32,"polynomials":{},"width":2,"inverse_derived":{},"source_openings":4,"proof_bytes":{},"verified":true,"native_pbs":false,"whole_security_certified":false}}"#,
            F::MODULUS_VALUE,
            EF::D,
            count,
            count == 4,
            bytes.len()
        );
    }
}
fn fresh_false<F, EF>()
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
{
    let width = 2;
    let n = 32;
    let pp = Parameters::<F, EF>::new(4, width, 10, 2, 1, 2).unwrap();
    let shape = Shape::new_canonical::<F, Sha256, _>(&pp, n).unwrap();
    let data: Vec<_> = (0..n).map(|i| F::from(i + 4)).collect();
    let mut wrong = data.clone();
    F::get_ntt_table(5).unwrap().transform_slice(&mut wrong);
    wrong[0] += F::from(1usize);
    let co_table = PackedTable::new(4, width, data.clone()).unwrap();
    let ev_table = PackedTable::new(4, width, wrong.clone()).unwrap();
    let (cr, cs) =
        CanonicalPcs::<F, Sha256>::commit(&pp, &co_table, &mut StdRng::seed_from_u64(381)).unwrap();
    let (er, es) =
        CanonicalPcs::<F, Sha256>::commit(&pp, &ev_table, &mut StdRng::seed_from_u64(382)).unwrap();
    let co = CanonicalProverOracle::<F, Sha256, _> {
        parameters: &pp,
        commitment: &cr,
        state: &cs,
    };
    let ev = CanonicalProverOracle::<F, Sha256, _> {
        parameters: &pp,
        commitment: &er,
        state: &es,
    };
    assert!(
        packed_ntt::prove_canonical::<F, Sha256, _>(
            &mut Transcript::new_direct(),
            &shape,
            &co,
            &ev
        )
        .is_err()
    );
    assert_eq!(cs.spent().unwrap(), 0);
    assert_eq!(es.spent().unwrap(), 0);
    // One polynomial makes tensor-row folding the identity; every declared fold
    // is the actual source word, while its claimed transform identity is false.
    let coefficients = vec![CanonicalPcs::<F, Sha256>::normalize_values(&pp, data); width];
    let evaluations = vec![CanonicalPcs::<F, Sha256>::normalize_values(&pp, wrong); width];
    let prefix = |t: &mut Transcript<F>| {
        let context = CanonicalPcs::<F, Sha256>::context(&pp).unwrap();
        t.append_message(
            <Parameters<F, EF> as CanonicalPcs<F, Sha256>>::NTT_DOMAIN,
            &(
                F::MODULUS_VALUE.to_string(),
                &shape,
                F::get_ntt_table(5).unwrap().root(),
                (context, context),
                &cr,
                &er,
            ),
        );
        for _ in 0..width {
            assert!(
                t.get_vec_challenge(b"packed NTT independent row point", 0)
                    .is_empty()
            );
        }
        t.append_message(
            b"packed NTT folded polynomials",
            &(&coefficients, &evaluations),
        );
        let compression: Vec<_> = (0..shape.coefficient_variables())
            .map(|_| {
                challenge_pair(&t.get_vec_challenge(b"packed NTT coefficient compression", width))
                    .unwrap()
            })
            .collect();
        vec![compression; width]
    };
    let mut prover = Transcript::new_direct();
    let queries = prefix(&mut prover);
    let cvalues: Vec<_> = queries
        .iter()
        .map(|q| co.table().evaluate(q).unwrap())
        .collect();
    let evalues: Vec<_> = queries
        .iter()
        .map(|q| ev.table().evaluate(q).unwrap())
        .collect();
    let coefficient_opening =
        CanonicalPcs::<F, Sha256>::open_many(&pp, &mut prover, &cr, &cs, &queries, &cvalues)
            .unwrap();
    let evaluation_opening =
        CanonicalPcs::<F, Sha256>::open_many(&pp, &mut prover, &er, &es, &queries, &evalues)
            .unwrap();
    let mut reference = Transcript::new_direct();
    let queries = prefix(&mut reference);
    CanonicalPcs::<F, Sha256>::verify_many(
        &pp,
        &mut reference,
        &cr,
        &queries,
        &cvalues,
        &coefficient_opening,
    )
    .unwrap();
    CanonicalPcs::<F, Sha256>::verify_many(
        &pp,
        &mut reference,
        &er,
        &queries,
        &evalues,
        &evaluation_opening,
    )
    .unwrap();
    assert_eq!(
        prover.get_challenge(b"false NTT after"),
        reference.get_challenge(b"false NTT after")
    );
    let proof = CanonicalProof {
        coefficients,
        evaluations,
        coefficient_opening,
        evaluation_opening,
    };
    let error = packed_ntt::verify_canonical::<F, Sha256, _>(
        &mut Transcript::new_direct(),
        &shape,
        &co.verifier(),
        &ev.verifier(),
        &proof,
    )
    .unwrap_err();
    assert!(error.0.contains("folded NTT identity failed"));
    println!(
        r#"HB_MASKED_NTT_FORGERY {{"prime":{},"extension_degree":{},"genuine_source_openings":4,"actual_roots_verified":true,"production_accepted":false}}"#,
        F::MODULUS_VALUE,
        EF::D
    );
}
#[test]
fn babybear_sextic_ntt() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks_cubic_ntt() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}
#[test]
fn babybear_fresh_false_ntt() {
    fresh_false::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks_fresh_false_ntt() {
    fresh_false::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}

#[test]
fn masked_ntt_rejects_equal_value_noncanonical_fold_encodings() {
    use algebra::{Field, Goldilocks as F, GoldilocksExtension3 as E};
    let pp = Parameters::<F, E>::new(4, 2, 10, 2, 1, 2).unwrap();
    let shape = Shape::new_canonical::<F, Sha256, _>(&pp, 32).unwrap();
    let table = PackedTable::new(4, 2, vec![F::new(0); 32]).unwrap();
    let (cr, cs) =
        CanonicalPcs::<F, Sha256>::commit(&pp, &table, &mut StdRng::seed_from_u64(591)).unwrap();
    let (er, es) =
        CanonicalPcs::<F, Sha256>::commit(&pp, &table, &mut StdRng::seed_from_u64(592)).unwrap();
    let co = CanonicalProverOracle::<F, Sha256, _> {
        parameters: &pp,
        commitment: &cr,
        state: &cs,
    };
    let ev = CanonicalProverOracle::<F, Sha256, _> {
        parameters: &pp,
        commitment: &er,
        state: &es,
    };
    let proof = packed_ntt::prove_canonical::<F, Sha256, _>(
        &mut Transcript::new_direct(),
        &shape,
        &co,
        &ev,
    )
    .unwrap();
    for coefficients in [true, false] {
        let mut changed = proof.clone();
        if coefficients {
            changed.coefficients[0][0] = F::new(F::MODULUS_VALUE);
        } else {
            changed.evaluations[0][0] = F::new(F::MODULUS_VALUE);
        }
        let error = packed_ntt::verify_canonical::<F, Sha256, _>(
            &mut Transcript::new_direct(),
            &shape,
            &co.verifier(),
            &ev.verifier(),
            &changed,
        )
        .unwrap_err();
        assert!(error.0.contains("noncanonical public packed response"));
    }
}
