#[allow(dead_code)]
#[path = "support/legacy_packed_ntt_v2.rs"]
mod legacy;
use algebra::{
    BabyBear, Field, Goldilocks, NTTField, matrix_weighted::PackedTable,
    transformation::AbstractNTT,
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use serde::Serialize;
use sha2::Sha256;
use snarks::{
    packed_ntt::{self, Proof, Shape},
    packed_oracle::ProverOracle,
    packed_relation,
};

fn check<F: NTTField + Serialize>() {
    for (n, count, width) in [(32, 1, 8), (32, 4, 4), (64, 16, 8), (32, 1, 32)] {
        let coefficients: Vec<F> = (0..n * count).map(|i| F::from(i * 17 + 9)).collect();
        let mut evaluations = coefficients.clone();
        F::init_ntt_table(n.ilog2()).unwrap();
        let table = F::get_ntt_table(n.ilog2()).unwrap();
        for row in evaluations.chunks_exact_mut(n) {
            table.transform_slice(row);
        }
        let packed = if count == 1 && width == n {
            vec![
                PackedTable::new(0, width, coefficients.clone()).unwrap(),
                PackedTable::new(0, width, evaluations.clone()).unwrap(),
            ]
        } else {
            packed_relation::pack_rows(width, &[&coefficients, &evaluations]).unwrap()
        };
        let params = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(
            packed[0].num_vars(),
            width,
            if width == n { 8 } else { 64 },
            2,
        )
        .unwrap();
        let shape = Shape::new::<F, _>(&params, n).unwrap();
        assert_eq!(shape.num_polynomials(), count);
        let (coefficient_commitment, coefficient_state) =
            params.commit::<F, Sha256>(&packed[0]).unwrap();
        let (evaluation_commitment, evaluation_state) =
            params.commit::<F, Sha256>(&packed[1]).unwrap();
        let coefficients = ProverOracle {
            parameters: &params,
            commitment: &coefficient_commitment,
            state: &coefficient_state,
            table: &packed[0],
        };
        let evaluations = ProverOracle {
            parameters: &params,
            commitment: &evaluation_commitment,
            state: &evaluation_state,
            table: &packed[1],
        };
        let mut prover = Transcript::new();
        let proof =
            packed_ntt::prove::<F, Sha256, _>(&mut prover, &shape, &coefficients, &evaluations)
                .unwrap();
        let mut verifier = Transcript::new();
        packed_ntt::verify::<F, Sha256, _>(
            &mut verifier,
            &shape,
            &coefficients.verifier(),
            &evaluations.verifier(),
            &proof,
        )
        .unwrap();
        let after = prover.get_challenge(b"after");
        assert_eq!(after, verifier.get_challenge(b"after"));
        let old_shape = legacy::Shape::new::<F, _>(&params, n).unwrap();
        let mut reference = Transcript::new();
        let previous =
            legacy::prove::<F, Sha256, _>(&mut reference, &old_shape, &coefficients, &evaluations)
                .unwrap();
        assert_eq!(
            bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap(),
            bincode::serde::encode_to_vec(&previous, bincode::config::standard()).unwrap()
        );
        let mut old_verifier = Transcript::new();
        legacy::verify::<F, Sha256, _>(
            &mut old_verifier,
            &old_shape,
            &coefficients.verifier(),
            &evaluations.verifier(),
            &previous,
        )
        .unwrap();
        assert_eq!(after, reference.get_challenge(b"after"));
        assert_eq!(after, old_verifier.get_challenge(b"after"));
        println!(
            r#"HB_NTT_LEGACY_WIRE {{"prime":{},"polynomial_size":{},"polynomials":{},"width":{},"exact_bytes":true,"exact_transcript":true}}"#,
            F::MODULUS_VALUE,
            n,
            count,
            width
        );

        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        // Generic F only needs Serialize for the protocol; the concrete test
        // below also checks deserialization and malformed/tampered wire values.
        assert!(!bytes.is_empty());
    }
}

#[test]
fn tensor_ntt_roundtrip_babybear_and_goldilocks() {
    check::<BabyBear>();
    check::<Goldilocks>();
}

#[test]
fn tensor_ntt_rejects_consistent_forged_folds_and_wrong_canonical_data() {
    type F = BabyBear;
    let n = 32;
    let coefficients: Vec<F> = (0..n * 4).map(|i| F::new(i as u32 + 1)).collect();
    let table = F::get_ntt_table(5).unwrap();
    let mut evaluations = coefficients.clone();
    for row in evaluations.chunks_exact_mut(n) {
        table.transform_slice(row);
    }
    let packed = packed_relation::pack_rows(8, &[&coefficients, &evaluations]).unwrap();
    let params =
        Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(packed[0].num_vars(), 8, 64, 2)
            .unwrap();
    let shape = Shape::new::<F, _>(&params, n).unwrap();
    let (c, cs) = params.commit::<F, Sha256>(&packed[0]).unwrap();
    let (e, es) = params.commit::<F, Sha256>(&packed[1]).unwrap();
    let coeff = ProverOracle {
        parameters: &params,
        commitment: &c,
        state: &cs,
        table: &packed[0],
    };
    let eval = ProverOracle {
        parameters: &params,
        commitment: &e,
        state: &es,
        table: &packed[1],
    };
    let proof =
        packed_ntt::prove::<F, Sha256, _>(&mut Transcript::new(), &shape, &coeff, &eval).unwrap();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (Proof<F, [u8; 32]>, _) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let reject = |proof: &Proof<F, [u8; 32]>| {
        packed_ntt::verify::<F, Sha256, _>(
            &mut Transcript::new(),
            &shape,
            &coeff.verifier(),
            &eval.verifier(),
            proof,
        )
        .is_err()
    };
    let mut bad = proof.clone();
    bad.coefficients[0][0] += F::new(1);
    assert!(reject(&bad));
    let mut bad = proof.clone();
    bad.coefficients[0][0] += F::new(1);
    bad.evaluations[0] = bad.coefficients[0].clone();
    table.transform_slice(&mut bad.evaluations[0]);
    assert!(
        reject(&bad),
        "locally valid folded NTTs must still bind to the canonical sources"
    );
    let mut bad = proof.clone();
    bad.coefficient_opening.evaluations.pop();
    assert!(reject(&bad));
    let mut bad = proof.clone();
    bad.evaluations[0].pop();
    assert!(reject(&bad));
    let mut bad = proof.clone();
    bad.evaluation_opening.columns[0].values[0] += F::new(1);
    assert!(reject(&bad));

    let mut wrong_coefficients = coefficients.clone();
    wrong_coefficients[0] += F::new(1);
    let mut wrong_evaluations = wrong_coefficients.clone();
    for row in wrong_evaluations.chunks_exact_mut(n) {
        table.transform_slice(row);
    }
    let wrong = packed_relation::pack_rows(8, &[&wrong_coefficients, &wrong_evaluations]).unwrap();
    let (wc, wcs) = params.commit::<F, Sha256>(&wrong[0]).unwrap();
    let (we, wes) = params.commit::<F, Sha256>(&wrong[1]).unwrap();
    let wrong_coeff = ProverOracle {
        parameters: &params,
        commitment: &wc,
        state: &wcs,
        table: &wrong[0],
    };
    let wrong_eval = ProverOracle {
        parameters: &params,
        commitment: &we,
        state: &wes,
        table: &wrong[1],
    };
    // The malicious prover can generate a genuinely valid proof for different
    // data, even with the same enclosing public-statement prefix.
    let mut malicious = Transcript::new();
    malicious.append_message(b"public statement", &123u64);
    let wrong_proof =
        packed_ntt::prove::<F, Sha256, _>(&mut malicious, &shape, &wrong_coeff, &wrong_eval)
            .unwrap();
    let mut verifier = Transcript::new();
    verifier.append_message(b"public statement", &123u64);
    assert!(
        packed_ntt::verify::<F, Sha256, _>(
            &mut verifier,
            &shape,
            &coeff.verifier(),
            &eval.verifier(),
            &wrong_proof
        )
        .is_err()
    );
    // A matching table shape does not allow swapping the private source data
    // while retaining a different canonical commitment/state.
    let unrelated_coeff = ProverOracle {
        parameters: &params,
        commitment: &c,
        state: &cs,
        table: &wrong[0],
    };
    let unrelated_eval = ProverOracle {
        parameters: &params,
        commitment: &e,
        state: &es,
        table: &wrong[1],
    };
    assert!(
        packed_ntt::prove::<F, Sha256, _>(
            &mut Transcript::new(),
            &shape,
            &unrelated_coeff,
            &unrelated_eval
        )
        .is_err()
    );
    let invalid = ProverOracle {
        parameters: &params,
        commitment: &we,
        state: &wes,
        table: &packed[1],
    };
    assert!(
        packed_ntt::prove::<F, Sha256, _>(&mut Transcript::new(), &shape, &wrong_coeff, &invalid)
            .is_err()
    );

    assert!(Shape::new::<F, _>(&params, 0).is_err());
    assert!(Shape::new::<F, _>(&params, 31).is_err());
    assert!(Shape::new::<F, _>(&params, 256).is_err());
    let nonbinary = PackedTable::new(4, 5, vec![F::new(0); 80]).unwrap();
    let nonbinary_params =
        Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(nonbinary.num_vars(), 5, 64, 2)
            .unwrap();
    assert!(Shape::new::<F, _>(&nonbinary_params, 32).is_err());
}
