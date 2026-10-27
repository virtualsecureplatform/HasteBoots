use algebra::{BabyBear as F, Field};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted::Parameters,
    utils::code::{BlockReedSolomonCode, ReedSolomonCode},
};
use sha2::Sha256;
use snarks::packed_relation::{self, RelationProof};
use sumcheck::packed::PackedShape;

#[test]
fn authenticated_block_relation_and_instrumentation_roundtrip() {
    for length in [7, 728, 728 * 16] {
        let a: Vec<_> = (0..length).map(|i| F::new(i as u32 + 1)).collect();
        let b: Vec<_> = (0..length).map(|i| F::new(i as u32 * 11 + 5)).collect();
        let c: Vec<_> = a.iter().zip(&b).map(|(&a, &b)| a * b).collect();
        let factors = packed_relation::pack_rows(8, &[&a, &b, &c]).unwrap();
        let n = factors[0].num_vars();
        let params = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(n, 8, 64, 2).unwrap();
        let (commitments, states): (Vec<_>, Vec<_>) = factors
            .iter()
            .map(|table| params.commit::<F, Sha256>(table).unwrap())
            .unzip();
        let shape = PackedShape {
            num_vars: n,
            width: 8,
            num_factors: 3,
            terms: vec![(F::new(1), vec![0, 1]), (-F::new(1), vec![2])],
        };
        let mut first = Transcript::new();
        let proof = packed_relation::prove::<F, Sha256, _>(
            &mut first,
            &shape,
            &params,
            &factors,
            &commitments,
            &states,
        )
        .unwrap();
        let mut second = Transcript::new();
        let measured = packed_relation::prove_with_statistics::<F, Sha256, _>(
            &mut second,
            &shape,
            &params,
            &factors,
            &commitments,
            &states,
            &mut packed_relation::ProverStatistics::default(),
        )
        .unwrap();
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        assert_eq!(
            bytes,
            bincode::serde::encode_to_vec(&measured, bincode::config::standard()).unwrap()
        );
        assert_eq!(
            first.get_challenge(b"after"),
            second.get_challenge(b"after")
        );
        let (proof, used): (RelationProof<F, [u8; 32]>, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        packed_relation::verify::<F, Sha256, _>(
            &mut Transcript::new(),
            &shape,
            &params,
            &commitments,
            &proof,
        )
        .unwrap();
    }
}

#[test]
fn authenticated_hadamard_handles_partial_lanes_and_padding() {
    for length in [1, 7, 728, 1024, 728 * 4, 728 * 16] {
        let a: Vec<_> = (0..length).map(|i| F::new(i as u32 + 2)).collect();
        let b: Vec<_> = (0..length).map(|i| F::new(i as u32 * 3 + 7)).collect();
        let c: Vec<_> = a.iter().zip(&b).map(|(&a, &b)| a * b).collect();
        let factors = packed_relation::pack_rows(5, &[&a, &b, &c]).unwrap();
        let n = factors[0].num_vars();
        let cols = 1 << (n - n / 2);
        let params =
            Parameters::new::<F>(n, 5, n / 2, 20, ReedSolomonCode::new(cols, cols * 2)).unwrap();
        let (commitments, states): (Vec<_>, Vec<_>) = factors
            .iter()
            .map(|t| params.commit::<F, Sha256>(t).unwrap())
            .unzip();
        let shape = PackedShape {
            num_vars: n,
            width: 5,
            num_factors: 3,
            terms: vec![(F::new(1), vec![0, 1]), (-F::new(1), vec![2])],
        };
        let mut prover = Transcript::new();
        let proof = packed_relation::prove::<F, Sha256, _>(
            &mut prover,
            &shape,
            &params,
            &factors,
            &commitments,
            &states,
        )
        .unwrap();
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, _): (RelationProof<F, [u8; 32]>, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        let mut verifier = Transcript::new();
        packed_relation::verify::<F, Sha256, _>(
            &mut verifier,
            &shape,
            &params,
            &commitments,
            &proof,
        )
        .unwrap();
        assert_eq!(
            prover.get_challenge(b"after"),
            verifier.get_challenge(b"after")
        );
        let mut bad = proof.clone();
        bad.values[0][0] += F::new(1);
        assert!(
            packed_relation::verify::<F, Sha256, _>(
                &mut Transcript::new(),
                &shape,
                &params,
                &commitments,
                &bad
            )
            .is_err()
        );
        let mut bad = proof.clone();
        bad.openings.pop();
        assert!(
            packed_relation::verify::<F, Sha256, _>(
                &mut Transcript::new(),
                &shape,
                &params,
                &commitments,
                &bad
            )
            .is_err()
        );
        let mut wrong_roots = commitments.clone();
        wrong_roots[0].root[0] ^= 1;
        assert!(
            packed_relation::verify::<F, Sha256, _>(
                &mut Transcript::new(),
                &shape,
                &params,
                &wrong_roots,
                &proof
            )
            .is_err()
        );
        let changed_code =
            Parameters::new::<F>(n, 5, n / 2, 20, ReedSolomonCode::new(cols, cols * 2 + 1))
                .unwrap();
        assert!(
            packed_relation::verify::<F, Sha256, _>(
                &mut Transcript::new(),
                &shape,
                &changed_code,
                &commitments,
                &proof
            )
            .is_err()
        );
    }
}
