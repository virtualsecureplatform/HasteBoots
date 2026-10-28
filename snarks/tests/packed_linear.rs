#[allow(dead_code)]
#[path = "support/legacy_packed_linear_v1.rs"]
mod legacy;
use algebra::{BabyBear as F, matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use sha2::Sha256;
use snarks::{
    packed_linear::{self, Relation},
    packed_oracle::ProverOracle,
};
#[test]
fn linear_relations_authenticate_every_source_and_trusted_coefficient() {
    for (n, width) in [(0, 1), (3, 3), (6, 8)] {
        let a: Vec<_> = (0..(1 << n) * width).map(|i| F::from(i + 1)).collect();
        let b: Vec<_> = a.iter().map(|a| *a * F::from(7usize)).collect();
        let c: Vec<_> = a.iter().zip(&b).map(|(a, b)| *a + *b).collect();
        let tables: Vec<_> = [a, b, c]
            .into_iter()
            .map(|v| PackedTable::new(n, width, v).unwrap())
            .collect();
        let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(n, width, 32, 2).unwrap();
        let (commitments, states): (Vec<_>, Vec<_>) = tables
            .iter()
            .map(|t| pp.commit::<F, Sha256>(t).unwrap())
            .unzip();
        let oracles: Vec<_> = tables
            .iter()
            .zip(&commitments)
            .zip(&states)
            .map(|((table, commitment), state)| ProverOracle {
                parameters: &pp,
                table,
                commitment,
                state,
            })
            .collect();
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
        let mut prover = Transcript::new();
        let proof = packed_linear::prove::<F, Sha256, _>(
            &mut prover,
            &oracles.iter().collect::<Vec<_>>(),
            &relations,
        )
        .unwrap();
        let public: Vec<_> = oracles.iter().map(|s| s.verifier()).collect();
        let mut verifier = Transcript::new();
        packed_linear::verify::<F, Sha256, _>(&mut verifier, &public, &relations, &proof).unwrap();
        assert_eq!(
            prover.get_challenge(b"after"),
            verifier.get_challenge(b"after")
        );
        for i in 0..3 {
            let mut bad = proof.clone();
            bad.values[i][0] += F::from(1usize);
            assert!(
                packed_linear::verify::<F, Sha256, _>(
                    &mut Transcript::new(),
                    &public,
                    &relations,
                    &bad
                )
                .is_err()
            );
            let mut bad = proof.clone();
            bad.openings[i].columns.clear();
            assert!(
                packed_linear::verify::<F, Sha256, _>(
                    &mut Transcript::new(),
                    &public,
                    &relations,
                    &bad
                )
                .is_err()
            );
        }
        let mut changed = relations.clone();
        changed[0].terms[0].0 += F::from(1usize);
        assert!(
            packed_linear::verify::<F, Sha256, _>(
                &mut Transcript::new(),
                &public,
                &changed,
                &proof
            )
            .is_err()
        );
        for invalid in [
            vec![],
            vec![Relation { terms: vec![] }],
            vec![Relation {
                terms: vec![(F::from(1usize), 3)],
            }],
        ] {
            assert!(
                packed_linear::verify::<F, Sha256, _>(
                    &mut Transcript::new(),
                    &public,
                    &invalid,
                    &proof
                )
                .is_err()
            );
        }
        let mut bad = proof.clone();
        bad.values.pop();
        assert!(
            packed_linear::verify::<F, Sha256, _>(
                &mut Transcript::new(),
                &public,
                &relations,
                &bad
            )
            .is_err()
        );
    }
}

fn compare_legacy<F: algebra::NTTField + serde::Serialize>(width: usize) {
    let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(4, width, 32, 2).unwrap();
    let a: Vec<_> = (0..16 * width).map(|i| F::from(i * i + 3)).collect();
    let b: Vec<_> = a.iter().map(|&v| v * F::from(7usize)).collect();
    let c: Vec<_> = a.iter().zip(&b).map(|(&a, &b)| a + b).collect();
    let tables: Vec<_> = [a, b, c]
        .into_iter()
        .map(|v| PackedTable::new(4, width, v).unwrap())
        .collect();
    let (roots, states): (Vec<_>, Vec<_>) = tables
        .iter()
        .map(|t| pp.commit::<F, Sha256>(t).unwrap())
        .unzip();
    let sources: Vec<_> = tables
        .iter()
        .zip(&roots)
        .zip(&states)
        .map(|((table, commitment), state)| ProverOracle {
            parameters: &pp,
            commitment,
            state,
            table,
        })
        .collect();
    let refs: Vec<_> = sources.iter().collect();
    let relations = vec![Relation {
        terms: vec![
            (F::from(1usize), 0),
            (F::from(1usize), 1),
            (-F::from(1usize), 2),
        ],
    }];
    let old_relations = vec![legacy::Relation {
        terms: relations[0].terms.clone(),
    }];
    let mut current = Transcript::new_direct();
    let mut reference = Transcript::new_direct();
    let proof = packed_linear::prove::<F, Sha256, _>(&mut current, &refs, &relations).unwrap();
    let old = legacy::prove::<F, Sha256, _>(&mut reference, &refs, &old_relations).unwrap();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    assert_eq!(
        bytes,
        bincode::serde::encode_to_vec(&old, bincode::config::standard()).unwrap()
    );
    let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    let mut verifier = Transcript::new_direct();
    let mut old_verifier = Transcript::new_direct();
    packed_linear::verify::<F, Sha256, _>(&mut verifier, &public, &relations, &proof).unwrap();
    legacy::verify::<F, Sha256, _>(&mut old_verifier, &public, &old_relations, &old).unwrap();
    let after = current.get_challenge(b"linear legacy after");
    assert_eq!(after, reference.get_challenge(b"linear legacy after"));
    assert_eq!(after, verifier.get_challenge(b"linear legacy after"));
    assert_eq!(after, old_verifier.get_challenge(b"linear legacy after"));
    println!(
        r#"HB_LINEAR_LEGACY_WIRE {{"prime":{},"width":{},"proof_bytes":{},"exact_bytes":true,"exact_transcript":true}}"#,
        F::MODULUS_VALUE,
        width,
        bytes.len()
    );
}
#[test]
fn babybear_linear_legacy_wire() {
    compare_legacy::<algebra::BabyBear>(8);
}
#[test]
fn goldilocks_linear_legacy_wire() {
    compare_legacy::<algebra::Goldilocks>(4);
}
