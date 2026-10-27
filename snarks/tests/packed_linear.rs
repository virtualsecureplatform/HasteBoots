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
