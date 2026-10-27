use algebra::{BabyBear, Goldilocks, NTTField, PrimeField, matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_accumulator::{self, Proof, Shape},
    packed_oracle::ProverOracle,
};
fn fixture<F: PrimeField + From<usize>>(
    n: usize,
    k: usize,
    rounds: usize,
) -> (Shape, Vec<F>, Vec<F>, Vec<PackedTable<F>>) {
    let shape = Shape::new(n, rounds).unwrap();
    let rows = shape.padded_rounds();
    let size = 2 * rows * n;
    let mut input = vec![F::from(0); size];
    let mut output = input.clone();
    let mut sum = input.clone();
    let mut ext = input.clone();
    let initial: Vec<_> = (0..2 * n).map(|i| F::from(i + 3)).collect();
    let mut final_acc = vec![F::from(0); 2 * n];
    for half in 0..2 {
        for j in 0..n {
            let mut acc = initial[half * n + j];
            for row in 0..rounds {
                let at = (half * rows + row) * n + j;
                input[at] = acc;
                sum[at] = F::from(row * 3 + j + 1);
                acc += sum[at];
                output[at] = acc;
                ext[at] = F::from(row * 7 + j + 2);
            }
            final_acc[half * n + j] = acc;
        }
    }
    let monomial: Vec<_> = input.iter().zip(&ext).map(|(&a, &b)| a + b).collect();
    let a = ext[..rows * n]
        .iter()
        .chain(&ext[..rows * n])
        .copied()
        .collect();
    let b = ext[rows * n..]
        .iter()
        .chain(&ext[rows * n..])
        .copied()
        .collect();
    let vars = (size / k).ilog2() as usize;
    (
        shape,
        initial,
        final_acc,
        [input, monomial, ext, output, sum, a, b]
            .into_iter()
            .map(|v| PackedTable::new(vars, k, v).unwrap())
            .collect(),
    )
}
fn roundtrip<F: PrimeField + NTTField + Serialize + DeserializeOwned + From<usize>>() {
    for (n, k, rounds) in [(1, 1, 1), (32, 4, 3), (32, 8, 4), (32, 8, 5)] {
        let (shape, initial, final_acc, tables) = fixture::<F>(n, k, rounds);
        let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(
            tables[0].num_vars(),
            k,
            32,
            2,
        )
        .unwrap();
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
        let refs: Vec<_> = oracles.iter().collect();
        let public: Vec<_> = oracles.iter().map(|s| s.verifier()).collect();
        let mut prover = Transcript::new();
        let proof = packed_accumulator::prove::<F, Sha256, _>(
            &mut prover,
            &shape,
            &initial,
            &final_acc,
            &refs,
        )
        .unwrap();
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (Proof<F, [u8; 32]>, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let mut verifier = Transcript::new();
        packed_accumulator::verify::<F, Sha256, _>(
            &mut verifier,
            &shape,
            &initial,
            &final_acc,
            &public,
            &proof,
        )
        .unwrap();
        assert_eq!(
            prover.get_challenge(b"after"),
            verifier.get_challenge(b"after")
        );
        let reject = |p: &Proof<F, [u8; 32]>| {
            packed_accumulator::verify::<F, Sha256, _>(
                &mut Transcript::new(),
                &shape,
                &initial,
                &final_acc,
                &public,
                p,
            )
            .is_err()
        };
        for source in 0..7 {
            for point in 0..proof.values[source].len() {
                let mut bad = proof.clone();
                bad.values[source][point][0] += F::from(1);
                assert!(reject(&bad));
            }
            let mut bad = proof.clone();
            bad.openings[source].columns.clear();
            assert!(reject(&bad));
        }
        let mut bad = proof.clone();
        bad.values[0].pop();
        assert!(reject(&bad));
        if rounds < shape.padded_rounds() {
            let changed = Shape::new(n, shape.padded_rounds()).unwrap();
            assert!(
                packed_accumulator::prove::<F, Sha256, _>(
                    &mut Transcript::new(),
                    &changed,
                    &initial,
                    &final_acc,
                    &refs
                )
                .is_err()
            );
        }
        let mut changed = initial.clone();
        changed[0] += F::from(1);
        assert!(
            packed_accumulator::verify::<F, Sha256, _>(
                &mut Transcript::new(),
                &shape,
                &changed,
                &final_acc,
                &public,
                &proof
            )
            .is_err()
        );
        let mut changed = final_acc.clone();
        changed[n] += F::from(1);
        assert!(
            packed_accumulator::verify::<F, Sha256, _>(
                &mut Transcript::new(),
                &shape,
                &initial,
                &changed,
                &public,
                &proof
            )
            .is_err()
        );
    }
}
#[test]
fn accumulator_links_roundtrip_babybear_and_goldilocks() {
    roundtrip::<BabyBear>();
    roundtrip::<Goldilocks>();
}
#[test]
fn false_internal_round_and_decomposition_links_are_rejected() {
    type F = BabyBear;
    let (shape, initial, final_acc, original) = fixture::<F>(32, 8, 3);
    let pp =
        Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(original[0].num_vars(), 8, 32, 2)
            .unwrap();
    for source in [0, 1, 2, 3, 4, 5, 6] {
        let mut tables = original.clone();
        let mut values = tables[source].values().to_vec();
        values[32] += F::from(1);
        tables[source] = PackedTable::new(tables[source].num_vars(), 8, values).unwrap();
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
        assert!(
            packed_accumulator::prove::<F, Sha256, _>(
                &mut Transcript::new(),
                &shape,
                &initial,
                &final_acc,
                &oracles.iter().collect::<Vec<_>>()
            )
            .is_err()
        );
    }
    assert!(Shape::new(3, 4).is_err());
    assert!(Shape::new(32, 0).is_err());
}
