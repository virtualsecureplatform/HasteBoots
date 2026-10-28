use algebra::{AbstractExtensionField, NTTField, matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_decomposition::{Config, batch},
    packed_oracle::{ProverOracle, VerifierOracle},
};
fn exercise<F, EF>(k: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let mu = k.ilog2() as usize + 1;
    let size = (1 << mu) * k;
    let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(mu, k, 32, 2).unwrap();
    let helper =
        Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(mu + k.ilog2() as usize, k, 32, 2)
            .unwrap();
    for count in [1, 4, 5, 16] {
        let configs: Vec<_> = (0..count)
            .map(|i| {
                Config::new::<F>(
                    if i % 2 == 0 { 8 } else { 5 },
                    size - if i % 3 == 1 { 3 } else { 0 },
                    1 + usize::from(i % 5 == 0),
                )
                .unwrap()
            })
            .collect();
        let tables: Vec<Vec<_>> = configs
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let bits = if i % 2 == 0 { 8 } else { 5 };
                let values: Vec<_> = (0..size)
                    .map(|row| match row % 8 {
                        0 => 0,
                        1 => 1,
                        2 => p - 1,
                        3 => p - 2,
                        _ => (row * 7919 + i * 12345) as u128 % p,
                    })
                    .collect();
                let mut columns = vec![
                    values
                        .iter()
                        .map(|&x| F::from(x as usize))
                        .collect::<Vec<_>>(),
                ];
                columns.extend((0..c.num_digits::<F>().unwrap()).map(|j| {
                    values
                        .iter()
                        .map(|&x| F::from(((x >> (bits * j)) & ((1 << bits) - 1)) as usize))
                        .collect()
                }));
                columns
                    .into_iter()
                    .map(|v| PackedTable::new(mu, k, v).unwrap())
                    .collect()
            })
            .collect();
        let committed: Vec<Vec<_>> = tables
            .iter()
            .map(|t| {
                t.iter()
                    .map(|t| pp.commit::<F, Sha256>(t).unwrap())
                    .collect()
            })
            .collect();
        let oracles: Vec<Vec<_>> = tables
            .iter()
            .zip(&committed)
            .map(|(tables, c)| {
                tables
                    .iter()
                    .zip(c)
                    .map(|(table, (commitment, state))| ProverOracle {
                        parameters: &pp,
                        commitment,
                        state,
                        table,
                    })
                    .collect()
            })
            .collect();
        let sources: Vec<_> = oracles.iter().map(|o| &o[0]).collect();
        let digits: Vec<Vec<_>> = oracles.iter().map(|o| o[1..].iter().collect()).collect();
        let public: Vec<_> = sources.iter().map(|o| o.verifier()).collect();
        let pd: Vec<Vec<_>> = digits
            .iter()
            .map(|d| d.iter().map(|o| o.verifier()).collect())
            .collect();
        let mut prover = Transcript::new_direct();
        let proof =
            batch::prove::<F, EF, Sha256, _>(&mut prover, &configs, &helper, &sources, &digits)
                .unwrap();
        assert_eq!(proof.members.len(), count);
        assert_eq!(proof.comparisons.len(), count.div_ceil(batch::MAX_GROUP));
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (batch::Proof<F, EF, [u8; 32]>, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let mut verifier = Transcript::new_direct();
        batch::verify::<F, EF, Sha256, _>(&mut verifier, &configs, &helper, &public, &pd, &proof)
            .unwrap();
        assert_eq!(
            prover.get_challenge(b"after decomp batch"),
            verifier.get_challenge(b"after decomp batch")
        );
        let reject = |configs: &[_], proof: &_| {
            assert!(
                batch::verify::<F, EF, Sha256, _>(
                    &mut Transcript::new_direct(),
                    configs,
                    &helper,
                    &public,
                    &pd,
                    proof
                )
                .is_err()
            )
        };
        let mut bad = proof.clone();
        bad.members.pop();
        reject(&configs, &bad);
        let mut bad = proof.clone();
        bad.comparisons.pop();
        reject(&configs, &bad);
        let mut bad = proof.clone();
        bad.members[0].comparisons.clear();
        reject(&configs, &bad);
        let mut bad = proof.clone();
        bad.members[0].borrow_commitments[0].root[0] ^= 1;
        reject(&configs, &bad);
        let mut bad = proof.clone();
        bad.comparisons[0].helper_values[0] += EF::from_base(F::from(1usize));
        reject(&configs, &bad);
        let mut bad = proof.clone();
        bad.comparisons[0].source_opening.opening.columns.pop();
        reject(&configs, &bad);
        let mut bad = proof.clone();
        bad.comparisons[0].helper_opening.opening.columns.pop();
        reject(&configs, &bad);
        if count > 1 {
            let mut bad = proof.clone();
            bad.members.swap(0, count - 1);
            reject(&configs, &bad);
        }
        if count > batch::MAX_GROUP {
            let mut bad = proof.clone();
            bad.comparisons.swap(0, 1);
            reject(&configs, &bad);
        }
        let mut wrong = configs.clone();
        wrong[0] = Config::new::<F>(7, size, 1).unwrap();
        reject(&wrong, &proof);
        let other = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(mu, k, 16, 2).unwrap();
        let wrong: Vec<_> = sources
            .iter()
            .enumerate()
            .map(|(i, o)| VerifierOracle {
                parameters: if i == 0 { &other } else { &pp },
                commitment: o.commitment,
            })
            .collect();
        assert!(
            batch::verify::<F, EF, Sha256, _>(
                &mut Transcript::new_direct(),
                &configs,
                &helper,
                &wrong,
                &pd,
                &proof
            )
            .is_err()
        );
    }
}
#[test]
fn babybear_bounded_comparison_batches() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
}
#[test]
fn goldilocks_bounded_comparison_batches() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}
