use algebra::{
    AbstractExtensionField, BabyBear, Goldilocks, NTTField, PrimeField,
    matrix_weighted::PackedTable,
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_decomposition::{Config, deferred as decomposition},
    packed_oracle::ProverOracle,
};

fn roundtrip<F, EF>(k: usize)
where
    F: PrimeField + NTTField + Serialize + DeserializeOwned + From<usize>,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    // Exercise every limb, both endpoints of the integer range and padding.
    let values = [0, 1, p - 1, p - 2, 12345, 256, 65536];
    for logical_len in [7, 2 * k] {
        let config = Config::new::<F>(8, logical_len, 1).unwrap();
        let d = config.num_digits::<F>().unwrap();
        let base: Vec<_> = values.into_iter().chain([0]).collect();
        let mut columns = vec![
            base.iter()
                .map(|v| F::from(*v as usize))
                .collect::<Vec<_>>(),
        ];
        columns.extend((0..d).map(|i| {
            base.iter()
                .map(|v| F::from(((v >> (8 * i)) & 255) as usize))
                .collect()
        }));
        let tables: Vec<_> = columns
            .into_iter()
            .map(|v| {
                PackedTable::new(
                    1,
                    k,
                    v.into_iter()
                        .chain(std::iter::repeat_n(F::from(0), 2 * k - 8))
                        .collect(),
                )
                .unwrap()
            })
            .collect();
        let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(1, k, 32, 2).unwrap();
        let helper = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(
            1 + k.ilog2() as usize,
            k,
            32,
            2,
        )
        .unwrap();
        let (roots, states): (Vec<_>, Vec<_>) = tables
            .iter()
            .map(|t| pp.commit::<F, Sha256>(t).unwrap())
            .unzip();
        let oracles: Vec<_> = tables
            .iter()
            .zip(&roots)
            .zip(&states)
            .map(|((table, commitment), state)| ProverOracle {
                parameters: &pp,
                table,
                commitment,
                state,
            })
            .collect();
        let digits: Vec<_> = oracles[1..].iter().collect();
        let public: Vec<_> = digits.iter().map(|o| o.verifier()).collect();
        let mut prover = Transcript::new_direct();
        let proof = decomposition::prove::<F, EF, Sha256, _>(
            &mut prover,
            &config,
            &oracles[0],
            &helper,
            &digits,
        )
        .unwrap();
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (decomposition::Proof<F, EF, [u8; 32]>, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(proof.comparisons.len(), 1);
        assert_eq!(proof.comparisons[0].lookups.len(), d);
        assert!(
            proof.comparisons[0]
                .lookups
                .iter()
                .all(|p| p.source_openings.is_empty())
        );
        assert!(proof.comparisons[0].source_authentication.openings.len() <= 2 * d + 1);
        let verify = |t: &mut Transcript<F>,
                      config: &Config,
                      proof: &decomposition::Proof<F, EF, [u8; 32]>| {
            decomposition::verify::<F, EF, Sha256, _>(
                t,
                config,
                &oracles[0].verifier(),
                &helper,
                &public,
                proof,
            )
        };
        let mut verifier = Transcript::new_direct();
        verify(&mut verifier, &config, &proof).unwrap();
        assert_eq!(
            prover.get_challenge(b"after"),
            verifier.get_challenge(b"after")
        );
        let reject = |p: &decomposition::Proof<F, EF, [u8; 32]>| {
            assert!(verify(&mut Transcript::new_direct(), &config, p).is_err())
        };
        let mut bad = proof.clone();
        bad.borrow_commitments[d].root[0] ^= 1;
        reject(&bad);
        let mut bad = proof.clone();
        bad.comparisons[0].lookups.swap(0, 1);
        reject(&bad);
        let mut bad = proof.clone();
        bad.comparisons[0].lookups[0].groups[0].source_values[0][0] += F::from(1);
        reject(&bad);
        let mut bad = proof.clone();
        bad.comparisons[0].source_authentication.openings.pop();
        reject(&bad);
        let mut bad = proof.clone();
        bad.comparisons[0].lookups.pop();
        reject(&bad);
        let mut bad = proof.clone();
        bad.comparisons.clear();
        reject(&bad);
        let mut bad = proof.clone();
        bad.comparisons.push(proof.comparisons[0].clone());
        reject(&bad);
        let mut swapped: Vec<_> = digits.iter().map(|o| o.verifier()).collect();
        swapped.swap(0, 1);
        assert!(
            decomposition::verify::<F, EF, Sha256, _>(
                &mut Transcript::new_direct(),
                &config,
                &oracles[0].verifier(),
                &helper,
                &swapped,
                &proof
            )
            .is_err()
        );
        let changed = Config::new::<F>(8, logical_len, 2).unwrap();
        assert!(verify(&mut Transcript::new_direct(), &changed, &proof).is_err());
    }
}
#[test]
fn babybear_deferred_decomposition() {
    roundtrip::<BabyBear, algebra::BabyBearExtension6>(8);
}
#[test]
fn goldilocks_deferred_decomposition() {
    roundtrip::<Goldilocks, algebra::GoldilocksExtension3>(4);
}
