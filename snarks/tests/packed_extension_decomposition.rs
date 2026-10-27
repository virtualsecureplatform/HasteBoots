use algebra::{
    AbstractExtensionField, BabyBear, BabyBearExtension5, Goldilocks, GoldilocksExtension5,
    NTTField, PrimeField, matrix_weighted::PackedTable,
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_decomposition::{self as decomposition, Config, ExtensionProof},
    packed_oracle::ProverOracle,
};

fn roundtrip<F, EF>()
where
    F: PrimeField + NTTField + Serialize + DeserializeOwned + From<usize>,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    // Exercise every limb, both endpoints of the integer range and padding.
    let values = [0, 1, p - 1, p - 2, 12345, 256, 65536];
    for logical_len in [7, 16] {
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
                    8,
                    v.into_iter()
                        .chain(std::iter::repeat_n(F::from(0), 8))
                        .collect(),
                )
                .unwrap()
            })
            .collect();
        let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(1, 8, 32, 2).unwrap();
        let helper = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(4, 8, 32, 2).unwrap();
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
        let proof = decomposition::prove_extension::<F, EF, Sha256, _>(
            &mut prover,
            &config,
            &oracles[0],
            &helper,
            &digits,
        )
        .unwrap();
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (ExtensionProof<F, EF, [u8; 32]>, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        assert!(proof.comparisons.iter().all(|p| p.groups.len() == 1));
        let verify =
            |t: &mut Transcript<F>, config: &Config, proof: &ExtensionProof<F, EF, [u8; 32]>| {
                decomposition::verify_extension::<F, EF, Sha256, _>(
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
        let reject = |p: &ExtensionProof<F, EF, [u8; 32]>| {
            assert!(verify(&mut Transcript::new_direct(), &config, p).is_err())
        };
        let mut bad = proof.clone();
        bad.borrow_commitments[d].root[0] ^= 1;
        reject(&bad);
        let mut bad = proof.clone();
        bad.comparisons.swap(0, 1);
        reject(&bad);
        let mut bad = proof.clone();
        bad.comparisons[0].groups[0].source_values[0][0] += F::from(1);
        reject(&bad);
        let changed = Config::new::<F>(8, logical_len, 2).unwrap();
        assert!(verify(&mut Transcript::new_direct(), &changed, &proof).is_err());
    }
}
#[test]
fn babybear_extension_decomposition() {
    roundtrip::<BabyBear, BabyBearExtension5>();
}
#[test]
fn goldilocks_extension_decomposition() {
    roundtrip::<Goldilocks, GoldilocksExtension5>();
}

#[test]
fn babybear_degree6_decomposition() {
    roundtrip::<BabyBear, algebra::BabyBearExtension6>();
}

#[test]
fn babybear_degree8_decomposition() {
    roundtrip::<BabyBear, algebra::BabyBearExtension8>();
}
