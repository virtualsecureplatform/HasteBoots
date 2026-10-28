use algebra::{AbstractExtensionField, NTTField, matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_extension_lookup::shared::{self as lookup, Proof, Request},
    packed_oracle::ProverOracle,
    packed_tuple_lookup::Config,
};

fn exercise<F, EF>(k: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let mu = k.ilog2() as usize + 1;
    let n = mu + k.ilog2() as usize;
    let size = (1 << mu) * k;
    let source = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(mu, k, 32, 2).unwrap();
    let helper = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(n, k, 32, 2).unwrap();
    let tables: Vec<_> = (0..3)
        .map(|column| {
            PackedTable::new(
                mu,
                k,
                (0..size)
                    .map(|row| {
                        F::from(if column == 2 {
                            2 * (row % 4) + 1
                        } else {
                            row % 4
                        })
                    })
                    .collect(),
            )
            .unwrap()
        })
        .collect();
    let committed: Vec<_> = tables
        .iter()
        .map(|t| source.commit::<F, Sha256>(t).unwrap())
        .collect();
    let oracles: Vec<_> = (0..3)
        .map(|i| ProverOracle {
            parameters: &source,
            commitment: &committed[i].0,
            state: &committed[i].1,
            table: &tables[i],
        })
        .collect();
    let refs: Vec<_> = oracles.iter().collect();
    let expected: Vec<_> = oracles.iter().map(|o| o.verifier()).collect();
    for count in [1, 4, 16] {
        let requests: Vec<_> = (0..count)
            .map(|i| {
                let columns = if i % 2 == 0 { vec![0, 2] } else { vec![1] };
                let table = (0..4)
                    .map(|j| {
                        if columns.len() == 2 {
                            vec![F::from(j), F::from(2 * j + 1)]
                        } else {
                            vec![F::from(j)]
                        }
                    })
                    .collect();
                Request {
                    config: Config::new(
                        size - if i % 3 == 1 { 3 } else { 0 },
                        table,
                        1 + usize::from(i % 3 == 0),
                    )
                    .unwrap(),
                    source_slots: columns,
                }
            })
            .collect();
        let mut prover = Transcript::new_direct();
        let proof =
            lookup::prove::<F, EF, Sha256, _>(&mut prover, &helper, &refs, &requests).unwrap();
        assert_eq!(proof.source_opening.opening.columns.len(), 2);
        assert_eq!(proof.algebra.instances.len(), 2 * proof.helper_roots.len());
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (Proof<F, EF, [u8; 32]>, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let mut verifier = Transcript::new_direct();
        lookup::verify::<F, EF, Sha256, _>(&mut verifier, &helper, &expected, &requests, &proof)
            .unwrap();
        assert_eq!(
            prover.get_challenge(b"after shared lookup"),
            verifier.get_challenge(b"after shared lookup")
        );
        if count == 16 {
            let old = snarks::packed_extension_lookup::deferred::prove::<F, EF, Sha256, _>(
                &mut Transcript::new_direct(),
                &helper,
                &refs,
                &requests,
            )
            .unwrap();
            let old_bytes =
                bincode::serde::encode_to_vec(&old, bincode::config::standard()).unwrap();
            let (old, used): (
                snarks::packed_extension_lookup::deferred::Proof<F, EF, [u8; 32]>,
                _,
            ) = bincode::serde::decode_from_slice(&old_bytes, bincode::config::standard()).unwrap();
            assert_eq!(used, old_bytes.len());
            snarks::packed_extension_lookup::deferred::verify::<F, EF, Sha256, _>(
                &mut Transcript::new_direct(),
                &helper,
                &expected,
                &requests,
                &old,
            )
            .unwrap();
            assert!(bytes.len() < old_bytes.len());
            eprintln!(
                "HB_SHARED_LOOKUP_SIZE {{\"scope\":\"toy-component-decoded-public-verification\",\"prime\":{},\"width\":{k},\"requests\":16,\"scalar_capacity\":{size},\"helper_count\":{},\"shared_bytes\":{},\"deferred_bytes\":{},\"whole_proof_security_certified\":false}}",
                F::MODULUS_VALUE,
                proof.helper_roots.len(),
                bytes.len(),
                old_bytes.len()
            );
        }
        let reject = |requests: &[_], proof: &_| {
            assert!(
                lookup::verify::<F, EF, Sha256, _>(
                    &mut Transcript::new_direct(),
                    &helper,
                    &expected,
                    requests,
                    proof
                )
                .is_err()
            )
        };
        let mut bad = proof.clone();
        bad.multiplicities.pop();
        reject(&requests, &bad);
        let mut bad = proof.clone();
        bad.multiplicities[0][0] += F::one();
        reject(&requests, &bad);
        let mut bad = proof.clone();
        bad.helper_values[0] += EF::one();
        reject(&requests, &bad);
        let mut bad = proof.clone();
        bad.helper_roots[0].root[0] ^= 1;
        reject(&requests, &bad);
        let mut bad = proof.clone();
        bad.helper_opening.opening.columns.pop();
        reject(&requests, &bad);
        let mut bad = proof.clone();
        bad.source_opening.opening.columns.pop();
        reject(&requests, &bad);
        let mut bad = proof.clone();
        bad.source_values[1][0] += F::one();
        reject(&requests, &bad);
        let mut bad = proof.clone();
        bad.algebra.instances.swap(0, 1);
        reject(&requests, &bad);
        let mut bad = proof.clone();
        bad.algebra.instances[0].pop();
        reject(&requests, &bad);
        let mut wrong = requests.clone();
        wrong[0].source_slots.swap(0, 1);
        reject(&wrong, &proof);
        let mut wrong = requests.clone();
        wrong[0].source_slots[0] = 3;
        reject(&wrong, &proof);
        reject(&[], &proof);
        let other = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(mu, k, 16, 2).unwrap();
        let wrong: Vec<_> = oracles
            .iter()
            .map(|o| snarks::packed_oracle::VerifierOracle {
                parameters: &other,
                commitment: o.commitment,
            })
            .collect();
        assert!(
            lookup::verify::<F, EF, Sha256, _>(
                &mut Transcript::new_direct(),
                &helper,
                &wrong,
                &requests,
                &proof
            )
            .is_err()
        );
    }
}
#[test]
fn babybear_shared_extension_lookups() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
}
#[test]
fn goldilocks_shared_extension_lookups() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}
