use algebra::{AbstractExtensionField, NTTField, PrimeField, matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript, Transcript};
use pcs::matrix_weighted::{
    backend::CanonicalPcs,
    masked_polyfrim::{Parameters, Proof as MaskedProof},
};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_accumulator::{self, CanonicalProof, Shape},
    packed_oracle::{CanonicalProverOracle, ProverOracle},
};
#[allow(dead_code)]
#[path = "support/legacy_packed_accumulator_v1.rs"]
mod legacy;
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

fn exercise<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    for (n, width, rounds, physical, budget) in
        [(1, 1, 1, 10, 3), (4, 2, 3, 11, 5), (4, 2, 5, 12, 6)]
    {
        let (shape, initial, final_acc, tables) = fixture::<F>(n, width, rounds);
        let pp: Vec<_> = (0..7)
            .map(|i| {
                Parameters::<F, EF>::new(
                    tables[0].num_vars(),
                    width,
                    physical + i % 2,
                    2,
                    1,
                    budget,
                )
                .unwrap()
            })
            .collect();
        let (roots, states): (Vec<_>, Vec<_>) = tables
            .iter()
            .enumerate()
            .map(|(i, t)| {
                CanonicalPcs::<F, Sha256>::commit(
                    &pp[i],
                    t,
                    &mut StdRng::seed_from_u64(928 + i as u64),
                )
                .unwrap()
            })
            .unzip();
        let sources: Vec<_> = (0..7)
            .map(|i| CanonicalProverOracle::<F, Sha256, _> {
                parameters: &pp[i],
                commitment: &roots[i],
                state: &states[i],
            })
            .collect();
        let refs: Vec<_> = sources.iter().collect();
        let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
        let mut prover = Transcript::new_direct();
        let proof = packed_accumulator::prove_canonical::<F, Sha256, _>(
            &mut prover,
            &shape,
            &initial,
            &final_acc,
            &refs,
        )
        .unwrap();
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (CanonicalProof<F, MaskedProof<EF, [u8; 32]>>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let mut verifier = Transcript::new_direct();
        packed_accumulator::verify_canonical::<F, Sha256, _>(
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
        for (state, values) in states.iter().zip(&proof.values) {
            assert_eq!(state.spent().unwrap(), values.len());
            assert!(values.iter().flatten().all(|v| v.is_canonical()));
        }
        let mut bad = proof.clone();
        bad.values[0][0][0] += F::one();
        assert!(
            packed_accumulator::verify_canonical::<F, Sha256, _>(
                &mut Transcript::new_direct(),
                &shape,
                &initial,
                &final_acc,
                &public,
                &bad
            )
            .is_err()
        );
        let mut bad = proof.clone();
        bad.openings.pop();
        assert!(
            packed_accumulator::verify_canonical::<F, Sha256, _>(
                &mut Transcript::new_direct(),
                &shape,
                &initial,
                &final_acc,
                &public,
                &bad
            )
            .is_err()
        );
        let mut wrong = final_acc.clone();
        wrong[0] += F::one();
        assert!(
            packed_accumulator::verify_canonical::<F, Sha256, _>(
                &mut Transcript::new_direct(),
                &shape,
                &initial,
                &wrong,
                &public,
                &proof
            )
            .is_err()
        );
        let mut wrong = roots.clone();
        wrong[0].root[0] ^= 1;
        let mut changed = sources.iter().map(|s| s.verifier()).collect::<Vec<_>>();
        changed[0].commitment = &wrong[0];
        assert!(
            packed_accumulator::verify_canonical::<F, Sha256, _>(
                &mut Transcript::new_direct(),
                &shape,
                &initial,
                &final_acc,
                &changed,
                &proof
            )
            .is_err()
        );
        println!(
            "HB_MASKED_CANONICAL_ACCUMULATOR {{\"prime\":{},\"rounds\":{},\"width\":{},\"child_openings\":{},\"native_pbs\":false,\"whole_security_certified\":false}}",
            F::MODULUS_VALUE,
            rounds,
            width,
            proof.values.iter().map(Vec::len).sum::<usize>()
        );
        // Frozen direct-dispatch implementation controls ordinary legacy bytes.
        let old =
            pcs::matrix_weighted::Parameters::balanced_block_rs(tables[0].num_vars(), width, 8, 2)
                .unwrap();
        let (roots, states): (Vec<_>, Vec<_>) = tables
            .iter()
            .map(|t| old.commit::<F, Sha256>(t).unwrap())
            .unzip();
        let sources: Vec<_> = (0..7)
            .map(|i| ProverOracle::<F, Sha256, _> {
                parameters: &old,
                commitment: &roots[i],
                state: &states[i],
                table: &tables[i],
            })
            .collect();
        let refs: Vec<_> = sources.iter().collect();
        let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
        let mut a = Transcript::new_direct();
        let mut b = Transcript::new_direct();
        let proof =
            packed_accumulator::prove::<F, Sha256, _>(&mut a, &shape, &initial, &final_acc, &refs)
                .unwrap();
        let old_shape = legacy::Shape::new(n, rounds).unwrap();
        let frozen =
            legacy::prove::<F, Sha256, _>(&mut b, &old_shape, &initial, &final_acc, &refs).unwrap();
        assert_eq!(
            bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap(),
            bincode::serde::encode_to_vec(&frozen, bincode::config::standard()).unwrap()
        );
        assert_eq!(a.get_challenge(b"after"), b.get_challenge(b"after"));
        let mut a = Transcript::new_direct();
        let mut b = Transcript::new_direct();
        packed_accumulator::verify::<F, Sha256, _>(
            &mut a, &shape, &initial, &final_acc, &public, &proof,
        )
        .unwrap();
        legacy::verify::<F, Sha256, _>(&mut b, &old_shape, &initial, &final_acc, &public, &frozen)
            .unwrap();
        assert_eq!(a.get_challenge(b"after"), b.get_challenge(b"after"));
    }
}
#[test]
fn babybear() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}

#[test]
fn goldilocks_terminal_codec_and_public_endpoint_aliases() {
    use algebra::{Field, Goldilocks as F, GoldilocksExtension3 as E};
    let pp = Parameters::<F, E>::new(1, 1, 10, 2, 1, 3).unwrap();
    let shape = Shape::new(1, 1).unwrap();
    let table = PackedTable::new(1, 1, vec![F::new(0); 2]).unwrap();
    let (roots, states): (Vec<_>, Vec<_>) = (0..7)
        .map(|i| {
            CanonicalPcs::<F, Sha256>::commit(&pp, &table, &mut StdRng::seed_from_u64(572 + i))
                .unwrap()
        })
        .unzip();
    let sources: Vec<_> = (0..7)
        .map(|i| CanonicalProverOracle::<F, Sha256, _> {
            parameters: &pp,
            commitment: &roots[i],
            state: &states[i],
        })
        .collect();
    let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    let endpoints = vec![F::new(0); 2];
    let mut prover = Transcript::new_direct();
    let proof = packed_accumulator::prove_canonical::<F, Sha256, _>(
        &mut prover,
        &shape,
        &endpoints,
        &endpoints,
        &sources.iter().collect::<Vec<_>>(),
    )
    .unwrap();
    let aliases = vec![F::new(F::MODULUS_VALUE); 2];
    let mut verifier = Transcript::new_direct();
    packed_accumulator::verify_canonical::<F, Sha256, _>(
        &mut verifier,
        &shape,
        &aliases,
        &aliases,
        &public,
        &proof,
    )
    .unwrap();
    assert_eq!(
        prover.get_challenge(b"after"),
        verifier.get_challenge(b"after")
    );
    let mut bad = proof;
    bad.values[0][0][0] = F::new(F::MODULUS_VALUE);
    let err = packed_accumulator::verify_canonical::<F, Sha256, _>(
        &mut Transcript::new_direct(),
        &shape,
        &endpoints,
        &endpoints,
        &public,
        &bad,
    )
    .unwrap_err();
    assert!(
        err.0.contains("noncanonical public packed response"),
        "{err}"
    );
}
