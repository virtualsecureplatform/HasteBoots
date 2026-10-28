use algebra::{AbstractExtensionField, NTTField, matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript, Transcript};
use pcs::matrix_weighted::{
    backend::CanonicalPcs,
    masked_polyfrim::{Parameters, Proof as MaskedProof},
};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_monomial::{
        Plan,
        canonical::{self, Proof},
    },
    packed_oracle::CanonicalProverOracle,
};
fn fixture<F: NTTField>(width: usize, rotations: Vec<usize>) -> (Plan, Vec<PackedTable<F>>) {
    let plan = Plan::new(32, rotations).unwrap();
    let rows = plan.padded_rounds();
    let mut input = vec![F::zero(); 2 * rows * 32];
    let mut output = input.clone();
    for half in 0..2 {
        for (row, &rotation) in plan.rotations().iter().enumerate() {
            for c in 0..32 {
                let value = F::from((half * rows + row) * 32 + c + 3);
                input[(half * rows + row) * 32 + c] = value;
                let to = (c + rotation) % 64;
                if to < 32 {
                    output[(half * rows + row) * 32 + to] += value;
                } else {
                    output[(half * rows + row) * 32 + to - 32] -= value;
                }
            }
        }
    }
    let vars = (input.len() / width).ilog2() as usize;
    (
        plan,
        [input, output]
            .into_iter()
            .map(|v| PackedTable::new(vars, width, v).unwrap())
            .collect(),
    )
}
fn exercise<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    for (width, rotations) in [(1, vec![0]), (2, vec![0, 1, 31, 32, 37, 63])] {
        let (plan, tables) = fixture::<F>(width, rotations);
        let vars = tables[0].num_vars();
        let cpp: Vec<_> = (0..2)
            .map(|i| Parameters::<F, EF>::new(vars, width, 10 + i, 2, 1, width).unwrap())
            .collect();
        let epp = Parameters::<F, EF>::new(vars, width, 11, 2, 1, width + 1).unwrap();
        let (roots, states): (Vec<_>, Vec<_>) = tables
            .iter()
            .enumerate()
            .map(|(i, t)| {
                CanonicalPcs::<F, Sha256>::commit(
                    &cpp[i],
                    t,
                    &mut StdRng::seed_from_u64(747 + i as u64),
                )
                .unwrap()
            })
            .unzip();
        let sources: Vec<_> = (0..2)
            .map(|i| CanonicalProverOracle::<F, Sha256, _> {
                parameters: &cpp[i],
                commitment: &roots[i],
                state: &states[i],
            })
            .collect();
        let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
        let mut prover = Transcript::new_direct();
        let proof = canonical::prove::<F, Sha256, _, _>(
            &mut prover,
            &plan,
            &epp,
            &sources.iter().collect::<Vec<_>>(),
            &mut StdRng::seed_from_u64(851),
        )
        .unwrap();
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (
            Proof<F, [u8; 32], MaskedProof<EF, [u8; 32]>, MaskedProof<EF, [u8; 32]>>,
            usize,
        ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        for i in 0..2 {
            assert_eq!(states[i].spent().unwrap(), width);
            assert_eq!(
                proof.ntt[i]
                    .coefficient_opening
                    .openings
                    .iter()
                    .map(|p| p.index)
                    .collect::<Vec<_>>(),
                (0..width).collect::<Vec<_>>()
            );
            assert_eq!(
                proof.ntt[i]
                    .evaluation_opening
                    .openings
                    .iter()
                    .map(|p| p.index)
                    .collect::<Vec<_>>(),
                (0..width).collect::<Vec<_>>()
            );
            assert_eq!(proof.openings[i].openings[0].index, width);
        }
        let mut verifier = Transcript::new_direct();
        canonical::verify::<F, Sha256, _>(&mut verifier, &plan, &epp, &public, &proof).unwrap();
        assert_eq!(
            prover.get_challenge(b"after"),
            verifier.get_challenge(b"after")
        );
        let mut changed = proof.clone();
        changed.values[0][0] += F::one();
        assert!(
            canonical::verify::<F, Sha256, _>(
                &mut Transcript::new_direct(),
                &plan,
                &epp,
                &public,
                &changed
            )
            .is_err()
        );
        let mut changed = proof.clone();
        changed.ntt.pop();
        assert!(
            canonical::verify::<F, Sha256, _>(
                &mut Transcript::new_direct(),
                &plan,
                &epp,
                &public,
                &changed
            )
            .is_err()
        );
        let mut changed = proof.clone();
        changed.openings[0].openings.clear();
        assert!(
            canonical::verify::<F, Sha256, _>(
                &mut Transcript::new_direct(),
                &plan,
                &epp,
                &public,
                &changed
            )
            .is_err()
        );
        let mut changed = proof.clone();
        changed.evaluations[0].root[0] ^= 1;
        assert!(
            canonical::verify::<F, Sha256, _>(
                &mut Transcript::new_direct(),
                &plan,
                &epp,
                &public,
                &changed
            )
            .is_err()
        );
        let mut rotations = plan.rotations().to_vec();
        rotations[0] = (rotations[0] + 1) % 64;
        let wrong = Plan::new(32, rotations).unwrap();
        assert!(
            canonical::verify::<F, Sha256, _>(
                &mut Transcript::new_direct(),
                &wrong,
                &epp,
                &public,
                &proof
            )
            .is_err()
        );
        let wrong = Parameters::<F, EF>::new(vars, width, 12, 2, 1, width + 1).unwrap();
        assert!(
            canonical::verify::<F, Sha256, _>(
                &mut Transcript::new_direct(),
                &plan,
                &wrong,
                &public,
                &proof
            )
            .is_err()
        );
        assert!(
            canonical::prove::<F, Sha256, _, _>(
                &mut Transcript::new_direct(),
                &plan,
                &epp,
                &sources.iter().collect::<Vec<_>>(),
                &mut StdRng::seed_from_u64(853)
            )
            .is_err()
        );
        assert!(states.iter().all(|s| s.spent().unwrap() == width));
        println!(
            "HB_MASKED_CANONICAL_MONOMIAL {{\"prime\":{},\"width\":{},\"rounds\":{},\"genuine_child_openings\":{},\"native_pbs\":false,\"whole_security_certified\":false}}",
            F::MODULUS_VALUE,
            width,
            plan.rotations().len(),
            4 * width + 2
        );
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
fn brakedown() {
    use algebra::BabyBear as F;
    use pcs::matrix_weighted::{BatchOpening, Opening, Parameters as BaseParameters};
    let (plan, tables) = fixture::<F>(2, vec![1, 32, 63]);
    let pp = BaseParameters::balanced_block_rs(tables[0].num_vars(), 2, 8, 2).unwrap();
    let (roots, states): (Vec<_>, Vec<_>) = tables
        .iter()
        .map(|t| pp.commit::<F, Sha256>(t).unwrap())
        .unzip();
    let sources: Vec<_> = (0..2)
        .map(|i| CanonicalProverOracle::<F, Sha256, _> {
            parameters: &pp,
            commitment: &roots[i],
            state: &states[i],
        })
        .collect();
    let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    let mut prover = Transcript::new_direct();
    let proof = canonical::prove::<F, Sha256, _, _>(
        &mut prover,
        &plan,
        &pp,
        &sources.iter().collect::<Vec<_>>(),
        &mut StdRng::seed_from_u64(48),
    )
    .unwrap();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (
        Proof<F, [u8; 32], BatchOpening<F, [u8; 32]>, Opening<F, [u8; 32]>>,
        usize,
    ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut verifier = Transcript::new_direct();
    canonical::verify::<F, Sha256, _>(&mut verifier, &plan, &pp, &public, &proof).unwrap();
    assert_eq!(
        prover.get_challenge(b"after"),
        verifier.get_challenge(b"after")
    );
}

#[test]
fn goldilocks_terminal_codec() {
    use algebra::{Field, Goldilocks as F, GoldilocksExtension3 as E};
    let cpp = Parameters::<F, E>::new(6, 1, 10, 2, 1, 1).unwrap();
    let epp = Parameters::<F, E>::new(6, 1, 10, 2, 1, 2).unwrap();
    let plan = Plan::new(32, vec![0]).unwrap();
    let table = PackedTable::new(6, 1, vec![F::new(0); 64]).unwrap();
    let (roots, states): (Vec<_>, Vec<_>) = (0..2)
        .map(|i| {
            CanonicalPcs::<F, Sha256>::commit(&cpp, &table, &mut StdRng::seed_from_u64(211 + i))
                .unwrap()
        })
        .unzip();
    let sources: Vec<_> = (0..2)
        .map(|i| CanonicalProverOracle::<F, Sha256, _> {
            parameters: &cpp,
            commitment: &roots[i],
            state: &states[i],
        })
        .collect();
    let mut proof = canonical::prove::<F, Sha256, _, _>(
        &mut Transcript::new_direct(),
        &plan,
        &epp,
        &sources.iter().collect::<Vec<_>>(),
        &mut StdRng::seed_from_u64(215),
    )
    .unwrap();
    proof.values[0][0] = F::new(F::MODULUS_VALUE);
    let err = canonical::verify::<F, Sha256, _>(
        &mut Transcript::new_direct(),
        &plan,
        &epp,
        &sources.iter().map(|s| s.verifier()).collect::<Vec<_>>(),
        &proof,
    )
    .unwrap_err();
    assert!(
        err.0.contains("noncanonical public packed response"),
        "{err}"
    );
}
