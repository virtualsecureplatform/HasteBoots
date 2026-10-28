use super::*;
use algebra::{AbstractExtensionField, NTTField};
use pcs::matrix_weighted::masked_polyfrim::Parameters as MaskedParameters;
use rand::{SeedableRng, rngs::StdRng};
use serde::de::DeserializeOwned;
use sha2::Sha256;
fn fresh<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    for broken_chain in [false, true] {
        let shape = Shape::new(2, 3).unwrap();
        let width = 2;
        let rows = 4;
        let mut input = vec![F::zero(); 16];
        let mut output = input.clone();
        let mut sum = input.clone();
        for h in 0..2 {
            for r in 0usize..3 {
                for c in 0..2 {
                    let at = (h * rows + r) * 2 + c;
                    input[at] = F::from(r);
                    output[at] = F::from(r + 1);
                    sum[at] = F::one();
                }
            }
        }
        let mut monomial = input.clone();
        let mut initial = vec![F::zero(); 4];
        let final_acc = vec![F::from(3usize); 4];
        if broken_chain {
            input[2] += F::one();
            monomial[2] += F::one();
            output[2] += F::one();
        } else {
            initial[0] += F::one();
        }
        let tables: Vec<_> = [
            input,
            monomial,
            vec![F::zero(); 16],
            output,
            sum,
            vec![F::zero(); 16],
            vec![F::zero(); 16],
        ]
        .into_iter()
        .map(|v| PackedTable::new(3, width, v).unwrap())
        .collect();
        let pp = MaskedParameters::<F, EF>::new(3, width, 11, 2, 1, 5).unwrap();
        let (roots, states): (Vec<_>, Vec<_>) = tables
            .iter()
            .enumerate()
            .map(|(i, t)| {
                CanonicalPcs::<F, Sha256>::commit(
                    &pp,
                    t,
                    &mut StdRng::seed_from_u64(712 + i as u64),
                )
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
        assert!(
            prove_canonical::<F, Sha256, _>(
                &mut Transcript::new_direct(),
                &shape,
                &initial,
                &final_acc,
                &sources.iter().collect::<Vec<_>>()
            )
            .is_err()
        );
        assert!(states.iter().all(|s| s.spent().unwrap() == 0));
        let mut prover = Transcript::new_direct();
        let (_, queries) = bind_queries_backend::<F, Sha256, _>(
            &mut prover,
            &shape,
            &initial,
            &final_acc,
            &public,
        )
        .unwrap();
        let values: Vec<Vec<_>> = tables
            .iter()
            .zip(&queries)
            .map(|(table, q)| {
                evaluate_many(table, q)
                    .unwrap()
                    .into_iter()
                    .map(|v| CanonicalPcs::<F, Sha256>::normalize_values(&pp, v))
                    .collect()
            })
            .collect();
        let openings = sources
            .iter()
            .zip(&queries)
            .zip(&values)
            .map(|((s, q), v)| {
                CanonicalPcs::<F, Sha256>::open_many(&pp, &mut prover, s.commitment, s.state, q, v)
                    .unwrap()
            })
            .collect();
        let proof = CanonicalProof { values, openings };
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (
            CanonicalProof<F, pcs::matrix_weighted::masked_polyfrim::Proof<EF, [u8; 32]>>,
            usize,
        ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        // Strict independent PCS replay skips only the disputed linkage equations.
        let mut reference = Transcript::new_direct();
        let (_, queries) = bind_queries_backend::<F, Sha256, _>(
            &mut reference,
            &shape,
            &initial,
            &final_acc,
            &public,
        )
        .unwrap();
        for (((s, q), v), p) in public
            .iter()
            .zip(&queries)
            .zip(&proof.values)
            .zip(&proof.openings)
        {
            CanonicalPcs::<F, Sha256>::verify_many(&pp, &mut reference, s.commitment, q, v, p)
                .unwrap();
        }
        assert_eq!(
            prover.get_challenge(b"after"),
            reference.get_challenge(b"after")
        );
        let err = verify_canonical::<F, Sha256, _>(
            &mut Transcript::new_direct(),
            &shape,
            &initial,
            &final_acc,
            &public,
            &proof,
        )
        .unwrap_err();
        assert!(
            err.0.contains(if broken_chain {
                "continuity"
            } else {
                "endpoint"
            }),
            "{err}"
        );
        println!(
            "HB_MASKED_ACCUMULATOR_FORGERY {{\"prime\":{},\"broken_chain\":{},\"genuine_child_openings\":{},\"production_accepted\":false}}",
            F::MODULUS_VALUE,
            broken_chain,
            proof.values.iter().map(Vec::len).sum::<usize>()
        );
    }
}
#[test]
fn babybear_fresh_false_linkage() {
    fresh::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks_fresh_false_linkage() {
    fresh::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}
