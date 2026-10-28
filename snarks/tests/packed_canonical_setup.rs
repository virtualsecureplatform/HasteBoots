use algebra::{
    AbstractExtensionField, Basis, NTTField, NTTPolynomial, matrix_weighted::PackedTable,
};
use helper::{FiatShamirTranscript, Transcript};
use lattice::{NTTGadgetRLWE, NTTRGSW, NTTRLWE};
use pcs::matrix_weighted::{
    backend::CanonicalPcs,
    masked_polyfrim::{Parameters, Proof as MaskedProof},
};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_bootstrap_key as bk, packed_key_switch as ks,
    packed_opening_batch::{CanonicalOpeningBatch, CanonicalProof},
    packed_pbs::{self, canonical_setup as setup},
};
use sumcheck::packed::challenge_pair;
fn fixture<F: NTTField>() -> (Vec<NTTRGSW<F>>, Vec<NTTGadgetRLWE<F>>) {
    let br = (0usize..21)
        .map(|r| {
            let mut key = NTTRGSW::zero(32, Basis::new(16));
            for g in [key.c_neg_s_m_mut()] {
                for (d, p) in g.iter_mut().enumerate() {
                    for i in 0..32 {
                        p.a_mut_slice()[i] = F::from(100 * r + 20 * d + i + 1);
                        p.b_mut_slice()[i] = F::from(100 * r + 20 * d + i + 9);
                    }
                }
            }
            for (d, p) in key.c_m_mut().iter_mut().enumerate() {
                for i in 0..32 {
                    p.a_mut_slice()[i] = F::from(100 * r + 20 * d + i + 31);
                    p.b_mut_slice()[i] = F::from(100 * r + 20 * d + i + 41);
                }
            }
            key
        })
        .collect();
    let config = ks::Config::new::<F>(32, 21, 16, 1).unwrap();
    let ks = vec![NTTGadgetRLWE::new(
        (0..config.digits::<F>().unwrap())
            .map(|d| {
                NTTRLWE::new(
                    NTTPolynomial::new((0..32).map(|i| F::from(70 * d + 2 * i + 1)).collect()),
                    NTTPolynomial::new((0..32).map(|i| F::from(80 * d + 3 * i + 5)).collect()),
                )
            })
            .collect(),
        Basis::new(16),
    )];
    (br, ks)
}
fn exercise<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let (br, ks) = fixture::<F>();
    let cfg = packed_pbs::Config::new::<F>(32, 21, 16, 16, 1, 1).unwrap();
    let dims = cfg.variables(2).unwrap();
    let parameters: Vec<_> = dims
        .into_iter()
        .map(|n| Parameters::<F, EF>::new(n, 2, 12, 2, 1, 2).unwrap())
        .collect();
    let pp = setup::Parameters {
        source: &parameters[0],
        helper: &parameters[1],
        final_source: &parameters[2],
        final_helper: &parameters[3],
    };
    let owner = setup::preprocess::<F, Sha256, _, _>(
        &pp,
        cfg.clone(),
        &br,
        &ks,
        &mut StdRng::seed_from_u64(739),
    )
    .unwrap();
    let verifier = owner.verifier();
    setup::validate::<F, Sha256, _>(&pp, &verifier).unwrap();
    let expected_br = bk::tables(2, 32, &br).unwrap();
    let expected_ks: Vec<_> = ks[0]
        .iter()
        .map(|p| {
            PackedTable::new(
                dims[2],
                2,
                p.a_slice().iter().chain(p.b_slice()).copied().collect(),
            )
            .unwrap()
        })
        .collect();
    // Two complete rounds borrow the same setup afresh; counters must persist.
    for round in 0..2 {
        let mut private = owner.br_oracles(pp.source).unwrap();
        private.extend(owner.ks_oracles(pp.final_source).unwrap());
        let mut public = setup::br_oracles::<F, Sha256, _>(pp.source, &verifier).unwrap();
        public.extend(setup::ks_oracles::<F, Sha256, _>(pp.final_source, &verifier).unwrap());
        let expected: Vec<_> = expected_br.iter().chain(&expected_ks).collect();
        assert_eq!(private.len(), expected.len());
        for (source, table) in private.iter().zip(&expected) {
            assert_eq!(source.table().values(), table.values());
            assert_eq!(source.state.spent().unwrap(), round);
        }
        let mut prover = Transcript::new_direct();
        let mut verifier_transcript = Transcript::new_direct();
        let mut obligations =
            CanonicalOpeningBatch::<F, Sha256, _>::new(&mut prover, &public).unwrap();
        let mut checked =
            CanonicalOpeningBatch::<F, Sha256, _>::new(&mut verifier_transcript, &public).unwrap();
        for (slot, (source, table)) in private.iter().zip(&expected).enumerate() {
            let query = vec![
                challenge_pair(&[F::from(3usize + round), F::from(7usize)]).unwrap();
                source.parameters.num_vars()
            ];
            let values = table.evaluate(&query).unwrap();
            obligations
                .push(&mut prover, slot, query.clone(), values.clone())
                .unwrap();
            checked
                .push(&mut verifier_transcript, slot, query, values)
                .unwrap();
        }
        let proof = obligations
            .prove(
                &mut prover,
                &private.iter().map(|s| s.state).collect::<Vec<_>>(),
            )
            .unwrap();
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (CanonicalProof<MaskedProof<EF, [u8; 32]>>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        checked.verify(&mut verifier_transcript, &proof).unwrap();
        assert_eq!(
            prover.get_challenge(b"after"),
            verifier_transcript.get_challenge(b"after")
        );
        assert!(
            private
                .iter()
                .all(|s| s.state.spent().unwrap() == round + 1)
        );
    }
    // A cloned public setup cannot reset the retained owner's opening allowance.
    let private = owner.br_oracles(pp.source).unwrap();
    let table = private[0].table();
    let query = vec![challenge_pair(&[F::one(), F::one()]).unwrap(); table.num_vars()];
    let values = table.evaluate(&query).unwrap();
    assert!(
        CanonicalPcs::<F, Sha256>::open(
            pp.source,
            &mut Transcript::new_direct(),
            private[0].commitment,
            private[0].state,
            &query,
            &values
        )
        .is_err()
    );
    assert!(private.iter().all(|s| s.state.spent().unwrap() == 2));
    let wrong = Parameters::<F, EF>::new(dims[0], 2, 13, 2, 1, 2).unwrap();
    assert!(owner.br_oracles(&wrong).is_err());
    assert!(setup::br_oracles::<F, Sha256, _>(&wrong, &verifier).is_err());
    let wrong = Parameters::<F, EF>::new(dims[2], 2, 13, 2, 1, 2).unwrap();
    assert!(owner.ks_oracles(&wrong).is_err());
    assert!(setup::ks_oracles::<F, Sha256, _>(&wrong, &verifier).is_err());
    let wrong = setup::Parameters {
        source: pp.helper,
        helper: pp.source,
        final_source: pp.final_source,
        final_helper: pp.final_helper,
    };
    assert!(setup::validate::<F, Sha256, _>(&wrong, &verifier).is_err());
    assert!(
        setup::preprocess::<F, Sha256, _, _>(
            &pp,
            cfg.clone(),
            &br[..2],
            &ks,
            &mut StdRng::seed_from_u64(1)
        )
        .is_err()
    );
    assert!(
        setup::preprocess::<F, Sha256, _, _>(
            &pp,
            cfg.clone(),
            &br,
            &[],
            &mut StdRng::seed_from_u64(1)
        )
        .is_err()
    );
    let foreign =
        setup::preprocess::<F, Sha256, _, _>(&pp, cfg, &br, &ks, &mut StdRng::seed_from_u64(740))
            .unwrap();
    let foreign = foreign.verifier();
    let expected = setup::br_oracles::<F, Sha256, _>(pp.source, &verifier).unwrap();
    let other = setup::br_oracles::<F, Sha256, _>(pp.source, &foreign).unwrap();
    assert_ne!(expected[0].commitment.root, other[0].commitment.root);
    println!(
        "HB_CANONICAL_NATIVE_KEY_SETUP {{\"prime\":{},\"key_roots\":{},\"decoded_openings\":{},\"lifetime_rounds\":2,\"native_full_pbs\":false,\"whole_security_certified\":false}}",
        F::MODULUS_VALUE,
        expected_br.len() + expected_ks.len(),
        2 * (expected_br.len() + expected_ks.len())
    );
}
#[test]
fn babybear() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}

fn brakedown_compatibility<F: NTTField + Serialize>() {
    use pcs::{matrix_weighted::Parameters as BaseParameters, utils::code::BlockReedSolomonCode};
    let (br, ks) = fixture::<F>();
    let cfg = packed_pbs::Config::new::<F>(32, 21, 16, 16, 1, 1).unwrap();
    let parameters: Vec<_> = cfg
        .variables(2)
        .unwrap()
        .into_iter()
        .map(|n| BaseParameters::<BlockReedSolomonCode<F>>::balanced_block_rs(n, 2, 8, 2).unwrap())
        .collect();
    let old_pp = packed_pbs::Parameters {
        source: &parameters[0],
        helper: &parameters[1],
        final_source: &parameters[2],
        final_helper: &parameters[3],
    };
    let pp = setup::Parameters {
        source: &parameters[0],
        helper: &parameters[1],
        final_source: &parameters[2],
        final_helper: &parameters[3],
    };
    let old = packed_pbs::preprocess::<F, Sha256, _>(&old_pp, cfg.clone(), &br, &ks).unwrap();
    let canonical =
        setup::preprocess::<F, Sha256, _, _>(&pp, cfg, &br, &ks, &mut StdRng::seed_from_u64(735))
            .unwrap();
    assert_eq!(
        bincode::serde::encode_to_vec(old.verifier(), bincode::config::standard()).unwrap(),
        bincode::serde::encode_to_vec(canonical.verifier(), bincode::config::standard()).unwrap()
    );
    setup::validate::<F, Sha256, _>(&pp, &canonical.verifier()).unwrap();
    assert!(!canonical.br_oracles(pp.source).unwrap().is_empty());
    assert!(!canonical.ks_oracles(pp.final_source).unwrap().is_empty());
}
#[test]
fn babybear_brakedown_public_setup_bytes() {
    brakedown_compatibility::<algebra::BabyBear>();
}
#[test]
fn goldilocks_brakedown_public_setup_bytes() {
    brakedown_compatibility::<algebra::Goldilocks>();
}
