use super::*;
use algebra::NTTField;
use pcs::matrix_weighted::masked_polyfrim::{Parameters, Proof as MaskedProof};
use rand::{SeedableRng, rngs::StdRng};
use serde::de::DeserializeOwned;
use sha2::Sha256;
use sumcheck::packed::challenge_pair;
fn fresh<F, EF>(width: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    let config = Config::new::<F>(8, 2 * width, 1).unwrap();
    let d = config.num_digits::<F>().unwrap();
    let spp = Parameters::<F, EF>::new(1, width, 11, 2, 1, 1).unwrap();
    let dpp = Parameters::<F, EF>::new(1, width, 11, 2, 1, 2).unwrap();
    let bpp = Parameters::<F, EF>::new(1, width, 12, 2, 1, 3).unwrap();
    let helper = Parameters::<F, EF>::new(1 + width.ilog2() as usize, width, 12, 2, 1, 2).unwrap();
    let mut tables = vec![PackedTable::new(1, width, vec![F::zero(); 2 * width]).unwrap()];
    for i in 0..d {
        tables.push(
            PackedTable::new(
                1,
                width,
                vec![F::from(((p >> (8 * i)) & 255) as usize); 2 * width],
            )
            .unwrap(),
        );
    }
    let (roots, states): (Vec<_>, Vec<_>) = tables
        .iter()
        .enumerate()
        .map(|(i, t)| {
            CanonicalPcs::<F, Sha256>::commit(
                if i == 0 { &spp } else { &dpp },
                t,
                &mut StdRng::seed_from_u64(649 + i as u64),
            )
            .unwrap()
        })
        .unzip();
    let sources: Vec<_> = (0..=d)
        .map(|i| CanonicalProverOracle::<F, Sha256, _> {
            parameters: if i == 0 { &spp } else { &dpp },
            commitment: &roots[i],
            state: &states[i],
        })
        .collect();
    let digits: Vec<_> = sources[1..].iter().collect();
    let public: Vec<_> = digits.iter().map(|s| s.verifier()).collect();
    assert!(
        prove::<F, EF, Sha256, _, _>(
            &mut Transcript::new_direct(),
            &config,
            &sources[0],
            &bpp,
            &helper,
            &digits,
            &mut StdRng::seed_from_u64(650)
        )
        .is_err()
    );
    assert!(states.iter().all(|s| s.spent().unwrap() == 0));
    // The integer digit string is p, hence congruent to source zero but noncanonical.
    // Every subtraction transition is genuine; only the final zero endpoint fails.
    let mut carry = 0;
    let mut bits = vec![0usize];
    for i in 0..d {
        carry = usize::from(
            ((p >> (8 * i)) & 255) as usize + carry > config.modulus_digit::<F>(i).unwrap(),
        );
        bits.push(carry);
    }
    assert_eq!(carry, 1);
    let (br, bs): (Vec<_>, Vec<_>) = bits
        .iter()
        .enumerate()
        .map(|(i, &bit)| {
            let t = PackedTable::new(1, width, vec![F::from(bit); 2 * width]).unwrap();
            CanonicalPcs::<F, Sha256>::commit(&bpp, &t, &mut StdRng::seed_from_u64(680 + i as u64))
                .unwrap()
        })
        .unzip();
    let borrows: Vec<_> = br
        .iter()
        .zip(&bs)
        .map(
            |(commitment, state)| CanonicalProverOracle::<F, Sha256, _> {
                parameters: &bpp,
                commitment,
                state,
            },
        )
        .collect();
    let mut prover = Transcript::new_direct();
    bind::<F, EF, Sha256, _>(
        &mut prover,
        &config,
        &sources[0].verifier(),
        &bpp,
        &helper,
        &public,
    )
    .unwrap();
    prover.append_message(b"packed canonical decomposition borrow roots", &br);
    let linear_sources: Vec<_> = sources.iter().chain(&borrows).collect();
    let relations = relations::<F>(&config).unwrap();
    // Replay the exact public linear challenge framing, without its false endpoint check.
    let query = |trans: &mut Transcript<F>| {
        let contexts: Vec<_> = linear_sources
            .iter()
            .map(|s| {
                (
                    CanonicalPcs::<F, Sha256>::context(s.parameters).unwrap(),
                    s.commitment,
                )
            })
            .collect();
        let normalized: Vec<_> = relations
            .iter()
            .map(|r| Relation {
                terms: CanonicalPcs::<F, Sha256>::normalize_values(
                    &spp,
                    r.terms.iter().map(|(a, _)| *a).collect(),
                )
                .into_iter()
                .zip(r.terms.iter().map(|(_, i)| *i))
                .collect(),
            })
            .collect();
        trans.append_message(
            <Parameters<F, EF> as CanonicalPcs<F, Sha256>>::LINEAR_DOMAIN,
            &(contexts, &normalized),
        );
        vec![
            challenge_pair(
                &trans.get_vec_challenge(b"packed linear independent challenges", width),
            )
            .unwrap(),
        ]
    };
    let q = query(&mut prover);
    let values: Vec<_> = linear_sources
        .iter()
        .map(|s| {
            CanonicalPcs::<F, Sha256>::normalize_values(
                s.parameters,
                s.table().evaluate(&q).unwrap(),
            )
        })
        .collect();
    let openings = linear_sources
        .iter()
        .zip(&values)
        .map(|(s, v)| {
            CanonicalPcs::<F, Sha256>::open(s.parameters, &mut prover, s.commitment, s.state, &q, v)
                .unwrap()
        })
        .collect();
    let linear = packed_linear::CanonicalProof { values, openings };
    let registry: Vec<_> = digits.iter().copied().chain(borrows.iter()).collect();
    let requests = comparison_requests::<F>(&config).unwrap();
    let comparisons = requests
        .iter()
        .map(|r| {
            lookup::prove::<F, EF, Sha256, _, _>(
                &mut prover,
                &r.config,
                &helper,
                &r.source_slots
                    .iter()
                    .map(|&s| registry[s])
                    .collect::<Vec<_>>(),
                &mut StdRng::seed_from_u64(710 + r.source_slots[0] as u64),
            )
            .unwrap()
        })
        .collect();
    let proof = Proof {
        borrow_commitments: br.clone(),
        linear,
        comparisons,
    };
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (
        Proof<F, EF, [u8; 32], MaskedProof<EF, [u8; 32]>, MaskedProof<EF, [u8; 32]>>,
        usize,
    ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut reference = Transcript::new_direct();
    bind::<F, EF, Sha256, _>(
        &mut reference,
        &config,
        &sources[0].verifier(),
        &bpp,
        &helper,
        &public,
    )
    .unwrap();
    reference.append_message(
        b"packed canonical decomposition borrow roots",
        &proof.borrow_commitments,
    );
    let q = query(&mut reference);
    for ((s, v), opening) in linear_sources
        .iter()
        .zip(&proof.linear.values)
        .zip(&proof.linear.openings)
    {
        CanonicalPcs::<F, Sha256>::verify(
            s.parameters,
            &mut reference,
            s.commitment,
            &q,
            v,
            opening,
        )
        .unwrap();
    }
    for (r, c) in requests.iter().zip(&proof.comparisons) {
        lookup::verify::<F, EF, Sha256, _>(
            &mut reference,
            &r.config,
            &helper,
            &r.source_slots
                .iter()
                .map(|&s| registry[s].verifier())
                .collect::<Vec<_>>(),
            c,
        )
        .unwrap();
    }
    assert_eq!(
        prover.get_challenge(b"after"),
        reference.get_challenge(b"after")
    );
    let err = verify::<F, EF, Sha256, _>(
        &mut Transcript::new_direct(),
        &config,
        &sources[0].verifier(),
        &bpp,
        &helper,
        &public,
        &proof,
    )
    .unwrap_err();
    assert!(err.0.contains("false canonical linear identity"), "{err}");
    assert_eq!(states[0].spent().unwrap(), 1);
    assert!(states[1..].iter().all(|s| s.spent().unwrap() == 2));
    for (i, s) in bs.iter().enumerate() {
        assert_eq!(s.spent().unwrap(), if i == 0 || i == d { 2 } else { 3 });
    }
    println!(
        "HB_MASKED_DECOMPOSITION_FORGERY {{\"prime\":{},\"digits\":{},\"genuine_child_openings\":{},\"production_accepted\":false}}",
        F::MODULUS_VALUE,
        d,
        7 * d + 2
    );
}
#[test]
fn babybear_noncanonical_integer() {
    fresh::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
}
#[test]
fn goldilocks_noncanonical_integer() {
    fresh::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}
