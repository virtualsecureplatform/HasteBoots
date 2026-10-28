//! Fresh complete algebraic certificates, including every actual-root opening.
//! Zero evaluation keys isolate linkage; these are not encrypted native profiles.
use super::*;
use algebra::Basis;
use rand::{SeedableRng, rngs::StdRng};
use serde::de::DeserializeOwned;
use sha2::Sha256;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Attack {
    Control,
    Initial,
    Final,
    Addition,
    Chain,
    DigitA,
    DigitB,
    Rotation,
    ExtractionA,
    ExtractionB,
    KeyProduct,
    SwitchKeyProduct,
}
impl Attack {
    fn accumulator_valid(self) -> bool {
        matches!(
            self,
            Self::Control
                | Self::Rotation
                | Self::ExtractionA
                | Self::ExtractionB
                | Self::KeyProduct
                | Self::SwitchKeyProduct
        )
    }
    fn monomial_valid(self) -> bool {
        self != Self::Rotation
    }
    fn extraction_valid(self) -> bool {
        !matches!(self, Self::ExtractionA | Self::ExtractionB)
    }
}
struct Report {
    key_product: bool,
    switch_key_product: bool,
    accumulator: bool,
    monomial: bool,
    extraction: bool,
}
fn make<F, EF, P>(
    pp: &Parameters<'_, P>,
    setup: &canonical_setup::ProverSetup<F, Sha256, P>,
    attack: Attack,
    seed: u64,
) -> (
    StatementData<F>,
    Proof<F, EF, [u8; 32], P::SingleProof, P::BatchProof>,
    F,
)
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    P: CanonicalPcs<F, Sha256>,
{
    let expected = setup.verifier();
    let cfg = &expected.config;
    let width = pp.coefficients.width();
    let vars = pp.coefficients.num_vars();
    let size = (1usize << vars) * width;
    let rows = cfg.lwe.next_power_of_two();
    let half = size / 2;
    let d = cfg.decomposition::<F>().unwrap().num_digits::<F>().unwrap();
    let mut s = StatementData {
        mask: vec![F::zero(); cfg.lwe],
        body: F::zero(),
        output: vec![F::zero(); cfg.lwe],
        output_b: F::zero(),
    };
    let (_, initial) = public_inputs(cfg, &s.borrowed()).unwrap();
    let mut final_acc = initial.clone();
    let mut acc_values = vec![F::zero(); size];
    for row in 0..cfg.lwe {
        acc_values[row * cfg.n..(row + 1) * cfg.n].copy_from_slice(&initial[..cfg.n]);
        acc_values[half + row * cfg.n..half + (row + 1) * cfg.n].copy_from_slice(&initial[cfg.n..]);
    }
    let mut ac = vec![
        acc_values.clone(),
        acc_values.clone(),
        vec![F::zero(); size],
        acc_values,
    ];
    let mut co = vec![vec![F::zero(); size]; 2 * d + 1];
    let mut inputs = vec![vec![F::zero(); size]; 2];
    match attack {
        Attack::Initial => {
            let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
            s.body = F::from((p / 4) as usize);
            assert_ne!(public_inputs(cfg, &s.borrowed()).unwrap().1, initial);
        }
        Attack::Final => {
            final_acc[cfg.n] += F::one();
        }
        Attack::Addition => {
            for v in &mut ac[3] {
                *v += F::one();
            }
        }
        Attack::Chain => {
            for i in [0, 1, 3] {
                ac[i][half + cfg.n] += F::one();
            }
        }
        Attack::DigitA => {
            inputs[0].fill(F::one());
            co[0].fill(F::one());
        }
        Attack::DigitB => {
            inputs[1].fill(F::one());
            co[d].fill(F::one());
        }
        Attack::Rotation | Attack::KeyProduct | Attack::SwitchKeyProduct => {
            let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
            s.mask[0] = F::from((p / (4 * cfg.n as u128)) as usize);
        }
        Attack::Control | Attack::ExtractionA | Attack::ExtractionB => {}
    }
    if matches!(attack, Attack::KeyProduct | Attack::SwitchKeyProduct) {
        // Rotate only the first active round. The zero-key trace leaves its
        // accumulator unchanged, but has a genuine nonzero external input.
        for h in 0..2 {
            let offset = h * half;
            let original = &initial[h * cfg.n..(h + 1) * cfg.n];
            for j in 0..cfg.n {
                ac[1][offset + j] = if j == 0 {
                    -original[cfg.n - 1]
                } else {
                    original[j - 1]
                };
                ac[2][offset + j] = ac[1][offset + j] - ac[0][offset + j];
            }
            // The decomposition source duplicates its selected ciphertext half.
            for row in 0..rows {
                for j in 0..cfg.n {
                    let x = ac[2][offset + row * cfg.n + j];
                    for duplicate in 0..2 {
                        let index = duplicate * half + row * cfg.n + j;
                        inputs[h][index] = x;
                        let mut integer: usize = x.canonicalized().value().try_into().ok().unwrap();
                        for limb in 0..d {
                            co[h * d + limb][index] = F::from((integer & 255) as usize);
                            integer >>= 8;
                        }
                        assert_eq!(integer, 0);
                    }
                }
            }
        }
    }
    if attack == Attack::SwitchKeyProduct {
        // The genuine BR key sends the first body external input into mask a.
        // Later identity rotations preserve this new accumulator mask.
        let delta = ac[2][half..half + cfg.n].to_vec();
        for j in 0..cfg.n {
            co[2 * d][j] = delta[j];
            ac[3][j] = delta[j];
            final_acc[j] = delta[j];
            for row in 1..cfg.lwe {
                for source in [0, 1, 3] {
                    ac[source][row * cfg.n + j] = delta[j];
                }
            }
        }
        assert!(final_acc[..cfg.n].iter().any(|&x| x != F::zero()));
    }
    let final_acc = pp.coefficients.normalize_values(final_acc);
    s.output_b = final_acc[cfg.n] + mono::nand_lut::<F>(cfg.n, cfg.lut_step).unwrap()[0];
    let actual_output = s.output.clone();
    let actual_body = s.output_b;
    if attack == Attack::ExtractionA {
        s.output[1] += F::one();
    }
    if attack == Attack::ExtractionB {
        s.output_b += F::one();
    }
    let (plan, requested_initial) = public_inputs(cfg, &s.borrowed()).unwrap();
    let actual_plan = mono::Plan::new(cfg.n, vec![0; cfg.lwe]).unwrap();
    if matches!(
        attack,
        Attack::Rotation | Attack::KeyProduct | Attack::SwitchKeyProduct
    ) {
        assert_eq!(plan.rotations()[0], 1);
    } else {
        assert!(plan.rotations().iter().all(|&r| r == 0));
    }
    let mut rng = StdRng::seed_from_u64(seed);
    let tables = |values: Vec<Vec<F>>| {
        values
            .into_iter()
            .map(|v| PackedTable::new(vars, width, v).unwrap())
            .collect::<Vec<_>>()
    };
    let (co_roots, co_states) =
        commit::<F, Sha256, P, _>(pp.coefficients, &tables(co), &mut rng).unwrap();
    F::init_ntt_table(cfg.n.ilog2()).unwrap();
    let native = F::get_ntt_table(cfg.n.ilog2()).unwrap();
    let ev_tables: Vec<_> = co_states
        .iter()
        .map(|state| {
            let mut v = P::table(state).values().to_vec();
            for p in v.chunks_exact_mut(cfg.n) {
                native.transform_slice(p);
            }
            PackedTable::new(vars, width, v).unwrap()
        })
        .collect();
    let (ev_roots, ev_states) =
        commit::<F, Sha256, P, _>(pp.evaluations, &ev_tables, &mut rng).unwrap();
    let (ac_roots, ac_states): (Vec<_>, Vec<_>) = tables(ac)
        .iter()
        .zip(pp.accumulators)
        .map(|(t, p)| p.commit(t, &mut rng).map_err(convert).unwrap())
        .unzip();
    let (in_roots, in_states) =
        commit::<F, Sha256, P, _>(pp.inputs, &tables(inputs), &mut rng).unwrap();
    let normalized = statement::<F, Sha256, P>(pp.coefficients, &s.borrowed());
    let mut trans = Transcript::new_direct();
    bind::<F, EF, Sha256, P>(
        &mut trans,
        pp,
        &expected,
        &normalized,
        &co_roots,
        &ev_roots,
        &in_roots,
        &ac_roots,
        &final_acc,
    )
    .unwrap();
    let co = oracles::<F, Sha256, P>(pp.coefficients, &co_roots, &co_states);
    let ev = oracles::<F, Sha256, P>(pp.evaluations, &ev_roots, &ev_states);
    let input = oracles::<F, Sha256, P>(pp.inputs, &in_roots, &in_states);
    let ac: Vec<_> = ac_roots
        .iter()
        .zip(&ac_states)
        .zip(pp.accumulators)
        .map(
            |((commitment, state), parameters)| CanonicalProverOracle::<F, Sha256, P> {
                parameters,
                commitment,
                state,
            },
        )
        .collect();
    let key = setup.br_oracles(pp.key).unwrap();
    let factors: Vec<_> = (0..2 * d)
        .flat_map(|i| [&ev[i], &key[i]])
        .chain(std::iter::once(&ev[2 * d]))
        .collect();
    let hadamard = if attack == Attack::KeyProduct {
        let foreign: Vec<_> = factors
            .iter()
            .enumerate()
            .map(|(i, s)| {
                if i % 2 == 1 {
                    PackedTable::new(vars, width, vec![F::zero(); size]).unwrap()
                } else {
                    s.table().clone()
                }
            })
            .collect();
        relation::audit::prove_foreign::<F, Sha256, P>(
            &mut trans,
            &shape(vars, width, 2 * d),
            &factors,
            &foreign,
        )
        .unwrap()
    } else {
        relation::prove_canonical::<F, Sha256, P>(
            &mut trans,
            &shape(vars, width, 2 * d),
            &factors,
            &mut relation::ProverStatistics::default(),
        )
        .unwrap()
    };
    let ntt_shape = ntt::Shape::new_canonical::<F, Sha256, P>(pp.coefficients, cfg.n).unwrap();
    let ntt = (0..2 * d + 1)
        .map(|i| {
            ntt::prove_canonical::<F, Sha256, P>(&mut trans, &ntt_shape, &co[i], &ev[i]).unwrap()
        })
        .collect();
    let decomposition = (0..2)
        .map(|h| {
            decomp::canonical::prove::<F, EF, Sha256, P, _>(
                &mut trans,
                &cfg.decomposition::<F>().unwrap(),
                &input[h],
                pp.borrows,
                pp.helper,
                &co[h * d..(h + 1) * d].iter().collect::<Vec<_>>(),
                &mut rng,
            )
            .unwrap()
        })
        .collect();
    let sources = [
        &ac[0],
        &ac[1],
        &ac[2],
        &ac[3],
        &co[2 * d],
        &input[0],
        &input[1],
    ];
    let (accumulator, valid) = acc::audit::prove::<F, Sha256, P>(
        &mut trans,
        &acc::Shape::new(cfg.n, cfg.lwe).unwrap(),
        &requested_initial,
        &final_acc,
        &sources,
    )
    .unwrap();
    assert_eq!(valid, attack.accumulator_valid());
    let monomial = mono::canonical::audit::prove_foreign::<F, Sha256, P, _>(
        &mut trans,
        &plan,
        if attack == Attack::Rotation {
            &actual_plan
        } else {
            &plan
        },
        pp.monomial,
        &[&ac[0], &ac[1]],
        &mut rng,
    )
    .unwrap();
    let coefficients = final_stage::audit::zero_key_coefficients::<F, Sha256, P>(
        &pp.final_stage,
        &expected.ks,
        &final_acc,
    )
    .unwrap();
    let key_switch = final_stage::audit::prove_foreign::<F, EF, Sha256, P, _>(
        &mut trans,
        &pp.final_stage,
        setup.switching_key(),
        &final_acc,
        &s.output,
        s.output_b,
        &actual_output,
        actual_body,
        &coefficients,
        attack == Attack::SwitchKeyProduct,
        &mut rng,
    )
    .unwrap();
    let proof = Proof {
        protocol_version: 10,
        coefficients: co_roots,
        evaluations: ev_roots,
        decomposition_inputs: in_roots,
        accumulators: ac_roots,
        final_accumulator: final_acc,
        hadamard,
        ntt,
        decomposition,
        accumulator,
        monomial,
        key_switch,
    };
    let digest = trans.get_challenge(b"v10 fresh complete certificate after");
    assert_eq!(rows, 32);
    (s, proof, digest)
}

struct StatementData<F> {
    mask: Vec<F>,
    body: F,
    output: Vec<F>,
    output_b: F,
}
impl<F: Field> StatementData<F> {
    fn borrowed(&self) -> Statement<'_, F> {
        Statement {
            left_a: &self.mask,
            left_b: self.body,
            right_a: &self.mask,
            right_b: F::zero(),
            output_a: &self.output,
            output_b: self.output_b,
        }
    }
}

fn reference_transcript<F, EF, H, P>(
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<H::Output>,
    s: &Statement<'_, F>,
    proof: &Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>,
    trans: &mut Transcript<F>,
) -> Result<Report, Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    if proof.protocol_version != PROTOCOL_VERSION {
        return Err(error("unsupported canonical complete PBS protocol version"));
    }
    validate::<F, EF, H, P>(pp, setup)?;
    pp.coefficients
        .validate_values(&proof.final_accumulator)
        .map_err(convert)?;
    let cfg = &setup.config;
    let width = pp.coefficients.width();
    let d = cfg
        .decomposition::<F>()?
        .num_digits::<F>()
        .map_err(convert)?;
    let normalized = statement::<F, H, P>(pp.coefficients, s);
    let s = normalized.borrowed();
    let (plan, initial) = public_inputs(cfg, &s)?;

    bind::<F, EF, H, P>(
        trans,
        pp,
        setup,
        &normalized,
        &proof.coefficients,
        &proof.evaluations,
        &proof.decomposition_inputs,
        &proof.accumulators,
        &proof.final_accumulator,
    )?;
    if proof.ntt.len() != 2 * d + 1 || proof.decomposition.len() != 2 {
        return Err(error("child proof counts"));
    }
    let co = public(pp.coefficients, &proof.coefficients);
    let ev = public(pp.evaluations, &proof.evaluations);
    let input = public(pp.inputs, &proof.decomposition_inputs);
    let key = bk::canonical::public_oracles::<F, H, P>(pp.key, &setup.br).map_err(convert)?;
    let factors: Vec<_> = (0..2 * d)
        .flat_map(|i| [&ev[i], &key[i]])
        .chain(std::iter::once(&ev[2 * d]))
        .map(|s| CanonicalVerifierOracle {
            parameters: s.parameters,
            commitment: s.commitment,
        })
        .collect();
    let key_product_valid = relation::audit::verify::<F, H, P>(
        trans,
        &shape(pp.evaluations.num_vars(), width, 2 * d),
        &factors,
        &proof.hadamard,
    )
    .map_err(convert)?;
    let ntt_shape =
        ntt::Shape::new_canonical::<F, H, P>(pp.coefficients, cfg.n).map_err(convert)?;
    for i in 0..2 * d + 1 {
        ntt::verify_canonical::<F, H, P>(trans, &ntt_shape, &co[i], &ev[i], &proof.ntt[i])
            .map_err(convert)?;
    }
    for half in 0..2 {
        decomp::canonical::verify::<F, EF, H, P>(
            trans,
            &cfg.decomposition::<F>()?,
            &input[half],
            pp.borrows,
            pp.helper,
            &co[half * d..(half + 1) * d]
                .iter()
                .map(|s| CanonicalVerifierOracle {
                    parameters: s.parameters,
                    commitment: s.commitment,
                })
                .collect::<Vec<_>>(),
            &proof.decomposition[half],
        )
        .map_err(convert)?;
    }
    let ac: Vec<_> = proof
        .accumulators
        .iter()
        .zip(pp.accumulators)
        .map(|(commitment, parameters)| CanonicalVerifierOracle {
            parameters,
            commitment,
        })
        .collect();
    let sources = [
        &ac[0],
        &ac[1],
        &ac[2],
        &ac[3],
        &co[2 * d],
        &input[0],
        &input[1],
    ]
    .into_iter()
    .map(|s| CanonicalVerifierOracle {
        parameters: s.parameters,
        commitment: s.commitment,
    })
    .collect::<Vec<_>>();
    let linkage_valid = acc::audit::verify::<F, H, P>(
        trans,
        &acc::Shape::new(cfg.n, cfg.lwe).map_err(convert)?,
        &initial,
        &proof.final_accumulator,
        &sources,
        &proof.accumulator,
    )
    .map_err(convert)?;
    let monomial_valid = mono::canonical::audit::verify::<F, H, P>(
        trans,
        &plan,
        pp.monomial,
        &ac[..2]
            .iter()
            .map(|s| CanonicalVerifierOracle {
                parameters: s.parameters,
                commitment: s.commitment,
            })
            .collect::<Vec<_>>(),
        &proof.monomial,
    )
    .map_err(convert)?;
    let (switch_key_product_valid, extraction_valid) = final_stage::audit::verify::<F, EF, H, P>(
        trans,
        &pp.final_stage,
        &setup.ks,
        &proof.final_accumulator,
        s.output_a,
        s.output_b,
        &proof.key_switch,
    )
    .map_err(convert)?;
    Ok(Report {
        key_product: key_product_valid,
        switch_key_product: switch_key_product_valid,
        accumulator: linkage_valid,
        monomial: monomial_valid,
        extraction: extraction_valid,
    })
}

fn run<F, EF, P>(
    pp: &Parameters<'_, P>,
    setup: &canonical_setup::ProverSetup<F, Sha256, P>,
    attack: Attack,
    backend: &str,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha256>,
    P::SingleProof: serde::de::DeserializeOwned,
    P::BatchProof: serde::de::DeserializeOwned,
{
    let (s, proof, digest) = make::<F, EF, P>(pp, setup, attack, 1700 + attack as u64);
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (Proof<F, EF, [u8; 32], P::SingleProof, P::BatchProof>, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let expected = setup.verifier();
    let mut replay = Transcript::new_direct();
    let report =
        reference_transcript::<F, EF, Sha256, P>(pp, &expected, &s.borrowed(), &proof, &mut replay)
            .unwrap();
    assert_eq!(report.key_product, attack != Attack::KeyProduct);
    assert_eq!(
        report.switch_key_product,
        attack != Attack::SwitchKeyProduct
    );
    assert_eq!(report.accumulator, attack.accumulator_valid());
    assert_eq!(report.monomial, attack.monomial_valid());
    assert_eq!(report.extraction, attack.extraction_valid());
    assert_eq!(
        digest,
        replay.get_challenge(b"v10 fresh complete certificate after")
    );
    let result = verify::<F, EF, Sha256, P>(pp, &expected, &s.borrowed(), &proof);
    if attack == Attack::Control {
        result.unwrap();
    } else {
        let err = result.unwrap_err();
        let label = match attack {
            Attack::KeyProduct | Attack::SwitchKeyProduct => "packed ZeroCheck terminal identity",
            Attack::Rotation => "packed public monomial product",
            Attack::ExtractionA | Attack::ExtractionB => "packed ZeroCheck terminal identity",
            _ => "packed accumulator linkage",
        };
        assert!(err.0.contains(label), "{attack:?}: {err}");
    }
    println!(
        "HB_V10_FRESH_LINKAGE_CASE {{\"protocol_version\":10,\"prime\":{},\"backend\":\"{}\",\"attack\":\"{:?}\",\"reference_scope\":\"complete-strict-children-and-actual-root-openings\",\"reference_key_product_valid\":{},\"reference_switch_key_product_valid\":{},\"reference_linkage_valid\":{},\"reference_monomial_valid\":{},\"reference_extraction_valid\":{},\"production_accepted\":{},\"encrypted_profile\":false,\"original_size\":false}}",
        F::MODULUS_VALUE,
        backend,
        attack,
        report.key_product,
        report.switch_key_product,
        report.accumulator,
        report.monomial,
        report.extraction,
        attack == Attack::Control
    );
}
fn ordinary<F, EF>(width: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    use pcs::{matrix_weighted::Parameters as Pp, utils::code::BlockReedSolomonCode};
    let cfg = Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
    let dims = cfg.variables(width).unwrap();
    let codes: Vec<_> = dims
        .into_iter()
        .map(|n| Pp::<BlockReedSolomonCode<F>>::balanced_block_rs(n, width, 32, 2).unwrap())
        .collect();
    let pp = Parameters {
        coefficients: &codes[0],
        evaluations: &codes[0],
        key: &codes[0],
        inputs: &codes[0],
        borrows: &codes[0],
        helper: &codes[1],
        accumulators: [&codes[0]; 4],
        monomial: &codes[0],
        final_stage: final_stage::Parameters {
            coefficients: &codes[2],
            evaluations: &codes[2],
            key: &codes[2],
            input: &codes[2],
            borrows: &codes[2],
            helper: &codes[3],
        },
    };
    let br = vec![NTTRGSW::<F>::zero(32, Basis::new(8)); 21];
    let ks = vec![NTTGadgetRLWE::<F>::zero(32, Basis::new(5))];
    let setup = canonical_setup::preprocess::<F, Sha256, _, _>(
        &canonical_setup::Parameters {
            source: &codes[0],
            helper: &codes[1],
            final_source: &codes[2],
            final_helper: &codes[3],
        },
        cfg,
        &br,
        &ks,
        &mut StdRng::seed_from_u64(1600),
    )
    .unwrap();
    for attack in [
        Attack::Control,
        Attack::Initial,
        Attack::Final,
        Attack::Addition,
        Attack::Chain,
        Attack::DigitA,
        Attack::DigitB,
        Attack::Rotation,
        Attack::ExtractionA,
        Attack::ExtractionB,
    ] {
        run::<F, EF, _>(&pp, &setup, attack, "brakedown");
    }
    let mut br = br;
    let mut weight = F::one();
    for limb in br[0].c_m_mut().iter_mut() {
        limb.b_mut_slice().fill(weight);
        weight *= F::from(256usize);
    }
    let setup = canonical_setup::preprocess::<F, Sha256, _, _>(
        &canonical_setup::Parameters {
            source: &codes[0],
            helper: &codes[1],
            final_source: &codes[2],
            final_helper: &codes[3],
        },
        setup.verifier().config,
        &br,
        &ks,
        &mut StdRng::seed_from_u64(1601),
    )
    .unwrap();
    run::<F, EF, _>(&pp, &setup, Attack::KeyProduct, "brakedown");
    let mut weight = F::one();
    for limb in br[0].c_m_mut().iter_mut() {
        limb.b_mut_slice().fill(F::zero());
        limb.a_mut_slice().fill(weight);
        weight *= F::from(256usize);
    }
    let mut ks = ks;
    let mut weight = F::one();
    for limb in ks[0].iter_mut() {
        limb.b_mut_slice().fill(weight);
        weight *= F::from(32usize);
    }
    let setup = canonical_setup::preprocess::<F, Sha256, _, _>(
        &canonical_setup::Parameters {
            source: &codes[0],
            helper: &codes[1],
            final_source: &codes[2],
            final_helper: &codes[3],
        },
        setup.verifier().config,
        &br,
        &ks,
        &mut StdRng::seed_from_u64(1602),
    )
    .unwrap();
    run::<F, EF, _>(&pp, &setup, Attack::SwitchKeyProduct, "brakedown");
}
#[test]
fn ordinary_babybear_complete_linkage() {
    ordinary::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
}
#[test]
fn ordinary_goldilocks_complete_linkage() {
    ordinary::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}

fn masked<F, EF>(width: usize, attack: Attack)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    use pcs::matrix_weighted::masked_polyfrim::Parameters as Pp;
    let cfg = Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
    let dims = cfg.variables(width).unwrap();
    let make = |vars: usize, budget: usize| {
        (vars..24)
            .find_map(|physical| Pp::<F, EF>::new(vars, width, physical, 2, 1, budget).ok())
            .unwrap()
    };
    let cpp = make(dims[0], width + 2);
    let epp = make(dims[0], width + 1);
    let key = make(dims[0], 1);
    let inputs = make(dims[0], 2);
    let borrow = make(dims[0], 3);
    let helper = make(dims[1], 2);
    let monomial = make(dims[0], width + 1);
    let ac = [
        make(dims[0], width + 8),
        make(dims[0], width + 1),
        make(dims[0], 3),
        make(dims[0], 2),
    ];
    let fco = make(dims[2], width + 2);
    let fev = make(dims[2], width + 1);
    let fkey = make(dims[2], 1);
    let fin = make(dims[2], 2);
    let fborrow = make(dims[2], 3);
    let fhelper = make(dims[3], 2);
    let pp = Parameters {
        coefficients: &cpp,
        evaluations: &epp,
        key: &key,
        inputs: &inputs,
        borrows: &borrow,
        helper: &helper,
        accumulators: [&ac[0], &ac[1], &ac[2], &ac[3]],
        monomial: &monomial,
        final_stage: final_stage::Parameters {
            coefficients: &fco,
            evaluations: &fev,
            key: &fkey,
            input: &fin,
            borrows: &fborrow,
            helper: &fhelper,
        },
    };
    let mut br = vec![NTTRGSW::<F>::zero(32, Basis::new(8)); 21];
    if attack == Attack::KeyProduct {
        let mut weight = F::one();
        for limb in br[0].c_m_mut().iter_mut() {
            limb.b_mut_slice().fill(weight);
            weight *= F::from(256usize);
        }
    }
    let mut ks = vec![NTTGadgetRLWE::<F>::zero(32, Basis::new(5))];
    if attack == Attack::SwitchKeyProduct {
        let mut weight = F::one();
        for limb in br[0].c_m_mut().iter_mut() {
            limb.a_mut_slice().fill(weight);
            weight *= F::from(256usize);
        }
        let mut weight = F::one();
        for limb in ks[0].iter_mut() {
            limb.b_mut_slice().fill(weight);
            weight *= F::from(32usize);
        }
    }
    let setup = canonical_setup::preprocess::<F, Sha256, _, _>(
        &canonical_setup::Parameters {
            source: &key,
            helper: &helper,
            final_source: &fkey,
            final_helper: &fhelper,
        },
        cfg,
        &br,
        &ks,
        &mut StdRng::seed_from_u64(2100 + attack as u64),
    )
    .unwrap();
    run::<F, EF, _>(&pp, &setup, attack, "masked");
    assert!(
        setup
            .br_oracles(&key)
            .unwrap()
            .iter()
            .all(|s| s.state.spent().unwrap() == 1)
    );
    assert!(
        setup
            .ks_oracles(&fkey)
            .unwrap()
            .iter()
            .all(|s| s.state.spent().unwrap() == 1)
    );
}
macro_rules! masked_case {
    ($name:ident,$f:ty,$e:ty,$width:expr,$attack:ident) => {
        #[test]
        #[ignore = "manual full masked certificate audit; substantial CPU and memory"]
        fn $name() {
            masked::<$f, $e>($width, Attack::$attack);
        }
    };
}
masked_case!(
    masked_babybear_control,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    Control
);
masked_case!(
    masked_babybear_initial,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    Initial
);
masked_case!(
    masked_babybear_final,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    Final
);
masked_case!(
    masked_babybear_addition,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    Addition
);
masked_case!(
    masked_babybear_chain,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    Chain
);
masked_case!(
    masked_babybear_digit_a,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    DigitA
);
masked_case!(
    masked_babybear_digit_b,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    DigitB
);
masked_case!(
    masked_goldilocks_control,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    Control
);
masked_case!(
    masked_goldilocks_initial,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    Initial
);
masked_case!(
    masked_goldilocks_final,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    Final
);
masked_case!(
    masked_goldilocks_addition,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    Addition
);
masked_case!(
    masked_goldilocks_chain,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    Chain
);
masked_case!(
    masked_goldilocks_digit_a,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    DigitA
);
masked_case!(
    masked_goldilocks_digit_b,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    DigitB
);

masked_case!(
    masked_babybear_rotation,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    Rotation
);
masked_case!(
    masked_babybear_extraction_a,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    ExtractionA
);
masked_case!(
    masked_babybear_extraction_b,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    ExtractionB
);
masked_case!(
    masked_goldilocks_rotation,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    Rotation
);
masked_case!(
    masked_goldilocks_extraction_a,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    ExtractionA
);
masked_case!(
    masked_goldilocks_extraction_b,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    ExtractionB
);

masked_case!(
    masked_babybear_key_product,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    KeyProduct
);
masked_case!(
    masked_goldilocks_key_product,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    KeyProduct
);

masked_case!(
    masked_babybear_switch_key_product,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    SwitchKeyProduct
);
masked_case!(
    masked_goldilocks_switch_key_product,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    SwitchKeyProduct
);
