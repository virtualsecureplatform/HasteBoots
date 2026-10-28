//! Fresh complete algebraic certificates, including every actual-root opening.
//! Zero evaluation keys isolate linkage; these are not encrypted native profiles.
use super::*;
mod mode;
use algebra::Basis;
use mode::AuditStages;
use rand::{SeedableRng, rngs::StdRng};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
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
    CanonicalA,
    CanonicalB,
    SwitchCanonical,
    LookupA,
    LookupB,
    SwitchLookup,
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
                | Self::CanonicalA
                | Self::CanonicalB
                | Self::SwitchCanonical
                | Self::LookupA
                | Self::LookupB
                | Self::SwitchLookup
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
    decomposition: [[bool; 3]; 2],
    switch_decomposition: [bool; 3],
    lookups: [bool; 2],
    switch_lookup: bool,
    key_product: bool,
    switch_key_product: bool,
    accumulator: bool,
    monomial: bool,
    extraction: bool,
}
fn make<F, EF, P, D>(
    pp: &Parameters<'_, P>,
    setup: &canonical_setup::ProverSetup<F, Sha256, P>,
    attack: Attack,
    seed: u64,
) -> (
    StatementData<F>,
    BackendProof<F, [u8; 32], P::SingleProof, P::BatchProof, D::Decomposition, D::KeySwitch>,
    (F, [u8; 32]),
)
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    P: CanonicalPcs<F, Sha256>,
    D: AuditStages<F, EF, Sha256, P>,
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
        Attack::CanonicalA | Attack::CanonicalB => {
            let half = usize::from(attack == Attack::CanonicalB);
            let mut integer: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
            for limb in 0..d {
                co[half * d + limb].fill(F::from((integer & 255) as usize));
                integer >>= 8;
            }
            assert_eq!(integer, 0);
        }
        Attack::Rotation | Attack::KeyProduct | Attack::SwitchKeyProduct => {
            let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
            s.mask[0] = F::from((p / (4 * cfg.n as u128)) as usize);
        }
        Attack::Control
        | Attack::ExtractionA
        | Attack::ExtractionB
        | Attack::SwitchCanonical
        | Attack::LookupA
        | Attack::LookupB
        | Attack::SwitchLookup => {}
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
    bind_inner::<F, EF, Sha256, P, D>(
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
            D::audit_decompose(
                &mut trans,
                &cfg.decomposition::<F>().unwrap(),
                &input[h],
                pp.borrows,
                pp.helper,
                &co[h * d..(h + 1) * d].iter().collect::<Vec<_>>(),
                attack
                    == if h == 0 {
                        Attack::LookupA
                    } else {
                        Attack::LookupB
                    },
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
    let mut coefficients = final_stage::audit::zero_key_coefficients::<F, Sha256, P>(
        &pp.final_stage,
        &expected.ks,
        &final_acc,
    )
    .unwrap();
    if attack == Attack::SwitchCanonical {
        let mut integer: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
        let count = coefficients.len() - 1;
        for word in coefficients.iter_mut().take(count) {
            *word = PackedTable::new(
                pp.final_stage.coefficients.num_vars(),
                width,
                vec![F::from((integer & 31) as usize); 2 * cfg.n],
            )
            .unwrap();
            integer >>= 5;
        }
        assert_eq!(integer, 0);
    }
    let key_switch = D::audit_key_switch(
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
        attack == Attack::SwitchLookup,
        &mut rng,
    )
    .unwrap();
    let proof = BackendProof {
        protocol_version: D::VERSION,
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
    let digest = trans.get_challenge(b"fresh complete canonical certificate after");
    let mut transcript_bytes = [0u8; 32];
    trans.get_challenge_bytes(
        b"fresh complete canonical certificate bytes after",
        &mut transcript_bytes,
    );
    assert_eq!(rows, 32);
    (s, proof, (digest, transcript_bytes))
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

fn reference_transcript<F, EF, H, P, D>(
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<H::Output>,
    s: &Statement<'_, F>,
    proof: &BackendProof<
        F,
        H::Output,
        P::SingleProof,
        P::BatchProof,
        D::Decomposition,
        D::KeySwitch,
    >,
    trans: &mut Transcript<F>,
) -> Result<Report, Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    D: AuditStages<F, EF, H, P>,
{
    if proof.protocol_version != D::VERSION {
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

    bind_inner::<F, EF, H, P, D>(
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
    let mut decomposition_valid = [[true; 3]; 2];
    let mut lookup_valid = [true; 2];
    for half in 0..2 {
        let (linear, lookup) = D::audit_verify_decomposition(
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
        )?;
        decomposition_valid[half] = linear;
        lookup_valid[half] = lookup;
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
    let (
        switch_key_product_valid,
        extraction_valid,
        switch_decomposition_valid,
        switch_lookup_valid,
    ) = D::audit_verify_key_switch(
        trans,
        &pp.final_stage,
        &setup.ks,
        &proof.final_accumulator,
        s.output_a,
        s.output_b,
        &proof.key_switch,
    )?;
    Ok(Report {
        decomposition: decomposition_valid,
        switch_decomposition: switch_decomposition_valid,
        lookups: lookup_valid,
        switch_lookup: switch_lookup_valid,
        key_product: key_product_valid,
        switch_key_product: switch_key_product_valid,
        accumulator: linkage_valid,
        monomial: monomial_valid,
        extraction: extraction_valid,
    })
}

fn run<F, EF, P, D>(
    pp: &Parameters<'_, P>,
    setup: &canonical_setup::ProverSetup<F, Sha256, P>,
    attack: Attack,
    backend: &str,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha256>,
    D: AuditStages<F, EF, Sha256, P>,
    P::SingleProof: serde::de::DeserializeOwned,
    P::BatchProof: serde::de::DeserializeOwned,
    D::Decomposition: Serialize + DeserializeOwned,
    D::KeySwitch: Serialize + DeserializeOwned,
{
    let (s, proof, (digest, transcript_bytes)) =
        make::<F, EF, P, D>(pp, setup, attack, 1700 + attack as u64);
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (
        BackendProof<F, [u8; 32], P::SingleProof, P::BatchProof, D::Decomposition, D::KeySwitch>,
        usize,
    ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let expected = setup.verifier();
    let mut replay = Transcript::new_direct();
    let report = reference_transcript::<F, EF, Sha256, P, D>(
        pp,
        &expected,
        &s.borrowed(),
        &proof,
        &mut replay,
    )
    .unwrap();
    assert_eq!(
        report.decomposition[0],
        [true, true, attack != Attack::CanonicalA]
    );
    assert_eq!(
        report.decomposition[1],
        [true, true, attack != Attack::CanonicalB]
    );
    assert_eq!(
        report.switch_decomposition,
        [true, true, attack != Attack::SwitchCanonical]
    );
    assert_eq!(
        report.lookups,
        [attack != Attack::LookupA, attack != Attack::LookupB]
    );
    assert_eq!(report.switch_lookup, attack != Attack::SwitchLookup);
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
        replay.get_challenge(b"fresh complete canonical certificate after")
    );
    let mut replay_bytes = [0u8; 32];
    replay.get_challenge_bytes(
        b"fresh complete canonical certificate bytes after",
        &mut replay_bytes,
    );
    assert_eq!(transcript_bytes, replay_bytes);
    let result = verify_inner::<F, EF, Sha256, P, D>(pp, &expected, &s.borrowed(), &proof);
    let production_error = if attack == Attack::Control {
        result.unwrap();
        None
    } else {
        let err = result.unwrap_err();
        let label = match attack {
            Attack::CanonicalA | Attack::CanonicalB | Attack::SwitchCanonical => {
                "false canonical linear identity"
            }
            Attack::LookupA | Attack::LookupB | Attack::SwitchLookup => {
                "terminal reciprocal identity"
            }
            Attack::KeyProduct | Attack::SwitchKeyProduct => "packed ZeroCheck terminal identity",
            Attack::Rotation => "packed public monomial product",
            Attack::ExtractionA | Attack::ExtractionB => "packed ZeroCheck terminal identity",
            _ => "packed accumulator linkage",
        };
        assert!(err.0.contains(label), "{attack:?}: {err}");
        Some(err.0)
    };
    println!(
        "{} {{\"protocol_version\":{},\"prime\":{},\"backend\":\"{}\",\"attack\":\"{:?}\",\"reference_scope\":\"complete-strict-children-and-actual-root-openings\",\"reference_decomposition_valid\":{:?},\"reference_switch_decomposition_valid\":{:?},\"reference_lookup_valid\":{:?},\"reference_switch_lookup_valid\":{},\"reference_key_product_valid\":{},\"reference_switch_key_product_valid\":{},\"reference_linkage_valid\":{},\"reference_monomial_valid\":{},\"reference_extraction_valid\":{},\"production_accepted\":{},\"proof_bytes\":{},\"proof_sha256\":\"{:x}\",\"transcript_bytes\":\"{}\",\"production_error\":{},\"encrypted_profile\":false,\"original_size\":false}}",
        if D::VERSION == 10 {
            "HB_V10_FRESH_LINKAGE_CASE"
        } else {
            "HB_V11_FRESH_BINDING_CASE"
        },
        D::VERSION,
        F::MODULUS_VALUE,
        backend,
        attack,
        report.decomposition,
        report.switch_decomposition,
        report.lookups,
        report.switch_lookup,
        report.key_product,
        report.switch_key_product,
        report.accumulator,
        report.monomial,
        report.extraction,
        attack == Attack::Control,
        bytes.len(),
        Sha256::digest(&bytes),
        transcript_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        production_error
            .map(|e| format!("{e:?}"))
            .unwrap_or_else(|| "null".to_owned())
    );
}
fn ordinary<F, EF, D>(width: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    D: AuditStages<
            F,
            EF,
            Sha256,
            pcs::matrix_weighted::Parameters<pcs::utils::code::BlockReedSolomonCode<F>>,
        >,
    D::Decomposition: Serialize + DeserializeOwned,
    D::KeySwitch: Serialize + DeserializeOwned,
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
        Attack::CanonicalA,
        Attack::CanonicalB,
        Attack::SwitchCanonical,
        Attack::LookupA,
        Attack::LookupB,
        Attack::SwitchLookup,
    ] {
        run::<F, EF, _, D>(&pp, &setup, attack, "brakedown");
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
    run::<F, EF, _, D>(&pp, &setup, Attack::KeyProduct, "brakedown");
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
    run::<F, EF, _, D>(&pp, &setup, Attack::SwitchKeyProduct, "brakedown");
}
#[test]
fn ordinary_babybear_complete_linkage() {
    ordinary::<algebra::BabyBear, algebra::BabyBearExtension6, stages::PerLimb>(8);
}
#[test]
fn ordinary_goldilocks_complete_linkage() {
    ordinary::<algebra::Goldilocks, algebra::GoldilocksExtension3, stages::PerLimb>(4);
}

fn masked_backend<F, EF, P, D>(
    width: usize,
    attack: Attack,
    backend: &str,
    make: impl Fn(usize, usize) -> P,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha256, State = pcs::matrix_weighted::masked_polyfrim::State<F, EF, Sha256>>,
    P::SingleProof: DeserializeOwned,
    P::BatchProof: DeserializeOwned,
    D: AuditStages<F, EF, Sha256, P>,
    D::Decomposition: Serialize + DeserializeOwned,
    D::KeySwitch: Serialize + DeserializeOwned,
{
    let cfg = Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
    let dims = cfg.variables(width).unwrap();
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
    run::<F, EF, _, D>(&pp, &setup, attack, backend);
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
fn masked<F, EF, D>(width: usize, attack: Attack)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    D: AuditStages<F, EF, Sha256, pcs::matrix_weighted::masked_polyfrim::Parameters<F, EF>>,
    D::Decomposition: Serialize + DeserializeOwned,
    D::KeySwitch: Serialize + DeserializeOwned,
{
    use pcs::matrix_weighted::masked_polyfrim::Parameters as Pp;
    masked_backend::<F, EF, Pp<F, EF>, D>(width, attack, "masked", |vars, budget| {
        (vars..24)
            .find_map(|physical| Pp::<F, EF>::new(vars, width, physical, 2, 1, budget).ok())
            .unwrap()
    });
}
fn joint_masked<F, EF, D>(width: usize, attack: Attack)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    D: AuditStages<F, EF, Sha256, pcs::matrix_weighted::masked_polyfrim::joint::Parameters<F, EF>>,
    D::Decomposition: Serialize + DeserializeOwned,
    D::KeySwitch: Serialize + DeserializeOwned,
{
    use pcs::matrix_weighted::masked_polyfrim::joint::Parameters as Pp;
    masked_backend::<F, EF, Pp<F, EF>, D>(width, attack, "masked-joint", |vars, budget| {
        (vars..24)
            .find_map(|physical| Pp::<F, EF>::new(vars, width, physical, 2, 1, budget).ok())
            .unwrap()
    });
}
macro_rules! masked_case {
    ($name:ident,$f:ty,$e:ty,$width:expr,$attack:ident) => {
        masked_case!($name, $f, $e, $width, $attack, stages::PerLimb);
    };
    ($name:ident,$f:ty,$e:ty,$width:expr,$attack:ident,$mode:ty) => {
        #[test]
        #[ignore = "manual full masked certificate audit; substantial CPU and memory"]
        fn $name() {
            masked::<$f, $e, $mode>($width, Attack::$attack);
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

masked_case!(
    masked_babybear_canonical_a,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    CanonicalA
);
masked_case!(
    masked_babybear_canonical_b,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    CanonicalB
);
masked_case!(
    masked_babybear_switch_canonical,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    SwitchCanonical
);
masked_case!(
    masked_goldilocks_canonical_a,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    CanonicalA
);
masked_case!(
    masked_goldilocks_canonical_b,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    CanonicalB
);
masked_case!(
    masked_goldilocks_switch_canonical,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    SwitchCanonical
);

#[test]
fn v11_ordinary_babybear_complete_binding() {
    ordinary::<algebra::BabyBear, algebra::BabyBearExtension6, stages::Shared>(8);
}
#[test]
fn v11_ordinary_goldilocks_complete_binding() {
    ordinary::<algebra::Goldilocks, algebra::GoldilocksExtension3, stages::Shared>(4);
}
masked_case!(
    v11_masked_babybear_control,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    Control,
    stages::Shared
);
masked_case!(
    v11_masked_babybear_initial,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    Initial,
    stages::Shared
);
masked_case!(
    v11_masked_babybear_final,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    Final,
    stages::Shared
);
masked_case!(
    v11_masked_babybear_addition,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    Addition,
    stages::Shared
);
masked_case!(
    v11_masked_babybear_chain,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    Chain,
    stages::Shared
);
masked_case!(
    v11_masked_babybear_digit_a,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    DigitA,
    stages::Shared
);
masked_case!(
    v11_masked_babybear_digit_b,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    DigitB,
    stages::Shared
);
masked_case!(
    v11_masked_goldilocks_control,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    Control,
    stages::Shared
);
masked_case!(
    v11_masked_goldilocks_initial,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    Initial,
    stages::Shared
);
masked_case!(
    v11_masked_goldilocks_final,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    Final,
    stages::Shared
);
masked_case!(
    v11_masked_goldilocks_addition,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    Addition,
    stages::Shared
);
masked_case!(
    v11_masked_goldilocks_chain,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    Chain,
    stages::Shared
);
masked_case!(
    v11_masked_goldilocks_digit_a,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    DigitA,
    stages::Shared
);
masked_case!(
    v11_masked_goldilocks_digit_b,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    DigitB,
    stages::Shared
);

masked_case!(
    v11_masked_babybear_rotation,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    Rotation,
    stages::Shared
);
masked_case!(
    v11_masked_babybear_extraction_a,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    ExtractionA,
    stages::Shared
);
masked_case!(
    v11_masked_babybear_extraction_b,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    ExtractionB,
    stages::Shared
);
masked_case!(
    v11_masked_goldilocks_rotation,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    Rotation,
    stages::Shared
);
masked_case!(
    v11_masked_goldilocks_extraction_a,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    ExtractionA,
    stages::Shared
);
masked_case!(
    v11_masked_goldilocks_extraction_b,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    ExtractionB,
    stages::Shared
);

masked_case!(
    v11_masked_babybear_key_product,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    KeyProduct,
    stages::Shared
);
masked_case!(
    v11_masked_goldilocks_key_product,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    KeyProduct,
    stages::Shared
);

masked_case!(
    v11_masked_babybear_switch_key_product,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    SwitchKeyProduct,
    stages::Shared
);
masked_case!(
    v11_masked_goldilocks_switch_key_product,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    SwitchKeyProduct,
    stages::Shared
);

masked_case!(
    v11_masked_babybear_canonical_a,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    CanonicalA,
    stages::Shared
);
masked_case!(
    v11_masked_babybear_canonical_b,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    CanonicalB,
    stages::Shared
);
masked_case!(
    v11_masked_babybear_switch_canonical,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    SwitchCanonical,
    stages::Shared
);
masked_case!(
    v11_masked_goldilocks_canonical_a,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    CanonicalA,
    stages::Shared
);
masked_case!(
    v11_masked_goldilocks_canonical_b,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    CanonicalB,
    stages::Shared
);
masked_case!(
    v11_masked_goldilocks_switch_canonical,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    SwitchCanonical,
    stages::Shared
);

// The complete fixture and strict reference replay are shared with the old
// backend. Only this trusted test parameter type chooses joint source packets.
macro_rules! joint_backend_cases {
    ($module:ident, $f:ty, $e:ty, $width:expr, $mode:ty) => {
        mod $module {
            use super::*;
            #[test]
            #[ignore = "manual full joint masked certificate audit; substantial CPU and memory"]
            fn control() {
                joint_masked::<$f, $e, $mode>($width, Attack::Control);
            }
            #[test]
            #[ignore = "manual full joint masked certificate audit; substantial CPU and memory"]
            fn initial() {
                joint_masked::<$f, $e, $mode>($width, Attack::Initial);
            }
            #[test]
            #[ignore = "manual full joint masked certificate audit; substantial CPU and memory"]
            fn final_endpoint() {
                joint_masked::<$f, $e, $mode>($width, Attack::Final);
            }
            #[test]
            #[ignore = "manual full joint masked certificate audit; substantial CPU and memory"]
            fn addition() {
                joint_masked::<$f, $e, $mode>($width, Attack::Addition);
            }
            #[test]
            #[ignore = "manual full joint masked certificate audit; substantial CPU and memory"]
            fn chain() {
                joint_masked::<$f, $e, $mode>($width, Attack::Chain);
            }
            #[test]
            #[ignore = "manual full joint masked certificate audit; substantial CPU and memory"]
            fn digit_a() {
                joint_masked::<$f, $e, $mode>($width, Attack::DigitA);
            }
            #[test]
            #[ignore = "manual full joint masked certificate audit; substantial CPU and memory"]
            fn digit_b() {
                joint_masked::<$f, $e, $mode>($width, Attack::DigitB);
            }
            #[test]
            #[ignore = "manual full joint masked certificate audit; substantial CPU and memory"]
            fn rotation() {
                joint_masked::<$f, $e, $mode>($width, Attack::Rotation);
            }
            #[test]
            #[ignore = "manual full joint masked certificate audit; substantial CPU and memory"]
            fn extraction_a() {
                joint_masked::<$f, $e, $mode>($width, Attack::ExtractionA);
            }
            #[test]
            #[ignore = "manual full joint masked certificate audit; substantial CPU and memory"]
            fn extraction_b() {
                joint_masked::<$f, $e, $mode>($width, Attack::ExtractionB);
            }
            #[test]
            #[ignore = "manual full joint masked certificate audit; substantial CPU and memory"]
            fn key_product() {
                joint_masked::<$f, $e, $mode>($width, Attack::KeyProduct);
            }
            #[test]
            #[ignore = "manual full joint masked certificate audit; substantial CPU and memory"]
            fn switch_key_product() {
                joint_masked::<$f, $e, $mode>($width, Attack::SwitchKeyProduct);
            }
            #[test]
            #[ignore = "manual full joint masked certificate audit; substantial CPU and memory"]
            fn canonical_a() {
                joint_masked::<$f, $e, $mode>($width, Attack::CanonicalA);
            }
            #[test]
            #[ignore = "manual full joint masked certificate audit; substantial CPU and memory"]
            fn canonical_b() {
                joint_masked::<$f, $e, $mode>($width, Attack::CanonicalB);
            }
            #[test]
            #[ignore = "manual full joint masked certificate audit; substantial CPU and memory"]
            fn switch_canonical() {
                joint_masked::<$f, $e, $mode>($width, Attack::SwitchCanonical);
            }
            #[test]
            #[ignore = "manual fresh complete false lookup; substantial CPU and memory"]
            fn false_lookup_a() {
                joint_masked::<$f, $e, $mode>($width, Attack::LookupA);
            }
            #[test]
            #[ignore = "manual fresh complete false lookup; substantial CPU and memory"]
            fn false_lookup_b() {
                joint_masked::<$f, $e, $mode>($width, Attack::LookupB);
            }
            #[test]
            #[ignore = "manual fresh complete false lookup; substantial CPU and memory"]
            fn false_lookup_switch() {
                joint_masked::<$f, $e, $mode>($width, Attack::SwitchLookup);
            }
        }
    };
}
joint_backend_cases!(
    v10_joint_babybear,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    stages::PerLimb
);
joint_backend_cases!(
    v10_joint_goldilocks,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    stages::PerLimb
);
joint_backend_cases!(
    v11_joint_babybear,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    stages::Shared
);
joint_backend_cases!(
    v11_joint_goldilocks,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    stages::Shared
);

masked_case!(
    v10_masked_babybear_false_lookup_a,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    LookupA,
    stages::PerLimb
);

masked_case!(
    v10_masked_babybear_false_lookup_b,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    LookupB,
    stages::PerLimb
);

masked_case!(
    v10_masked_babybear_false_lookup_switch,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    SwitchLookup,
    stages::PerLimb
);

masked_case!(
    v10_masked_goldilocks_false_lookup_a,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    LookupA,
    stages::PerLimb
);

masked_case!(
    v10_masked_goldilocks_false_lookup_b,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    LookupB,
    stages::PerLimb
);

masked_case!(
    v10_masked_goldilocks_false_lookup_switch,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    SwitchLookup,
    stages::PerLimb
);

masked_case!(
    v11_masked_babybear_false_lookup_a,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    LookupA,
    stages::Shared
);

masked_case!(
    v11_masked_babybear_false_lookup_b,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    LookupB,
    stages::Shared
);

masked_case!(
    v11_masked_babybear_false_lookup_switch,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    SwitchLookup,
    stages::Shared
);

masked_case!(
    v11_masked_goldilocks_false_lookup_a,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    LookupA,
    stages::Shared
);

masked_case!(
    v11_masked_goldilocks_false_lookup_b,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    LookupB,
    stages::Shared
);

masked_case!(
    v11_masked_goldilocks_false_lookup_switch,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    SwitchLookup,
    stages::Shared
);
