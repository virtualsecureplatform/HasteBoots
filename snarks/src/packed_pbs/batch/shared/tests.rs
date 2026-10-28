//! Fresh complete certificates with foreign comparison helpers and genuine
//! openings of the declared canonical sources. No honest-proof replay.
use super::*;
use algebra::Basis;
use pcs::utils::code::BlockReedSolomonCode;
use serde::de::DeserializeOwned;
use sha2::Sha256;

// A small exact relation with zero evaluation keys, identity rotations and a
// constant accumulator. These are algebraic adversarial fixtures, not secure
// encryption-key profiles. All public PBS equations are still checked.
fn member<F: NTTField + Serialize>(
    pp: &Parameters<'_, BlockReedSolomonCode<F>>,
    setup: &ProverSetup<F, Sha256>,
    statement: &Statement<'_, F>,
) -> (MemberProof<F, [u8; 32]>, EvaluationWitness<F, Sha256>) {
    let cfg = &setup.verifier.config;
    let d = cfg.decomposition::<F>().unwrap().num_digits::<F>().unwrap();
    let (plan, initial) = public_inputs(cfg, statement).unwrap();
    assert!(plan.rotations().iter().all(|&r| r == 0));
    let zero = PackedTable::new(
        pp.source.num_vars(),
        pp.source.width(),
        vec![F::zero(); (1 << pp.source.num_vars()) * pp.source.width()],
    )
    .unwrap();
    let mut acc = vec![F::zero(); zero.values().len()];
    let half = acc.len() / 2;
    for row in 0..cfg.lwe {
        acc[row * cfg.n..(row + 1) * cfg.n].copy_from_slice(&initial[..cfg.n]);
        acc[half + row * cfg.n..half + (row + 1) * cfg.n].copy_from_slice(&initial[cfg.n..]);
    }
    let acc = PackedTable::new(pp.source.num_vars(), pp.source.width(), acc).unwrap();
    let coefficient_tables = vec![zero.clone(); 2 * d + 1];
    let evaluation_tables = coefficient_tables.clone();
    let input_tables = vec![zero.clone(); 2];
    let acc_tables = vec![acc.clone(), acc.clone(), zero.clone(), acc];
    let (coefficients, co_states) = commit::<F, Sha256, _>(pp.source, &coefficient_tables).unwrap();
    let (evaluations, ev_states) = commit::<F, Sha256, _>(pp.source, &evaluation_tables).unwrap();
    let (decomposition_inputs, in_states) =
        commit::<F, Sha256, _>(pp.source, &input_tables).unwrap();
    let (accumulators, ac_states) = commit::<F, Sha256, _>(pp.source, &acc_tables).unwrap();
    let co = oracles(pp.source, &coefficient_tables, &coefficients, &co_states);
    let ev = oracles(pp.source, &evaluation_tables, &evaluations, &ev_states);
    let input = oracles(pp.source, &input_tables, &decomposition_inputs, &in_states);
    let ac = oracles(pp.source, &acc_tables, &accumulators, &ac_states);
    let mut trans = Transcript::new_direct();
    crate::packed_pbs::bind::<F, Sha256, _>(
        &mut trans,
        COMPARISON_BATCH_PROTOCOL_VERSION,
        pp,
        &setup.verifier,
        statement,
        &coefficients,
        &evaluations,
        &decomposition_inputs,
        &accumulators,
        &initial,
    )
    .unwrap();
    trans.append_message(b"packed PBS joint batch Hadamard obligation", &());
    let shape = ntt::Shape::new::<F, _>(pp.source, cfg.n).unwrap();
    let ntt = co
        .iter()
        .zip(&ev)
        .map(|(c, e)| ntt::prove::<F, Sha256, _>(&mut trans, &shape, c, e).unwrap())
        .collect();
    let mut decomposition = Vec::new();
    let mut borrows = Vec::new();
    for h in 0..2 {
        let mut retained = None;
        decomposition.push(
            decomp::prove_retained::<F, Sha256, _, decomp::batch::Batched>(
                &mut trans,
                &cfg.decomposition::<F>().unwrap(),
                &input[h],
                Some(pp.helper),
                &co[h * d..(h + 1) * d].iter().collect::<Vec<_>>(),
                &mut crate::packed_lane_lookup::ProverStatistics::default(),
                Some(&mut retained),
            )
            .unwrap(),
        );
        borrows.push(retained.unwrap());
    }
    let accumulator = acc::prove::<F, Sha256, _>(
        &mut trans,
        &acc::Shape::new(cfg.n, cfg.lwe).unwrap(),
        &initial,
        &initial,
        &[
            &ac[0],
            &ac[1],
            &ac[2],
            &ac[3],
            &co[2 * d],
            &input[0],
            &input[1],
        ],
    )
    .unwrap();
    let monomial = mono::prove::<F, Sha256, _>(&mut trans, &plan, &[&ac[0], &ac[1]]).unwrap();
    let k = setup
        .verifier
        .ks
        .config()
        .decomposition::<F>()
        .unwrap()
        .num_digits::<F>()
        .unwrap();
    let z = PackedTable::new(
        pp.final_source.num_vars(),
        pp.final_source.width(),
        vec![F::zero(); 2 * cfg.n],
    )
    .unwrap();
    let mut retained = None;
    let key_switch = ks::prove_retained::<F, Sha256, _, decomp::batch::Batched>(
        &mut trans,
        pp.final_source,
        pp.final_helper,
        &setup.ks,
        &initial,
        statement.output_a,
        statement.output_b,
        &vec![z; k + 1],
        Some(&mut retained),
    )
    .unwrap();
    (
        MemberProof {
            protocol_version: COMPARISON_BATCH_PROTOCOL_VERSION,
            coefficients,
            evaluations,
            decomposition_inputs,
            accumulators,
            final_accumulator: initial,
            hadamard: (),
            ntt,
            decomposition,
            accumulator,
            monomial,
            key_switch,
        },
        EvaluationWitness {
            tables: Vec::new(),
            states: ev_states,
            coefficients: co_states,
            borrows,
            key_switch: retained,
        },
    )
}

fn foreign_one<F: NTTField>(
    config: &decomp::Config,
    pp: &PcsParameters<BlockReedSolomonCode<F>>,
) -> Vec<PackedTable<F>> {
    let d = config.num_digits::<F>().unwrap();
    let radix = config.radix().unwrap() as u128;
    let mut modulus = F::MODULUS_VALUE.to_string().parse::<u128>().unwrap() - 1;
    let mut b = 0usize;
    let mut digits = Vec::new();
    let mut borrows = vec![0];
    for i in 0..d {
        let digit = usize::from(i == 0);
        b = usize::from(digit + b > (modulus % radix) as usize);
        modulus /= radix;
        digits.push(digit);
        borrows.push(b);
    }
    assert_eq!(b, 0);
    digits
        .into_iter()
        .chain(borrows)
        .map(|v| {
            PackedTable::new(
                pp.num_vars(),
                pp.width(),
                vec![F::from(v); (1 << pp.num_vars()) * pp.width()],
            )
            .unwrap()
        })
        .collect()
}

fn audit<F, EF>(width: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    type H = Sha256;
    F::init_ntt_table(5).unwrap();
    let cfg = Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
    let codes = cfg.variables(width).unwrap().map(|n| {
        PcsParameters::<BlockReedSolomonCode<F>>::balanced_block_rs(n, width, 32, 2).unwrap()
    });
    let pp = Parameters {
        source: &codes[0],
        helper: &codes[1],
        final_source: &codes[2],
        final_helper: &codes[3],
    };
    let br = vec![lattice::NTTRGSW::<F>::zero(32, Basis::new(8)); 21];
    let ks = vec![lattice::NTTGadgetRLWE::<F>::zero(32, Basis::new(5))];
    let setup = preprocess::<F, H, _>(&pp, cfg, &br, &ks).unwrap();
    let mask = vec![F::zero(); 21];
    let lut = mono::nand_lut::<F>(32, 1).unwrap();
    let statements: Vec<_> = (0..2)
        .map(|i| Statement {
            left_a: &mask,
            left_b: F::from(i),
            right_a: &mask,
            right_b: F::zero(),
            output_a: &mask,
            output_b: lut[0] + lut[0],
        })
        .collect();
    for attack in [
        None,
        Some((false, 0usize)),
        Some((false, 1)),
        Some((true, 0)),
        Some((true, 1)),
    ] {
        // Reconstruct every member and every outer child for this certificate.
        let (members, owners): (Vec<_>, Vec<_>) =
            statements.iter().map(|s| member(&pp, &setup, s)).unzip();
        let mut prover = Transcript::new_direct();
        let mut reference = Transcript::new_direct();
        let roots =
            bind::<F, EF, H, _>(&mut prover, &pp, &setup.verifier, &statements, &members).unwrap();
        bind::<F, EF, H, _>(&mut reference, &pp, &setup.verifier, &statements, &members).unwrap();
        for (s, m) in statements.iter().zip(&members) {
            verify_impl::<F, H, _, decomp::batch::Batched, hadamard::Batched>(
                &pp,
                &setup.verifier,
                s,
                m,
            )
            .unwrap();
        }
        let key = setup.br.oracles(pp.source).unwrap();
        let d = key.len();
        let mut factors = Vec::new();
        let mut states = Vec::new();
        for o in &owners {
            let mut f = Vec::new();
            let mut s = Vec::new();
            for i in 0..d {
                f.push(o.states[i].table());
                s.push(&o.states[i]);
                f.push(key[i].table);
                s.push(key[i].state);
            }
            f.push(o.states[d].table());
            s.push(&o.states[d]);
            factors.push(f);
            states.push(s);
        }
        let shapes = vec![hadamard_shape(pp.source, d); members.len()];
        let hadamard = relations::prove_borrowed::<F, EF, H, _>(
            &mut prover,
            &shapes,
            pp.source,
            &factors.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            &roots,
            &states,
        )
        .unwrap();
        relations::verify::<F, EF, H, _>(&mut reference, &shapes, pp.source, &roots, &hadamard)
            .unwrap();
        let mut blind_rotation = Vec::new();
        let mut key_switch = Vec::new();
        for final_stage in [false, true] {
            let config = if final_stage {
                setup.verifier.ks.config().decomposition::<F>().unwrap()
            } else {
                setup.verifier.config.decomposition::<F>().unwrap()
            };
            let n = config.num_digits::<F>().unwrap();
            let count = if final_stage { 2 } else { 4 };
            let source = if final_stage {
                pp.final_source
            } else {
                pp.source
            };
            let helper = if final_stage {
                pp.final_helper
            } else {
                pp.helper
            };
            let mut registry = Vec::new();
            for i in 0..count {
                let (co, bo, cr, br, offset) = if final_stage {
                    let o = owners[i].key_switch.as_ref().unwrap();
                    (
                        &o.coefficients,
                        &o.borrows,
                        &members[i].key_switch.coefficients,
                        &members[i].key_switch.decomposition.borrow_commitments,
                        0,
                    )
                } else {
                    let (m, h) = (i / 2, i % 2);
                    (
                        &owners[m].coefficients,
                        &owners[m].borrows[h],
                        &members[m].coefficients,
                        &members[m].decomposition[h].borrow_commitments,
                        h * n,
                    )
                };
                registry.extend(
                    co[offset..offset + n]
                        .iter()
                        .zip(&cr[offset..offset + n])
                        .chain(bo.iter().zip(br))
                        .map(|(state, commitment)| ProverOracle {
                            parameters: source,
                            commitment,
                            state,
                            table: state.table(),
                        }),
                );
            }
            let requests = decomp::batch::requests::<F>(&vec![config.clone(); count]).unwrap();
            group(&mut prover, final_stage, 0, count);
            group(&mut reference, final_stage, 0, count);
            let one = foreign_one(&config, source);
            let mut witness: Vec<_> = registry.iter().map(|s| s.table).collect();
            if let Some((stage, m)) = attack {
                if stage == final_stage {
                    let instance = if stage { m } else { 2 * m };
                    let offset = instance * (2 * n + 1);
                    witness[offset..offset + 2 * n + 1]
                        .copy_from_slice(&one.iter().collect::<Vec<_>>());
                }
            }
            let public: Vec<_> = registry.iter().map(|s| s.verifier()).collect();
            let proof = lookup::prove_foreign_for_audit::<F, EF, H, _>(
                &mut prover,
                helper,
                &registry.iter().collect::<Vec<_>>(),
                &requests,
                &witness,
            )
            .unwrap();
            // Checks every recurrence and genuine opening; deliberately omits
            // just the disputed source/helper terminal identity.
            lookup::verify_reference_for_audit::<F, EF, H, _>(
                &mut reference,
                helper,
                &public,
                &requests,
                &proof,
            )
            .unwrap();
            if final_stage {
                key_switch.push(proof);
            } else {
                blind_rotation.push(proof);
            }
        }
        assert_eq!(
            prover.get_challenge(b"audit post-proof"),
            reference.get_challenge(b"audit post-proof")
        );
        let proof = Proof {
            protocol_version: COMPARISON_BATCH_PROTOCOL_VERSION,
            members,
            hadamard,
            blind_rotation,
            key_switch,
        };
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (Proof<F, EF, [u8; 32]>, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let accepted = verify::<F, EF, H, _>(&pp, &setup.verifier, &statements, &proof).is_ok();
        assert_eq!(accepted, attack.is_none());
        let attack_json = match attack {
            None => "null".to_string(),
            Some((stage, m)) => format!(
                "{{\"stage\":\"{}\",\"member\":{m}}}",
                if stage {
                    "key-switch"
                } else {
                    "blind-rotation"
                }
            ),
        };
        eprintln!(
            "HB_COMPARISON_BATCH_BINDING_CASE {{\"prime\":{},\"members\":2,\"attack\":{attack_json},\"reference_scope\":\"fresh-complete-members-joint-hadamard-and-actual-root-openings\",\"production_accepted\":{accepted}}}",
            F::MODULUS_VALUE
        );
    }
}
#[test]
fn fresh_complete_foreign_helpers_babybear() {
    audit::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
}
#[test]
fn fresh_complete_foreign_helpers_goldilocks() {
    audit::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}
