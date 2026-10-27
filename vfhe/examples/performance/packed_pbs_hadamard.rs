//! Experimental proof of the Hadamard portion of an actual PBS trace.
use algebra::{
    BabyBear as F, Field,
    utils::{Block, Prg},
};
use fhe_core::{
    ConstParameters, LWESecretKeyType, Parameters as FheParameters, RingSecretKeyType,
    SecretKeyPack,
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted::Parameters,
    utils::code::{BlockReedSolomonCode, RowCode},
};
use rand::SeedableRng;
use sha2::Sha256;
use snarks::{
    packed_accumulator, packed_bootstrap_key, packed_decomposition, packed_key_switch,
    packed_lookup, packed_monomial, packed_ntt, packed_oracle::ProverOracle, packed_relation,
};
use std::time::Instant;
use vfhe::{
    Decryptor, Encryptor,
    bfhe::{BABYBEAR_BINARY_128_BITS_PARAMETERS, Evaluator},
};

fn main() {
    let full = std::env::args().any(|s| s == "--full");
    let with_lookup = std::env::args().any(|s| s == "--with-lookup");
    let with_key_switch = std::env::args().any(|s| s == "--with-key-switch");
    let with_public_key = with_key_switch || std::env::args().any(|s| s == "--with-public-key");
    let with_monomial = with_public_key || std::env::args().any(|s| s == "--with-monomial");
    let with_accumulator = with_monomial || std::env::args().any(|s| s == "--with-accumulator");
    let lane_lookups = with_accumulator || std::env::args().any(|s| s == "--lane-lookups");
    let with_decomposition = lane_lookups || std::env::args().any(|s| s == "--with-decomposition");
    let params = if full {
        *BABYBEAR_BINARY_128_BITS_PARAMETERS
    } else {
        FheParameters::<F>::new(ConstParameters {
            lwe_dimension: 32,
            lwe_plain_modulus: 4,
            lwe_noise_standard_deviation: 1.0,
            lwe_secret_key_type: LWESecretKeyType::Binary,
            ring_dimension: 32,
            ring_modulus: F::MODULUS_VALUE,
            ring_noise_standard_deviation: 1.0,
            ring_secret_key_type: RingSecretKeyType::Ternary,
            blind_rotation_basis_bits: 8,
            key_switching_basis_bits: 5,
            key_switching_standard_deviation: 1.0,
        })
        .unwrap()
    };
    // Public deterministic fixture, matching the complete PBS benchmark seed.
    let seed = 42u64;
    let mut seed_bytes = [0u8; 16];
    seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
    let sk = SecretKeyPack::with_rng(params, Prg::from_seed(Block::from(seed_bytes)));
    let enc = Encryptor::new(sk.clone());
    let evaluator = Evaluator::new(&sk);
    let dec = Decryptor::new(sk);
    let x = enc.encrypt(1);
    let y = enc.encrypt(1);
    let (out, mut trace) = evaluator.nand(&x, &y);
    assert_eq!(dec.decrypt_with_noise(&out).0, 0);
    trace.blind_rotation_trace.finalize(params.lwe_dimension());
    let timer = Instant::now();
    let (shape, factors) =
        packed_relation::from_sum_hadamard(8, &trace.blind_rotation_trace.hadamard_trace).unwrap();
    // Block RS backend; query count is deliberately explicit. These
    // example settings do not assert a complete PBS security budget.
    let parameters = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(
        shape.num_vars,
        shape.width,
        if with_lookup || with_decomposition {
            544
        } else {
            512
        },
        2,
    )
    .unwrap();
    let (commitments, states): (Vec<_>, Vec<_>) = factors
        .iter()
        .map(|t| parameters.commit::<F, Sha256>(t).unwrap())
        .unzip();
    let public_key = if with_public_key {
        let setup = Instant::now();
        let key = packed_bootstrap_key::preprocess::<F, Sha256, _>(
            &parameters,
            params.ring_dimension(),
            evaluator.binary_bootstrap_key().unwrap(),
        )
        .unwrap();
        assert_eq!(key.rounds(), params.lwe_dimension());
        assert_eq!(key.basis_bits(), params.blind_rotation_basis().bits());
        println!(
            "Trusted public binary key setup: roots={} preprocess_ms={:.3}; reusable setup, not a complete PBS proof",
            key.roots().len(),
            setup.elapsed().as_secs_f64() * 1000.0
        );
        Some(key)
    } else {
        None
    };
    let prepare_commit_ns = timer.elapsed().as_nanos();
    let commit_ms = prepare_commit_ns as f64 / 1e6;
    let mut prover = Transcript::new();
    let statement = (
        params.lwe_dimension(),
        params.ring_dimension(),
        x.a(),
        x.b(),
        y.a(),
        y.b(),
        out.a(),
        out.b(),
    );
    prover.append_message(b"PBS Hadamard component demo v1", &statement);
    let timer = Instant::now();
    let mut statistics = packed_relation::ProverStatistics::default();
    let proof = packed_relation::prove_with_statistics::<F, Sha256, _>(
        &mut prover,
        &shape,
        &parameters,
        &factors,
        &commitments,
        &states,
        &mut statistics,
    )
    .unwrap();
    let prove_ns = timer.elapsed().as_nanos();
    let prove_ms = prove_ns as f64 / 1e6;
    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .unwrap()
        .len();
    let mut verifier = Transcript::new();
    verifier.append_message(b"PBS Hadamard component demo v1", &statement);
    let timer = Instant::now();
    if let Some(key) = &public_key {
        let private: Vec<_> = commitments.iter().step_by(2).cloned().collect();
        packed_bootstrap_key::verify::<F, Sha256, _>(
            &mut verifier,
            &parameters,
            key,
            &private,
            &proof,
        )
        .unwrap();
    } else {
        packed_relation::verify::<F, Sha256, _>(
            &mut verifier,
            &shape,
            &parameters,
            &commitments,
            &proof,
        )
        .unwrap();
    }
    let verify_ns = timer.elapsed().as_nanos();
    if with_decomposition || with_lookup || std::env::args().any(|s| s == "--with-ntt") {
        let timer = Instant::now();
        let coefficient_factors = packed_relation::coefficients_from_sum_hadamard(
            8,
            &trace.blind_rotation_trace.hadamard_trace,
        )
        .unwrap();
        let ntt_shape =
            packed_ntt::Shape::new::<F, _>(&parameters, params.ring_dimension()).unwrap();
        let (coefficient_commitments, coefficient_states): (Vec<_>, Vec<_>) = coefficient_factors
            .iter()
            .map(|t| parameters.commit::<F, Sha256>(t).unwrap())
            .unzip();
        let mut ntt_bytes = 0usize;
        let mut lookup_bytes = 0usize;
        let mut lookup_ns = 0u128;
        for (index, table) in coefficient_factors.iter().enumerate() {
            let commitment = &coefficient_commitments[index];
            let state = &coefficient_states[index];
            let coefficients = ProverOracle {
                parameters: &parameters,
                commitment,
                state,
                table,
            };
            // Reuse the exact root and table consumed by the Hadamard proof.
            let evaluations = ProverOracle {
                parameters: &parameters,
                commitment: &commitments[index],
                state: &states[index],
                table: &factors[index],
            };
            let proof = packed_ntt::prove::<F, Sha256, _>(
                &mut prover,
                &ntt_shape,
                &coefficients,
                &evaluations,
            )
            .unwrap();
            packed_ntt::verify::<F, Sha256, _>(
                &mut verifier,
                &ntt_shape,
                &coefficients.verifier(),
                &evaluations.verifier(),
                &proof,
            )
            .unwrap();
            if with_lookup
                && index < 2 * trace.blind_rotation_trace.hadamard_trace.num_hadamard
                && index % 2 == 0
            {
                let timer = Instant::now();
                let active = 2 * trace.blind_rotation_trace.hadamard_trace.vec_hadamard[index / 2]
                    .bit
                    .poly
                    .len();
                let range = 1usize << params.blind_rotation_basis().bits();
                let config =
                    packed_lookup::Config::new(active, (0..range).map(F::from).collect(), 16)
                        .unwrap();
                let lookup =
                    packed_lookup::prove::<F, Sha256, _>(&mut prover, &config, &coefficients)
                        .unwrap();
                packed_lookup::verify::<F, Sha256, _>(
                    &mut verifier,
                    &config,
                    &coefficients.verifier(),
                    &lookup,
                )
                .unwrap();
                lookup_bytes += bincode::serde::encode_to_vec(&lookup, bincode::config::standard())
                    .unwrap()
                    .len();
                lookup_ns += timer.elapsed().as_nanos();
            }
            ntt_bytes +=
                bincode::serde::encode_to_vec(&(commitment, proof), bincode::config::standard())
                    .unwrap()
                    .len();
        }
        let mut decomposition_ns = 0u128;
        let mut accumulator_ns = 0u128;
        let mut monomial_ns = 0u128;
        let mut key_switch_ns = 0u128;
        if with_decomposition {
            let timer = Instant::now();
            let inputs =
                packed_decomposition::sources_from_blind_rotation(8, &trace.blind_rotation_trace)
                    .unwrap();
            let (decomposition_commitments, decomposition_states): (Vec<_>, Vec<_>) = inputs
                .iter()
                .map(|t| parameters.commit::<F, Sha256>(t).unwrap())
                .unzip();
            let d = params.blind_rotation_basis().decompose_len();
            let lane_parameters = if lane_lookups {
                Some(
                    Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(
                        shape.num_vars + shape.width.ilog2() as usize,
                        shape.width,
                        544,
                        2,
                    )
                    .unwrap(),
                )
            } else {
                None
            };
            let mut phase_statistics = snarks::packed_lane_lookup::ProverStatistics::default();
            let mut decomposition_prove_ns = 0u128;
            let mut decomposition_verify_ns = 0u128;
            let mut decomposition_serialize_ns = 0u128;
            let mut bytes = 0usize;
            for (component, input) in inputs.iter().enumerate() {
                let commitment = &decomposition_commitments[component];
                let state = &decomposition_states[component];
                let source = ProverOracle {
                    parameters: &parameters,
                    commitment,
                    state,
                    table: input,
                };
                let digit_oracles: Vec<_> = (0..d)
                    .map(|i| {
                        let index = 2 * (component * d + i);
                        ProverOracle {
                            parameters: &parameters,
                            commitment: &coefficient_commitments[index],
                            state: &coefficient_states[index],
                            table: &coefficient_factors[index],
                        }
                    })
                    .collect();
                let digits: Vec<_> = digit_oracles.iter().collect();
                let config = packed_decomposition::Config::new::<F>(
                    params.blind_rotation_basis().bits(),
                    input.values().len(),
                    16,
                )
                .unwrap();
                let public_digits: Vec<_> = digit_oracles.iter().map(|s| s.verifier()).collect();
                if let Some(helper) = &lane_parameters {
                    let phase_timer = Instant::now();
                    let proof = packed_decomposition::prove_lanes_with_statistics::<F, Sha256, _>(
                        &mut prover,
                        &config,
                        &source,
                        helper,
                        &digits,
                        &mut phase_statistics,
                    )
                    .unwrap();
                    decomposition_prove_ns += phase_timer.elapsed().as_nanos();
                    let phase_timer = Instant::now();
                    packed_decomposition::verify_lanes::<F, Sha256, _>(
                        &mut verifier,
                        &config,
                        &source.verifier(),
                        helper,
                        &public_digits,
                        &proof,
                    )
                    .unwrap();
                    decomposition_verify_ns += phase_timer.elapsed().as_nanos();
                    let phase_timer = Instant::now();
                    bytes += bincode::serde::encode_to_vec(
                        &(commitment, proof),
                        bincode::config::standard(),
                    )
                    .unwrap()
                    .len();
                    decomposition_serialize_ns += phase_timer.elapsed().as_nanos();
                } else {
                    let proof = packed_decomposition::prove::<F, Sha256, _>(
                        &mut prover,
                        &config,
                        &source,
                        &digits,
                    )
                    .unwrap();
                    packed_decomposition::verify::<F, Sha256, _>(
                        &mut verifier,
                        &config,
                        &source.verifier(),
                        &public_digits,
                        &proof,
                    )
                    .unwrap();
                    bytes += bincode::serde::encode_to_vec(
                        &(commitment, proof),
                        bincode::config::standard(),
                    )
                    .unwrap()
                    .len();
                }
            }
            if lane_lookups {
                println!(
                    "HB_LANE_PHASES {{\"prove_ns\":{decomposition_prove_ns},\"verify_ns\":{decomposition_verify_ns},\"serialization_ns\":{decomposition_serialize_ns},\"lookup_preparation_ns\":{},\"lookup_commitment_ns\":{},\"lookup_sumcheck_ns\":{},\"lookup_zero_check_ns\":{},\"lookup_terminal_evaluation_ns\":{},\"lookup_openings_ns\":{}}}",
                    phase_statistics.preparation.as_nanos(),
                    phase_statistics.commitment.as_nanos(),
                    phase_statistics.sumcheck.as_nanos(),
                    phase_statistics.zero_check.as_nanos(),
                    phase_statistics.terminal_evaluation.as_nanos(),
                    phase_statistics.openings.as_nanos()
                );
            }
            let active = inputs.iter().map(|t| t.values().len()).max().unwrap();
            let range = 2usize << params.blind_rotation_basis().bits();
            let marker = if lane_lookups {
                "HB_LANE_DECOMPOSITION"
            } else {
                "HB_DECOMPOSITION"
            };
            let kind = if lane_lookups {
                "pbs-lane-canonical-digit-decomposition"
            } else {
                "pbs-canonical-digit-decomposition"
            };
            let helper_json = if let Some(helper) = &lane_parameters {
                format!(
                    ",\"helper_variables\":{},\"helper_row_message_scalars\":{},\"helper_row_message_blocks\":{},\"helper_row_encoded_blocks\":{},\"helper_block_width\":{},\"helper_queries\":{},\"effective_repetitions\":16,\"lookup_groups\":2",
                    helper.num_vars(),
                    helper.code().message_len(),
                    helper.code().message_blocks(),
                    helper.code().codeword_blocks(),
                    helper.code().block_width(),
                    helper.queries()
                )
            } else {
                String::new()
            };
            println!(
                "{marker} {{\"kind\":\"{kind}\",\"full_parameters\":{full},\"prime\":{},\"width\":{},\"degree\":3,\"variables\":{},\"factors\":{},\"logical_len\":{active},\"public_table_len\":{range},\"excluded_challenges\":{},\"repetitions\":16,\"tuple_columns\":3,\"linear_checks\":2,\"linear_sources\":{},\"row_message_scalars\":{},\"row_message_blocks\":{},\"row_encoded_blocks\":{},\"block_width\":{},\"queries\":{},\"proof_bytes\":{bytes}{helper_json}}}",
                F::MODULUS_VALUE,
                shape.width,
                shape.num_vars,
                2 * d,
                range + 1,
                4 * d + 4,
                parameters.code().message_len(),
                parameters.code().message_blocks(),
                parameters.code().codeword_blocks(),
                parameters.code().block_width(),
                parameters.queries()
            );
            decomposition_ns = timer.elapsed().as_nanos();
            println!(
                "Canonical decomposition component: lane_lookups={lane_lookups} halves=2 digits_per_half={d} repetitions=16 additional_bytes={bytes} prepare_prove_verify_serialize_ms={:.3}; upstream rotation/key/public-statement provenance remains unproved",
                decomposition_ns as f64 / 1e6
            );
            if with_accumulator {
                let timer = Instant::now();
                let tables =
                    packed_accumulator::from_native(shape.width, &trace.blind_rotation_trace)
                        .unwrap();
                let (roots, states): (Vec<_>, Vec<_>) = tables
                    .iter()
                    .map(|t| parameters.commit::<F, Sha256>(t).unwrap())
                    .unzip();
                let mut oracles: Vec<_> = tables
                    .iter()
                    .zip(&roots)
                    .zip(&states)
                    .map(|((table, commitment), state)| ProverOracle {
                        parameters: &parameters,
                        table,
                        commitment,
                        state,
                    })
                    .collect();
                let last = coefficient_factors.len() - 1;
                oracles.push(ProverOracle {
                    parameters: &parameters,
                    table: &coefficient_factors[last],
                    commitment: &coefficient_commitments[last],
                    state: &coefficient_states[last],
                });
                for component in 0..2 {
                    oracles.push(ProverOracle {
                        parameters: &parameters,
                        table: &inputs[component],
                        commitment: &decomposition_commitments[component],
                        state: &decomposition_states[component],
                    });
                }
                let acc = &trace.blind_rotation_trace.acc_trace;
                let mut initial: Vec<_> = acc
                    .initial_acc
                    .poly
                    .0
                    .iter()
                    .chain(&acc.initial_acc.poly.1)
                    .copied()
                    .collect();
                let public_plan = if with_monomial {
                    let mask: Vec<_> = x.a().iter().zip(y.a()).map(|(&a, &b)| a + b).collect();
                    let plan =
                        packed_monomial::Plan::from_field_mask(params.ring_dimension(), &mask)
                            .unwrap();
                    let lut =
                        packed_monomial::nand_lut::<F>(params.ring_dimension(), params.lut_step())
                            .unwrap();
                    let public_initial =
                        packed_monomial::initial_accumulator(&lut, x.b() + y.b()).unwrap();
                    assert_eq!(initial, public_initial);
                    initial = public_initial;
                    Some(plan)
                } else {
                    None
                };
                let final_acc: Vec<_> = acc
                    .final_acc
                    .poly
                    .0
                    .iter()
                    .chain(&acc.final_acc.poly.1)
                    .copied()
                    .collect();
                let acc_shape =
                    packed_accumulator::Shape::new(params.ring_dimension(), params.lwe_dimension())
                        .unwrap();
                let proof = packed_accumulator::prove::<F, Sha256, _>(
                    &mut prover,
                    &acc_shape,
                    &initial,
                    &final_acc,
                    &oracles.iter().collect::<Vec<_>>(),
                )
                .unwrap();
                packed_accumulator::verify::<F, Sha256, _>(
                    &mut verifier,
                    &acc_shape,
                    &initial,
                    &final_acc,
                    &oracles.iter().map(|s| s.verifier()).collect::<Vec<_>>(),
                    &proof,
                )
                .unwrap();
                let source_queries: usize = proof.values.iter().map(Vec::len).sum();
                let response_groups: usize =
                    proof.openings.iter().map(|o| o.evaluations.len() + 1).sum();
                let bytes = bincode::serde::encode_to_vec(
                    &(&roots, &initial, &final_acc, proof),
                    bincode::config::standard(),
                )
                .unwrap()
                .len();
                accumulator_ns = timer.elapsed().as_nanos();
                println!(
                    "HB_ACCUMULATOR {{\"kind\":\"pbs-accumulator-linear-linkage\",\"full_parameters\":{full},\"prime\":{},\"width\":{},\"degree\":1,\"variables\":{},\"factors\":7,\"linear_relations\":7,\"polynomial_size\":{},\"rounds\":{},\"padded_rounds\":{},\"coefficient_variables\":{},\"left_vars\":{},\"source_queries\":{source_queries},\"response_groups\":{response_groups},\"row_message_scalars\":{},\"row_message_blocks\":{},\"row_encoded_blocks\":{},\"block_width\":{},\"queries\":{},\"proof_bytes\":{bytes},\"prepare_prove_verify_serialize_ns\":{accumulator_ns}}}",
                    F::MODULUS_VALUE,
                    shape.width,
                    shape.num_vars,
                    params.ring_dimension(),
                    params.lwe_dimension(),
                    acc_shape.padded_rounds(),
                    (params.ring_dimension() / shape.width).ilog2(),
                    parameters.left_vars(),
                    parameters.code().message_len(),
                    parameters.code().message_blocks(),
                    parameters.code().codeword_blocks(),
                    parameters.code().block_width(),
                    parameters.queries()
                );
                println!(
                    "Accumulator arithmetic/continuity component: additional_bytes={bytes} prepare_prove_verify_serialize_ms={:.3}; keys and full PBS remain unproved",
                    accumulator_ns as f64 / 1e6
                );
                if let Some(plan) = public_plan {
                    let timer = Instant::now();
                    let sources = [&oracles[0], &oracles[1]];
                    let proof =
                        packed_monomial::prove::<F, Sha256, _>(&mut prover, &plan, &sources)
                            .unwrap();
                    packed_monomial::verify::<F, Sha256, _>(
                        &mut verifier,
                        &plan,
                        &sources.iter().map(|s| s.verifier()).collect::<Vec<_>>(),
                        &proof,
                    )
                    .unwrap();
                    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
                        .unwrap()
                        .len();
                    monomial_ns = timer.elapsed().as_nanos();
                    println!(
                        "HB_MONOMIAL {{\"kind\":\"public-monomial-product\",\"full_parameters\":{full},\"prime\":{},\"width\":{},\"variables\":{},\"polynomial_size\":{},\"rounds\":{},\"padded_rounds\":{},\"left_vars\":{},\"row_message_scalars\":{},\"row_message_blocks\":{},\"row_encoded_blocks\":{},\"block_width\":{},\"queries\":{},\"proof_bytes\":{bytes},\"prove_verify_serialize_ns\":{monomial_ns}}}",
                        F::MODULUS_VALUE,
                        shape.width,
                        shape.num_vars,
                        plan.polynomial_size(),
                        plan.rotations().len(),
                        plan.padded_rounds(),
                        parameters.left_vars(),
                        parameters.code().message_len(),
                        parameters.code().message_blocks(),
                        parameters.code().codeword_blocks(),
                        parameters.code().block_width(),
                        parameters.queries()
                    );
                    println!(
                        "Public-input monomial product and accumulator initialization verified: additional_bytes={bytes} prove_verify_serialize_ms={:.3}; key binding and final output relation remain unproved",
                        monomial_ns as f64 / 1e6
                    );
                }
                if with_key_switch {
                    let timer = Instant::now();
                    let n = params.ring_dimension();
                    let variables = (2 * n / shape.width).ilog2() as usize;
                    let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(
                        variables,
                        shape.width,
                        544,
                        2,
                    )
                    .unwrap();
                    let helper = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(
                        variables + shape.width.ilog2() as usize,
                        shape.width,
                        544,
                        2,
                    )
                    .unwrap();
                    let native_key = evaluator.rlwe_key_switching_key().unwrap();
                    assert_eq!(native_key.lwe_dimension(), params.lwe_dimension());
                    let config = packed_key_switch::Config::new::<F>(
                        n,
                        params.lwe_dimension(),
                        params.key_switching_basis_bits(),
                        16,
                    )
                    .unwrap();
                    let digits = config.digits::<F>().unwrap();
                    let key = packed_key_switch::preprocess::<F, Sha256, _>(
                        &pp,
                        config,
                        native_key.as_slice(),
                    )
                    .unwrap();
                    let coefficients =
                        packed_key_switch::from_native(shape.width, &trace.key_switching_trace)
                            .unwrap();
                    let proof = packed_key_switch::prove::<F, Sha256, _>(
                        &mut prover,
                        &pp,
                        &helper,
                        &key,
                        &final_acc,
                        out.a(),
                        out.b(),
                        &coefficients,
                    )
                    .unwrap();
                    packed_key_switch::verify::<F, Sha256, _>(
                        &mut verifier,
                        &pp,
                        &helper,
                        key.expected(),
                        &final_acc,
                        out.a(),
                        out.b(),
                        &proof,
                    )
                    .unwrap();
                    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
                        .unwrap()
                        .len();
                    key_switch_ns = timer.elapsed().as_nanos();
                    println!(
                        "HB_KEY_SWITCH {{\"kind\":\"rlwe-key-switch-and-public-extraction\",\"full_parameters\":{full},\"prime\":{},\"width\":{},\"variables\":{variables},\"polynomial_size\":{n},\"output_dimension\":{},\"basis_bits\":{},\"digits\":{digits},\"repetitions\":16,\"left_vars\":{},\"row_message_scalars\":{},\"row_message_blocks\":{},\"row_encoded_blocks\":{},\"block_width\":{},\"queries\":{},\"helper_variables\":{},\"helper_row_message_scalars\":{},\"helper_row_message_blocks\":{},\"helper_row_encoded_blocks\":{},\"helper_block_width\":{},\"helper_queries\":{},\"proof_bytes\":{bytes},\"prepare_prove_verify_serialize_ns\":{key_switch_ns}}}",
                        F::MODULUS_VALUE,
                        shape.width,
                        params.lwe_dimension(),
                        params.key_switching_basis_bits(),
                        pp.left_vars(),
                        pp.code().message_len(),
                        pp.code().message_blocks(),
                        pp.code().codeword_blocks(),
                        pp.code().block_width(),
                        pp.queries(),
                        helper.num_vars(),
                        helper.code().message_len(),
                        helper.code().message_blocks(),
                        helper.code().codeword_blocks(),
                        helper.code().block_width(),
                        helper.queries()
                    );
                    println!(
                        "Canonical key switching and original output extraction verified: additional_bytes={bytes} prepare_prove_verify_serialize_ms={:.3}; complete PBS API/security/performance promotion remain pending",
                        key_switch_ns as f64 / 1e6
                    );
                }
            }
        }
        if with_lookup {
            println!(
                "Digit lookup component: factors={} repetitions=16 additional_bytes={lookup_bytes} prove_verify_ms={:.3}; no reconstruction/full-PBS/security claim",
                trace.blind_rotation_trace.hadamard_trace.num_hadamard,
                lookup_ns as f64 / 1e6
            );
        }
        if with_lookup {
            let active = trace
                .blind_rotation_trace
                .hadamard_trace
                .vec_hadamard
                .iter()
                .map(|t| 2 * t.bit.poly.len())
                .max()
                .unwrap();
            let range = 1usize << params.blind_rotation_basis().bits();
            println!(
                "HB_LOOKUP {{\"kind\":\"pbs-digit-range-lookup\",\"prime\":{},\"width\":{},\"degree\":3,\"variables\":{},\"factors\":{},\"logical_len\":{active},\"public_table_len\":{range},\"excluded_challenges\":{range},\"repetitions\":16,\"row_message_scalars\":{},\"row_message_blocks\":{},\"row_encoded_blocks\":{},\"block_width\":{},\"queries\":{},\"proof_bytes\":{lookup_bytes},\"prove_verify_ns\":{lookup_ns}}}",
                F::MODULUS_VALUE,
                shape.width,
                shape.num_vars,
                trace.blind_rotation_trace.hadamard_trace.num_hadamard,
                parameters.code().message_len(),
                parameters.code().message_blocks(),
                parameters.code().codeword_blocks(),
                parameters.code().block_width(),
                parameters.queries()
            );
        }
        assert_eq!(
            prover.get_challenge(b"after NTT"),
            verifier.get_challenge(b"after NTT")
        );
        println!(
            "NTT-linked Hadamard component: factors={} additional_bytes={ntt_bytes} commit_prove_verify_ms={:.3}; no full-PBS/security claim",
            coefficient_factors.len(),
            (timer.elapsed().as_nanos()
                - lookup_ns
                - decomposition_ns
                - accumulator_ns
                - monomial_ns
                - key_switch_ns) as f64
                / 1e6
        );
    }
    let commitment_bytes = bincode::serde::encode_to_vec(&commitments, bincode::config::standard())
        .unwrap()
        .len();
    println!("Hadamard component only; full_parameters={full}; no full-PBS/security claim");
    println!(
        "row_code=block-rs left_vars={} block_width={} encoded_blocks={}",
        parameters.left_vars(),
        parameters.code().block_width(),
        parameters.code().codeword_blocks()
    );
    println!(
        "commit_ms={commit_ms:.3} prove_ms={prove_ms:.3} verify_ms={:.3} proof_bytes={proof_bytes} factors={} width={} variables={}",
        verify_ns as f64 / 1e6,
        factors.len(),
        shape.width,
        shape.num_vars
    );
    println!(
        "HB_COMPONENT {{\"kind\":\"pbs-external-product-hadamard\",\"full_parameters\":{full},\"seed\":{seed},\"prime\":{},\"width\":{},\"variables\":{},\"degree\":{},\"factors\":{},\"left_vars\":{},\"row_message_scalars\":{},\"row_message_blocks\":{},\"row_encoded_blocks\":{},\"block_width\":{},\"queries\":{},\"prepare_commit_ns\":{prepare_commit_ns},\"prove_ns\":{prove_ns},\"verify_ns\":{verify_ns},\"zero_check_ns\":{},\"terminal_evaluation_ns\":{},\"openings_ns\":{},\"proof_bytes\":{proof_bytes},\"commitment_bytes\":{commitment_bytes},\"artifact_bytes\":{},\"threads\":{}}}",
        F::MODULUS_VALUE,
        shape.width,
        shape.num_vars,
        shape
            .terms
            .iter()
            .map(|(_, indices)| indices.len())
            .max()
            .unwrap(),
        shape.num_factors,
        parameters.left_vars(),
        parameters.code().message_len(),
        parameters.code().message_blocks(),
        parameters.code().codeword_blocks(),
        parameters.code().block_width(),
        parameters.queries(),
        statistics.zero_check.as_nanos(),
        statistics.terminal_evaluation.as_nanos(),
        statistics.openings.as_nanos(),
        proof_bytes + commitment_bytes,
        rayon::current_num_threads()
    );
}
