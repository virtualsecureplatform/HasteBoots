//! Complete experimental v11 control. Public seeds are reproducibility controls.
use algebra::{
    utils::{Block, Prg},
    AbstractExtensionField, AsInto, Field, NTTField,
};
use fhe_core::{
    ConstParameters, LWESecretKeyType, Parameters as FheParameters, RingSecretKeyType,
    SecretKeyPack,
};
use pcs::{
    matrix_weighted::{backend::CanonicalPcs, polyfrim, Parameters as Brakedown},
    utils::code::{BlockReedSolomonCode, RowCode},
};
use rand::{rngs::StdRng, SeedableRng};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use snarks::{
    packed_key_switch::canonical::protocol as ks,
    packed_pbs::{self as pbs, canonical, canonical::shared, canonical_setup},
};
use std::time::Instant;
use vfhe::{
    bfhe::{Evaluator, BABYBEAR_BINARY_128_BITS_PARAMETERS, GOLDILOCKS_BINARY_128_BITS_PARAMETERS},
    Decryptor, Encryptor,
};

fn digest<T: Serialize>(v: &T) -> String {
    format!(
        "{:x}",
        Sha256::digest(bincode::serde::encode_to_vec(v, bincode::config::standard()).unwrap())
    )
}
#[path = "canonical_opening_inventory.rs.inc"]
mod opening_inventory;

struct Options {
    backend: String,
    full: bool,
    count: usize,
    warmups: usize,
    validation: bool,
    cold: bool,
    parallel_oracles: bool,
    basis_helpers: bool,
    v9_fixture: bool,
    opening_inventory: bool,
    queries: usize,
}
fn run<F, E, P>(
    codes: Vec<P>,
    native: FheParameters<F>,
    width: usize,
    options: &Options,
    layouts: Vec<[usize; 6]>,
    encoders: Vec<String>,
) where
    F: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha256>,
    P::SingleProof: DeserializeOwned,
    P::BatchProof: DeserializeOwned,
{
    let opening_log: opening_inventory::Log = Default::default();
    let codes = codes
        .into_iter()
        .enumerate()
        .map(|(role, pp)| {
            opening_inventory::Observed::new::<F, Sha256>(
                pp,
                role,
                options.opening_inventory,
                opening_log.clone(),
            )
        })
        .collect();
    run_observed::<F, E, opening_inventory::Observed<P>>(
        codes,
        native,
        width,
        options,
        layouts,
        encoders,
        opening_log,
    );
}
fn run_observed<F, E, P>(
    codes: Vec<P>,
    native: FheParameters<F>,
    width: usize,
    options: &Options,
    layouts: Vec<[usize; 6]>,
    encoders: Vec<String>,
    opening_log: opening_inventory::Log,
) where
    F: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha256>,
    P::SingleProof: DeserializeOwned,
    P::BatchProof: DeserializeOwned,
{
    let cfg =
        pbs::Config::new::<F>(native.ring_dimension(), native.lwe_dimension(), 8, 5, 1, 1).unwrap();
    let pp = canonical::Parameters {
        coefficients: &codes[0],
        evaluations: &codes[0],
        key: &codes[0],
        inputs: &codes[0],
        borrows: &codes[0],
        helper: &codes[1],
        accumulators: [&codes[0]; 4],
        monomial: &codes[0],
        final_stage: ks::Parameters {
            coefficients: &codes[2],
            evaluations: &codes[2],
            key: &codes[2],
            input: &codes[2],
            borrows: &codes[2],
            helper: &codes[3],
        },
    };
    let mut seed = [0u8; 16];
    seed[..8].copy_from_slice(&42u64.to_le_bytes());
    let secret = SecretKeyPack::with_rng(native, Prg::from_seed(Block::from(seed)));
    let enc = Encryptor::new(secret.clone());
    let dec = Decryptor::new(secret.clone());
    let evaluator =
        Evaluator::from_public_evaluation_key(Evaluator::new(&secret).public_evaluation_key());
    let br_data: Vec<_> = evaluator
        .binary_bootstrap_key()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r.basis().bits(),
                [r.c_neg_s_m(), r.c_m()]
                    .map(|g| g.data().iter().map(|p| p.a_b_slice()).collect::<Vec<_>>()),
            )
        })
        .collect();
    let ks_data: Vec<_> = evaluator
        .rlwe_key_switching_key()
        .unwrap()
        .as_slice()
        .iter()
        .map(|g| {
            (
                g.basis().bits(),
                g.data().iter().map(|p| p.a_b_slice()).collect::<Vec<_>>(),
            )
        })
        .collect();
    let native_keys_sha256 = digest(&(br_data, ks_data));
    let fhe_sha256 = format!("{:x}", Sha256::digest(format!("{native:?}")));
    let contexts = codes
        .iter()
        .map(|p| p.context().unwrap_or_else(|e| panic!("{e}")))
        .collect::<Vec<_>>();
    let params_sha256 = digest(&(&cfg, &contexts));
    let context_fingerprints: Vec<_> = contexts.iter().map(digest).collect();
    let setup_pp = canonical_setup::Parameters {
        source: &codes[0],
        helper: &codes[1],
        final_source: &codes[2],
        final_helper: &codes[3],
    };
    let make_setup = || {
        canonical_setup::preprocess::<F, Sha256, _, _>(
            &setup_pp,
            cfg.clone(),
            evaluator.binary_bootstrap_key().unwrap(),
            evaluator.rlwe_key_switching_key().unwrap().as_slice(),
            &mut StdRng::seed_from_u64(941),
        )
        .unwrap()
    };
    let start = Instant::now();
    let mut setup = make_setup();
    let mut setup_s = start.elapsed().as_secs_f64();
    let schedule: Vec<(usize, usize)> = if options.validation {
        [1, 4, 16]
            .into_iter()
            .flat_map(|n| (0..n).map(move |i| (n, i)))
            .collect()
    } else {
        (0..options.warmups + options.count)
            .map(|i| (1, i))
            .collect()
    };
    if options.v9_fixture {
        // Match the frozen complete-v9 benchmark's encryption stream exactly.
        let _ = enc.encrypt(1usize.as_into());
        let _ = enc.encrypt(1usize.as_into());
    }
    for (ordinal, (group, index)) in schedule.into_iter().enumerate() {
        let left = if options.v9_fixture {
            0
        } else {
            ordinal / 2 % 2
        };
        let right = if options.v9_fixture { 0 } else { ordinal % 2 };
        let x = enc.encrypt(left.as_into());
        let y = enc.encrypt(right.as_into());
        let complete_start = Instant::now();
        if options.cold {
            drop(setup);
            let start = Instant::now();
            setup = make_setup();
            setup_s = start.elapsed().as_secs_f64();
        }
        let start = Instant::now();
        let (out, trace) = evaluator.nand(&x, &y);
        let trace_s = start.elapsed().as_secs_f64();
        let statement = pbs::Statement {
            left_a: x.a(),
            left_b: x.b(),
            right_a: y.a(),
            right_b: y.b(),
            output_a: out.a(),
            output_b: out.b(),
        };
        let expected = setup.verifier();
        let mut stats = pbs::ProverStatistics::default();
        let start = Instant::now();
        let proof = shared::prove_with_statistics::<F, E, Sha256, _, _>(
            &pp,
            &setup,
            &statement,
            &trace,
            &mut StdRng::seed_from_u64(942 + ordinal as u64),
            &mut stats,
        )
        .unwrap();
        let prove_s = start.elapsed().as_secs_f64();
        let lookup_phases = [
            stats.canonical_lookup.preparation,
            stats.canonical_lookup.commitment,
            stats.canonical_lookup.sumcheck,
            stats.canonical_lookup.zero_check,
            stats.canonical_lookup.terminal_evaluation,
            stats.canonical_lookup.openings,
        ];
        assert!(lookup_phases.iter().copied().sum::<std::time::Duration>() <= stats.decomposition);
        assert!(lookup_phases
            .iter()
            .enumerate()
            .all(|(i, d)| i == 3 || !d.is_zero()));
        assert!(stats.canonical_lookup.zero_check.is_zero());
        drop(trace);
        let start = Instant::now();
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let serialization_s = start.elapsed().as_secs_f64();
        let complete_s = complete_start.elapsed().as_secs_f64();
        drop(proof);
        let start = Instant::now();
        let (proof, used): (
            shared::Proof<F, E, [u8; 32], P::SingleProof, P::BatchProof>,
            usize,
        ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let decode_s = start.elapsed().as_secs_f64();
        if options.opening_inventory {
            opening_log.lock().unwrap().clear();
        }
        let start = Instant::now();
        shared::verify::<F, E, Sha256, _>(&pp, &expected, &statement, &proof).unwrap();
        let verify_s = start.elapsed().as_secs_f64();
        let opening_events = if options.opening_inventory {
            std::mem::take(&mut *opening_log.lock().unwrap())
        } else {
            Vec::new()
        };
        let output: <F as Field>::Value = (1 - left * right).as_into();
        assert_eq!(dec.decrypt_with_noise(&out).0, output);
        let mut altered = statement.clone();
        altered.output_b += F::from(1usize);
        assert!(shared::verify::<F, E, Sha256, _>(&pp, &expected, &altered, &proof).is_err());
        let inventory = snarks::packed_root_inventory::canonical_shared_inventory(&proof);
        let warmup = !options.validation && ordinal < options.warmups;
        if options.opening_inventory {
            println!(
                "HB_CANONICAL_OPENING_INVENTORY {{\"backend\":\"{}\",\"ordinal\":{},\"scope\":\"successful-complete-verification\",\"includes_altered_output_replay\":false,\"events\":[{}]}}",
                options.backend, ordinal,
                opening_events.iter().map(opening_inventory::Event::json).collect::<Vec<_>>().join(",")
            );
        }
        println!(
            "HB_CANONICAL_LOOKUP_PROFILE {{\"backend\":\"{}\",\"ordinal\":{},\"scope\":\"main-decomposition-lookups\",\"includes_final_key_switch\":false,\"preparation_s\":{},\"commitment_s\":{},\"sumcheck_s\":{},\"zero_check_s\":{},\"terminal_evaluation_s\":{},\"openings_s\":{}}}",
            options.backend,
            ordinal,
            stats.canonical_lookup.preparation.as_secs_f64(),
            stats.canonical_lookup.commitment.as_secs_f64(),
            stats.canonical_lookup.sumcheck.as_secs_f64(),
            stats.canonical_lookup.zero_check.as_secs_f64(),
            stats.canonical_lookup.terminal_evaluation.as_secs_f64(),
            stats.canonical_lookup.openings.as_secs_f64(),
        );
        println!(
            "HB_CANONICAL_PBS {{\"backend\":\"{}\",\"prime\":{},\"extension_degree\":{},\"protocol_version\":11,\"ring_dimension\":{},\"lwe_dimension\":{},\"output_dimension\":{},\"width\":{},\"queries\":{},\"lookup_repetitions\":1,\"group_size\":{},\"group_index\":{},\"ordinal\":{},\"warmup\":{},\"cold\":{},\"parallel_oracles\":{},\"basis_helpers\":{},\"v9_fixture\":{},\"opening_inventory\":{},\"helper_width\":{},\"final_helper_width\":{},\"rs_layouts\":{:?},\"rs_encoders_sha256\":{:?},\"contexts_sha256\":{:?},\"left\":{},\"right\":{},\"output\":{},\"fhe_parameters_sha256\":\"{}\",\"native_keys_sha256\":\"{}\",\"parameters_sha256\":\"{}\",\"statement_sha256\":\"{}\",\"trusted_setup_sha256\":\"{}\",\"proof_sha256\":\"{:x}\",\"proof_bytes\":{},\"root_slots\":{},\"setup_s\":{},\"trace_s\":{},\"prove_s\":{},\"serialization_s\":{},\"complete_s\":{},\"decode_s\":{},\"verify_s\":{},\"phase_s\":{:?},\"verified\":true,\"altered_output_rejected\":true,\"complete_pbs\":true,\"original_size\":{},\"whole_security_matched\":false,\"hiding_certified\":false,\"performance_gate\":false}}",
            options.backend,
            F::MODULUS_VALUE,
            E::D,
            native.ring_dimension(),
            native.lwe_dimension(),
            out.a().len(),
            width,
            options.queries,
            group,
            index,
            ordinal,
            warmup,
            options.cold,
            options.parallel_oracles,
            options.basis_helpers,
            options.v9_fixture,
            options.opening_inventory,
            pp.helper.width(),
            pp.final_stage.helper.width(),
            layouts,
            encoders,
            context_fingerprints,
            left,
            right,
            1 - left * right,
            fhe_sha256,
            native_keys_sha256,
            params_sha256,
            digest(&statement),
            digest(&expected),
            Sha256::digest(&bytes),
            bytes.len(),
            inventory.total(),
            setup_s,
            trace_s,
            prove_s,
            serialization_s,
            complete_s,
            decode_s,
            verify_s,
            [
                stats.preparation,
                stats.hadamard,
                stats.ntt,
                stats.decomposition,
                stats.accumulator,
                stats.monomial,
                stats.key_switch
            ]
            .map(|d| d.as_secs_f64()),
            options.full
        );
    }
}
fn select<F, E>(native: FheParameters<F>, width: usize, o: &Options)
where
    F: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let params = if o.full {
        native
    } else {
        FheParameters::<F>::new(ConstParameters {
            lwe_dimension: if o.v9_fixture { 32 } else { 21 },
            lwe_plain_modulus: 4usize.as_into(),
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
    let cfg =
        pbs::Config::new::<F>(params.ring_dimension(), params.lwe_dimension(), 8, 5, 1, 1).unwrap();
    let dims = cfg.variables(width).unwrap();
    if o.backend == "polyfrim" {
        run::<F, E, _>(
            dims.into_iter()
                .map(|v| {
                    let p = polyfrim::Parameters::<F, E>::new(v, width, 2, o.queries).unwrap();
                    if o.parallel_oracles {
                        p.with_parallel_oracles()
                    } else {
                        p
                    }
                })
                .collect(),
            params,
            width,
            o,
            Vec::new(),
            Vec::new(),
        )
    } else if o.backend == "polyfrim-compact" {
        run::<F, E, _>(
            dims.into_iter()
                .map(|v| {
                    let p =
                        polyfrim::compact::Parameters::<F, E>::new(v, width, 2, o.queries).unwrap();
                    if o.parallel_oracles {
                        p.with_parallel_oracles()
                    } else {
                        p
                    }
                })
                .collect(),
            params,
            width,
            o,
            Vec::new(),
            Vec::new(),
        )
    } else {
        let codes: Vec<_> = dims
            .into_iter()
            .enumerate()
            .map(|(role, v)| {
                let original =
                    Brakedown::<BlockReedSolomonCode<F>>::balanced_block_rs(v, width, o.queries, 2)
                        .unwrap();
                if o.basis_helpers && role % 2 == 1 {
                    // Keep the original RS symbol width, rate, domain and row split.
                    Brakedown::new_encoded::<F>(
                        v,
                        E::D,
                        original.left_vars(),
                        o.queries,
                        original.code().clone(),
                    )
                    .unwrap()
                } else {
                    original
                }
            })
            .collect();
        let layouts = codes
            .iter()
            .map(|p| {
                [
                    p.num_vars(),
                    p.width(),
                    p.left_vars(),
                    p.code().block_width(),
                    p.code().message_blocks(),
                    p.code().codeword_blocks(),
                ]
            })
            .collect();
        let encoders = codes.iter().map(|p| digest(p.code())).collect();
        run::<F, E, _>(codes, params, width, o, layouts, encoders)
    }
}
fn main() {
    let mut args = std::env::args().skip(1);
    let field=args.next().expect("babybear|goldilocks polyfrim|polyfrim-compact|brakedown [--full] [--iterations N] [--warmups N] [--queries N] [--validation-batches] [--cold] [--v9-fixture]");
    let backend = args.next().expect("backend");
    assert!(matches!(
        backend.as_str(),
        "polyfrim" | "polyfrim-compact" | "brakedown"
    ));
    let queries = if backend == "brakedown" { 544 } else { 128 };
    let mut o = Options {
        backend,
        full: false,
        count: 10,
        warmups: 1,
        validation: false,
        cold: false,
        parallel_oracles: false,
        basis_helpers: false,
        v9_fixture: false,
        opening_inventory: false,
        queries,
    };
    let mut explicit_iterations = false;
    let mut explicit_warmups = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--full" => o.full = true,
            "--basis-helpers" => o.basis_helpers = true,
            "--v9-fixture" => o.v9_fixture = true,
            "--opening-inventory" => o.opening_inventory = true,
            "--cold" => o.cold = true,
            "--parallel-oracles" => o.parallel_oracles = true,
            "--validation-batches" => o.validation = true,
            "--iterations" => {
                o.count = args.next().unwrap().parse().unwrap();
                explicit_iterations = true
            }
            "--warmups" => {
                o.warmups = args.next().unwrap().parse().unwrap();
                explicit_warmups = true
            }
            "--queries" => o.queries = args.next().unwrap().parse().unwrap(),
            _ => panic!("unknown argument {arg}"),
        }
    }
    assert!(o.count > 0 && o.queries > 0);
    assert!(
        !o.v9_fixture || !o.validation,
        "v9 fixture is single-proof timing only"
    );
    assert!(
        !o.basis_helpers || o.backend == "brakedown",
        "basis helper layout is initially Brakedown-only"
    );
    assert!(
        !o.parallel_oracles || o.backend != "brakedown",
        "parallel oracle policy applies only to PolyFRIM backends"
    );
    assert!(
        !o.validation || (!explicit_iterations && !explicit_warmups),
        "validation uses exactly 1/4/16 fresh proofs without warmups"
    );
    match field.as_str() {
        "babybear" => select::<algebra::BabyBear, algebra::BabyBearExtension6>(
            *BABYBEAR_BINARY_128_BITS_PARAMETERS,
            8,
            &o,
        ),
        "goldilocks" => select::<algebra::Goldilocks, algebra::GoldilocksExtension3>(
            *GOLDILOCKS_BINARY_128_BITS_PARAMETERS,
            4,
            &o,
        ),
        _ => panic!("unknown field"),
    }
}
