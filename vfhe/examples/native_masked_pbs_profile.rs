//! Complete original-size canonical PBS control; public seeds are test controls.
use algebra::{
    AsInto, Field,
    utils::{Block, Prg},
};
use fhe_core::SecretKeyPack;
use pcs::matrix_weighted::masked_polyfrim::joint::{Parameters, Proof as PcsProof};
use rand::{SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};
use snarks::packed_pbs::{self as pbs, canonical, canonical::shared, canonical_setup};
use std::{io::Write, path::Path, time::Instant};
use vfhe::{
    Decryptor, Encryptor,
    bfhe::{BABYBEAR_BINARY_128_BITS_PARAMETERS, Evaluator, GOLDILOCKS_BINARY_128_BITS_PARAMETERS},
};
macro_rules! digest {
    ($value:expr) => {
        format!(
            "{:x}",
            Sha256::digest(
                bincode::serde::encode_to_vec(&$value, bincode::config::standard()).unwrap()
            )
        )
    };
}
fn artifact(directory: &Path, name: &str, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join(name))
        .unwrap();
    file.write_all(bytes).unwrap();
}
macro_rules! profile {
    ($name:ident, $f:ty, $e:ty, $width:expr, $native:ident) => {
        fn $name(directory: &Path, replay: bool) {
            type F = $f;
            type E = $e;
            const WIDTH: usize = $width;
            let cfg = pbs::Config::new::<F>(1024, 728, 8, 5, 1, 1).unwrap();
            let dims = cfg.variables(WIDTH).unwrap();
            let budgets = cfg.canonical_opening_budget(WIDTH).unwrap();
            let make = |vars, budget| (vars..25).find_map(|physical| Parameters::<F, E>::new(vars, WIDTH, physical, 2, 128, budget).ok())
                .expect("native masked geometry").with_transient_source_values();
            let cpp = make(dims[0], budgets.coefficients);
            let epp = make(dims[0], budgets.evaluations);
            let key = make(dims[0], budgets.key);
            let input = make(dims[0], budgets.inputs);
            let borrow = make(dims[0], budgets.borrows);
            let helper = make(dims[1], budgets.helper);
            let mono = make(dims[0], budgets.monomial);
            let acc = budgets.accumulators.map(|allowance| make(dims[0], allowance));
            let fco = make(dims[2], budgets.final_coefficients);
            let fev = make(dims[2], budgets.final_evaluations);
            let fkey = make(dims[2], budgets.final_key);
            let fin = make(dims[2], budgets.final_input);
            let fborrow = make(dims[2], budgets.final_borrows);
            let fhelper = make(dims[3], budgets.final_helper);
            let parameters = [&cpp, &epp, &key, &input, &borrow, &helper, &mono, &acc[0], &acc[1], &acc[2], &acc[3], &fco, &fev, &fkey, &fin, &fborrow, &fhelper];
            let geometry = parameters.iter().map(|p| (p.num_vars(), p.physical_vars(), p.width(), p.max_openings())).collect::<Vec<_>>();
            eprintln!("HB_NATIVE_PBS_GEOMETRY {:?}", geometry);
            if !replay { artifact(directory, "geometry.json", format!("{:?}\n", geometry).replace('(', "[").replace(')', "]").as_bytes()); }
            let pp = canonical::Parameters {
                coefficients: &cpp, evaluations: &epp, key: &key, inputs: &input, borrows: &borrow, helper: &helper,
                accumulators: [&acc[0], &acc[1], &acc[2], &acc[3]], monomial: &mono,
                final_stage: snarks::packed_key_switch::canonical::protocol::Parameters {
                    coefficients: &fco, evaluations: &fev, key: &fkey, input: &fin, borrows: &fborrow, helper: &fhelper,
                },
            };
            pp.check_opening_limits::<F, Sha256>(&cfg).unwrap();
            let native_params = *$native;
            let fhe_parameters_sha256 = format!("{:x}", Sha256::digest(format!("{native_params:?}")));
            let sk = SecretKeyPack::with_rng(native_params, Prg::from_seed(Block::from([42u8; 16])));
            let enc = Encryptor::new(sk.clone());
            let dec = Decryptor::new(sk.clone());
            let evaluator = Evaluator::new(&sk);
            let setup_pp = canonical_setup::Parameters { source: &key, helper: &helper, final_source: &fkey, final_helper: &fhelper };
            eprintln!("HB_NATIVE_PBS_PHASE setup");
            let start = Instant::now();
            let setup = canonical_setup::preprocess::<F, Sha256, _, _>(&setup_pp, cfg.clone(), evaluator.binary_bootstrap_key().unwrap(), evaluator.rlwe_key_switching_key().unwrap().as_slice(), &mut StdRng::seed_from_u64(941)).unwrap();
            let setup_s = start.elapsed().as_secs_f64();
            let expected = setup.verifier();
            canonical_setup::validate::<F, Sha256, _>(&setup_pp, &expected).unwrap();
            let roots = (setup.br_oracles(&key).unwrap().iter().map(|o| o.commitment.root).collect::<Vec<_>>(),
                         setup.ks_oracles(&fkey).unwrap().iter().map(|o| o.commitment.root).collect::<Vec<_>>());
            let native_key_roots_sha256 = digest!(roots);
            eprintln!("HB_NATIVE_PBS_PHASE trace");
            let start = Instant::now();
            let x = enc.encrypt(1usize.as_into());
            let y = enc.encrypt(1usize.as_into());
            let (out, trace) = evaluator.nand(&x, &y);
            assert_eq!(out.a().len(), 728);
            assert_eq!(dec.decrypt_with_noise(&out).0, 0usize.as_into());
            let trace_s = start.elapsed().as_secs_f64();
            let statement = pbs::Statement { left_a: x.a(), left_b: x.b(), right_a: y.a(), right_b: y.b(), output_a: out.a(), output_b: out.b() };
            let trusted_artifacts = [
                ("statement.bin", bincode::serde::encode_to_vec(&statement, bincode::config::standard()).unwrap()),
                ("trusted-setup.bin", bincode::serde::encode_to_vec(&expected, bincode::config::standard()).unwrap()),
                ("parameters.bin", bincode::serde::encode_to_vec(&(&cfg, parameters), bincode::config::standard()).unwrap()),
                ("fhe-parameters.txt", format!("{native_params:?}").into_bytes()),
            ];
            for (name, bytes) in trusted_artifacts {
                if replay { assert_eq!(std::fs::read(directory.join(name)).unwrap(), bytes); }
                else { artifact(directory, name, &bytes); }
            }
            let parameters_sha256 = digest!((&cfg, parameters));
            let statement_sha256 = digest!(statement);
            let trusted_setup_sha256 = digest!(expected);
            if replay {
                eprintln!("HB_NATIVE_PBS_PHASE replay");
                let bytes = std::fs::read(directory.join("proof.bin")).unwrap();
                let (proof, used): (shared::Proof<F, E, [u8; 32], PcsProof<E, [u8; 32]>, PcsProof<E, [u8; 32]>>, usize) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
                assert_eq!(used, bytes.len());
                shared::verify::<F, E, Sha256, _>(&pp, &expected, &statement, &proof).unwrap();
                assert!(setup.br_oracles(&key).unwrap().iter().all(|o| o.state.spent().unwrap() == 0));
                assert!(setup.ks_oracles(&fkey).unwrap().iter().all(|o| o.state.spent().unwrap() == 0));
                println!("HB_NATIVE_COMPLETE_MASKED_REPLAY {{\"field\":\"{}\",\"proof_sha256\":\"{:x}\",\"proof_bytes\":{},\"statement_sha256\":\"{}\",\"parameters_sha256\":\"{}\",\"trusted_setup_sha256\":\"{}\",\"native_key_roots_sha256\":\"{}\",\"verified\":true,\"original_size\":true,\"complete_pbs\":true,\"whole_security_matched\":false}}",
                    stringify!($f), Sha256::digest(&bytes), bytes.len(), statement_sha256, parameters_sha256, trusted_setup_sha256, native_key_roots_sha256);
                return;
            }
            eprintln!("HB_NATIVE_PBS_PHASE prove");
            let start = Instant::now();
            let mut stats = pbs::ProverStatistics::default();
            let proof = shared::prove_with_statistics::<F, E, Sha256, _, _>(&pp, &setup, &statement, &trace, &mut StdRng::seed_from_u64(942), &mut stats).unwrap();
            let prove_s = start.elapsed().as_secs_f64();
            assert_eq!(proof.protocol_version, 11);
            drop(trace);
            for oracle in setup.br_oracles(&key).unwrap().into_iter().chain(setup.ks_oracles(&fkey).unwrap()) {
                assert_eq!(oracle.state.spent().unwrap(), 1);
                assert_eq!(oracle.state.cached_codeword_elements().unwrap(), 0);
            }
            eprintln!("HB_NATIVE_PBS_PHASE serialize");
            let start = Instant::now();
            let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
            let serialization_s = start.elapsed().as_secs_f64();
            artifact(directory, "proof.bin", &bytes);
            drop(proof);
            let start = Instant::now();
            let (decoded, used): (shared::Proof<F, E, [u8; 32], PcsProof<E, [u8; 32]>, PcsProof<E, [u8; 32]>>, usize) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(used, bytes.len());
            let decode_s = start.elapsed().as_secs_f64();
            eprintln!("HB_NATIVE_PBS_PHASE verify");
            let start = Instant::now();
            shared::verify::<F, E, Sha256, _>(&pp, &expected, &statement, &decoded).unwrap();
            let verify_s = start.elapsed().as_secs_f64();
            let inventory = snarks::packed_root_inventory::canonical_shared_inventory(&decoded);
            let bits = F::MODULUS_VALUE.ilog2() as usize + 1;
            assert_eq!(inventory.total(), 8 * bits.div_ceil(8) + 4 * bits.div_ceil(5) + 16);
            let mut altered = statement.clone();
            altered.output_b += F::from(1usize);
            assert!(shared::verify::<F, E, Sha256, _>(&pp, &expected, &altered, &decoded).is_err());
            let record = format!("HB_NATIVE_COMPLETE_MASKED_PBS {{\"field\":\"{}\",\"protocol_version\":11,\"queries\":128,\"lookup_repetitions\":1,\"ring_dimension\":1024,\"lwe_dimension\":728,\"output_dimension\":728,\"width\":{},\"fhe_parameters_sha256\":\"{}\",\"parameters_sha256\":\"{}\",\"statement_sha256\":\"{}\",\"trusted_setup_sha256\":\"{}\",\"native_key_roots_sha256\":\"{}\",\"proof_sha256\":\"{:x}\",\"proof_bytes\":{},\"root_slots\":{},\"setup_s\":{},\"trace_s\":{},\"prove_s\":{},\"serialization_s\":{},\"decode_s\":{},\"verify_s\":{},\"phase_s\":{:?},\"verified\":true,\"altered_output_rejected\":true,\"complete_pbs\":true,\"original_size\":true,\"transient_cache\":true,\"whole_security_matched\":false,\"hiding_certified\":false,\"performance_gate\":false}}",
                stringify!($f), WIDTH, fhe_parameters_sha256, parameters_sha256, statement_sha256, trusted_setup_sha256, native_key_roots_sha256,
                Sha256::digest(&bytes), bytes.len(), inventory.total(), setup_s, trace_s, prove_s, serialization_s, decode_s, verify_s,
                [stats.preparation, stats.hadamard, stats.ntt, stats.decomposition, stats.accumulator, stats.monomial, stats.key_switch].map(|d| d.as_secs_f64()));
            artifact(directory, "verified-record.json", record.strip_prefix("HB_NATIVE_COMPLETE_MASKED_PBS ").unwrap().as_bytes());
            println!("{record}");
        }
    };
}
profile!(
    babybear,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    BABYBEAR_BINARY_128_BITS_PARAMETERS
);
profile!(
    goldilocks,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    GOLDILOCKS_BINARY_128_BITS_PARAMETERS
);
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    assert_eq!(
        args.len(),
        3,
        "prove|replay babybear|goldilocks artifact-directory"
    );
    assert!(matches!(args[0].as_str(), "prove" | "replay"));
    assert!(matches!(args[1].as_str(), "babybear" | "goldilocks"));
    let replay = args[0] == "replay";
    let directory = Path::new(&args[2]);
    if !replay {
        std::fs::create_dir(directory).unwrap();
    }
    match args[1].as_str() {
        "babybear" => babybear(directory, replay),
        "goldilocks" => goldilocks(directory, replay),
        _ => unreachable!(),
    }
}
