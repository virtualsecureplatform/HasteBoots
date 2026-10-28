//! Original native-key setup with public test seeds; not a complete PBS proof.
use algebra::{
    matrix_weighted::{Matrix, MatrixPair},
    utils::{Block, Prg},
};
use fhe_core::SecretKeyPack;
use helper::{FiatShamirTranscript, Transcript};
use pcs::matrix_weighted::masked_polyfrim::joint::{Parameters, Proof};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};
use snarks::packed_pbs::{Config, canonical_setup};
use std::time::Instant;
use vfhe::bfhe::{
    BABYBEAR_BINARY_128_BITS_PARAMETERS, Evaluator, GOLDILOCKS_BINARY_128_BITS_PARAMETERS,
};

fn resident_kib() -> Option<usize> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
}
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
macro_rules! profile {
    ($name:ident, $f:ty, $e:ty, $width:expr, $native:ident, $br:expr, $ks:expr) => {
        fn $name(transient: bool) {
            type F = $f;
            type E = $e;
            const WIDTH: usize = $width;
            let cfg = Config::new::<F>(1024, 728, 8, 5, 1, 1).unwrap();
            let dims = cfg.variables(WIDTH).unwrap();
            let make = |vars| {
                let pp = (vars..24).find_map(|physical| Parameters::<F, E>::new(vars, WIDTH, physical, 2, 128, 1).ok()).unwrap();
                if transient { pp.with_transient_source_values() } else { pp }
            };
            let source = make(dims[0]);
            let helper = make(dims[1]);
            let final_source = make(dims[2]);
            let final_helper = make(dims[3]);
            let native_params = *$native;
            let native_parameters_sha256 = format!("{:x}", Sha256::digest(format!("{native_params:?}")));
            let start = Instant::now();
            let sk = SecretKeyPack::with_rng(native_params, Prg::from_seed(Block::from([42u8; 16])));
            let evaluator = Evaluator::new(&sk);
            let keygen_s = start.elapsed().as_secs_f64();
            let mut rng = StdRng::seed_from_u64(941);
            let start = Instant::now();
            let setup = canonical_setup::preprocess::<F, Sha256, _, _>(
                &canonical_setup::Parameters { source: &source, helper: &helper, final_source: &final_source, final_helper: &final_helper },
                cfg.clone(), evaluator.binary_bootstrap_key().unwrap(),
                evaluator.rlwe_key_switching_key().unwrap().as_slice(), &mut rng,
            ).unwrap();
            let setup_s = start.elapsed().as_secs_f64();
            let setup_rss = resident_kib();
            let rng_tail = rng.next_u64();
            let br = setup.br_oracles(&source).unwrap();
            let ks = setup.ks_oracles(&final_source).unwrap();
            assert_eq!((br.len(), ks.len()), ($br, $ks));
            let roots = br.iter().chain(&ks).map(|o| o.commitment.root).collect::<Vec<_>>();
            let tables = br.iter().chain(&ks).map(|o| digest!(o.table())).collect::<Vec<_>>();
            let cache_before = br.iter().chain(&ks).map(|o| o.state.cached_codeword_elements().unwrap()).sum::<usize>();
            assert!(br.iter().chain(&ks).all(|o| o.state.spent().unwrap() == 0));
            if transient { assert_eq!(cache_before, 0); } else { assert!(cache_before > 0); }
            let mut packet_hashes = Vec::new();
            let mut transcript_hashes = Vec::new();
            let mut packet_bytes = Vec::new();
            let start = Instant::now();
            for oracle in [&br[0], &ks[0]] {
                let mut coins = Transcript::<F>::new_direct();
                let query = (0..oracle.parameters.num_vars()).map(|_| {
                    let v = coins.get_vec_challenge(b"native setup dense matrices", 2 * WIDTH * WIDTH);
                    MatrixPair {
                        zero: Matrix::new(WIDTH, v[..WIDTH * WIDTH].to_vec()).unwrap(),
                        one: Matrix::new(WIDTH, v[WIDTH * WIDTH..].to_vec()).unwrap(),
                    }
                }).collect::<Vec<_>>();
                let claim = oracle.table().evaluate(&query).unwrap();
                let queries = vec![query];
                let claims = vec![claim];
                let mut pt = Transcript::new_direct();
                let proof = oracle.parameters.open_many::<Sha256>(&mut pt, oracle.commitment, oracle.state, &queries, &claims).unwrap();
                let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
                let (decoded, used): (Proof<E, [u8; 32]>, usize) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
                assert_eq!(used, bytes.len());
                let mut vt = Transcript::new_direct();
                oracle.parameters.verify_many::<Sha256>(&mut vt, oracle.commitment, &queries, &claims, &decoded).unwrap();
                let after = pt.get_challenge(b"native setup opening after");
                assert_eq!(after, vt.get_challenge(b"native setup opening after"));
                packet_hashes.push(format!("{:x}", Sha256::digest(&bytes)));
                transcript_hashes.push(digest!(after));
                packet_bytes.push(bytes.len());
            }
            let opening_roundtrips_s = start.elapsed().as_secs_f64();
            let opened_rss = resident_kib();
            let cache_after = br.iter().chain(&ks).map(|o| o.state.cached_codeword_elements().unwrap()).sum::<usize>();
            assert_eq!(cache_before, cache_after);
            for owners in [&br, &ks] {
                for (i, oracle) in owners.iter().enumerate() { assert_eq!(oracle.state.spent().unwrap(), usize::from(i == 0)); }
            }
            println!("HB_NATIVE_MASKED_SETUP {{\"field\":\"{}\",\"transient\":{},\"ring_dimension\":1024,\"lwe_dimension\":728,\"queries\":128,\"budget\":1,\"br_sources\":{},\"ks_sources\":{},\"logical_vars\":{:?},\"physical_vars\":{:?},\"native_parameters_sha256\":\"{}\",\"parameters_sha256\":\"{}\",\"native_tables_sha256\":\"{}\",\"roots_sha256\":\"{}\",\"proof_sha256\":{:?},\"transcript_sha256\":{:?},\"proof_bytes\":{:?},\"rng_tail\":{},\"cache_before_elements\":{},\"cache_after_elements\":{},\"setup_rss_kib\":{},\"opened_rss_kib\":{},\"keygen_s\":{},\"setup_s\":{},\"opening_roundtrips_s\":{},\"verified\":true,\"native_keys\":true,\"complete_pbs\":false,\"whole_security_matched\":false}}",
                stringify!($f), transient, br.len(), ks.len(), dims,
                [source.physical_vars(), helper.physical_vars(), final_source.physical_vars(), final_helper.physical_vars()],
                native_parameters_sha256, digest!((&cfg, &source, &helper, &final_source, &final_helper)), digest!(tables), digest!(roots),
                packet_hashes, transcript_hashes, packet_bytes, rng_tail, cache_before, cache_after,
                setup_rss.map_or("null".to_owned(), |v| v.to_string()), opened_rss.map_or("null".to_owned(), |v| v.to_string()),
                keygen_s, setup_s, opening_roundtrips_s);
        }
    };
}
profile!(
    babybear,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    BABYBEAR_BINARY_128_BITS_PARAMETERS,
    8,
    7
);
profile!(
    goldilocks,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    GOLDILOCKS_BINARY_128_BITS_PARAMETERS,
    16,
    13
);
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    assert_eq!(args.len(), 2, "babybear|goldilocks retained|transient");
    let transient = match args[1].as_str() {
        "retained" => false,
        "transient" => true,
        _ => panic!("unknown cache policy"),
    };
    match args[0].as_str() {
        "babybear" => babybear(transient),
        "goldilocks" => goldilocks(transient),
        _ => panic!("unknown field"),
    }
}
