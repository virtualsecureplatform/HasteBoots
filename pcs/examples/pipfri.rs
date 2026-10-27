//! Synthetic scalar-table smoke; not a PBS or security-matched comparison.
use algebra::{
    AbstractExtensionField, DenseMultilinearExtension, Field, NTTField, transformation::AbstractNTT,
};
use helper::{
    FiatShamirTranscript, Transcript,
    transcript::{DIRECT_EXTENSION_TRANSCRIPT_ID, DIRECT_TRANSCRIPT_ID},
};
use pcs::pipfri::{self, Basis, Parameters, Proof};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use std::time::Instant;

struct Settings {
    vars: usize,
    fragment_vars: usize,
    queries: usize,
    runs: usize,
}
fn domain_root<F: NTTField>(vars: usize) -> F {
    let log = (vars + 1).max(5);
    let mut root = F::generate_ntt_table(log as u32).unwrap().root();
    for _ in vars + 1..log {
        root *= root;
    }
    root
}
fn run<F: Field + Serialize + DeserializeOwned>(
    field: &str,
    cfg: &Settings,
    root: F,
    from_index: fn(usize) -> F,
    transcript: fn() -> Transcript<F>,
    transcript_id: &str,
    encoder: (&str, fn(Parameters<F>) -> Parameters<F>),
) {
    let Settings {
        vars,
        fragment_vars,
        queries,
        runs,
    } = *cfg;
    let m = 1usize << fragment_vars;
    let pp = (encoder.1)(
        Parameters::new(
            m,
            1 << (vars - fragment_vars),
            2,
            queries,
            root,
            Basis::BooleanEvaluations,
        )
        .unwrap(),
    );
    let encoder_name = encoder.0;
    let data: Vec<F> = (0..1usize << vars).map(from_index).collect();
    // Uniform points in the actual scalar field, including all extension
    // coordinates. Separate fixture transcript; neither proof transcript is
    // consumed before the scalar opening binds its statement.
    let point = transcript().get_vec_challenge(b"ordinary PipFRI benchmark point", vars);
    let value =
        DenseMultilinearExtension::from_evaluations_vec(vars, data.clone()).evaluate(&point);
    for run in 0..runs {
        let start = Instant::now();
        let s = pipfri::commit::<F, Sha256>(&pp, &data).unwrap();
        let commit_s = start.elapsed().as_secs_f64();
        let expected = s.commitment();
        let mut prover = transcript();
        let start = Instant::now();
        let proof = pipfri::open(&mut prover, &pp, &expected, &s, &point, value).unwrap();
        let open_s = start.elapsed().as_secs_f64();
        let start = Instant::now();
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let serialization_s = start.elapsed().as_secs_f64();
        let (decoded, used): (Proof<F, [u8; 32]>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let mut verifier = transcript();
        let start = Instant::now();
        pipfri::verify::<F, Sha256>(&mut verifier, &pp, &expected, &point, value, &decoded)
            .unwrap();
        let verify_s = start.elapsed().as_secs_f64();
        assert_eq!(
            prover.get_challenge(b"after"),
            verifier.get_challenge(b"after")
        );
        println!(
            "{{\"backend\":\"ordinary-pipfri-reference-v1\",\"security\":\"experimental-unbudgeted\",\"workload\":\"synthetic-boolean-table-uniform-point\",\"field\":\"{field}\",\"transcript\":\"{transcript_id}\",\"encoder\":\"{encoder_name}\",\"vars\":{vars},\"fragment_vars\":{fragment_vars},\"blowup\":2,\"queries\":{queries},\"run\":{run},\"commit_s\":{commit_s},\"open_s\":{open_s},\"serialization_s\":{serialization_s},\"verify_s\":{verify_s},\"proof_bytes\":{},\"verified\":true}}",
            bytes.len()
        );
    }
}
fn prime<F: NTTField + Serialize + DeserializeOwned>(field: &str, cfg: &Settings) {
    run(
        field,
        cfg,
        domain_root::<F>(cfg.fragment_vars),
        |i| F::from((i * 17 + 11) % 100003),
        Transcript::<F>::new_direct,
        DIRECT_TRANSCRIPT_ID,
        ("generic", |pp| pp),
    );
}
fn extension<Base: NTTField, EF: AbstractExtensionField<Base> + Serialize + DeserializeOwned>(
    field: &str,
    cfg: &Settings,
) {
    run(
        field,
        cfg,
        EF::from_base(domain_root::<Base>(cfg.fragment_vars)),
        |i| EF::from_base_fn(|j| Base::from((i * 17 + 11 + 37 * j) % 100003)),
        Transcript::<EF>::new_direct_extension::<Base>,
        DIRECT_EXTENSION_TRANSCRIPT_ID,
        ("coordinate-base", |pp| {
            pp.with_base_field_encoder::<Base>().unwrap()
        }),
    );
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        6,
        "usage: pipfri babybear|goldilocks|babybear-ext4|goldilocks-ext2|babybear-ext8|goldilocks-ext4|babybear-ext5|goldilocks-ext5 vars fragment_vars queries runs"
    );
    let cfg = Settings {
        vars: args[2].parse().unwrap(),
        fragment_vars: args[3].parse().unwrap(),
        queries: args[4].parse().unwrap(),
        runs: args[5].parse().unwrap(),
    };
    assert!(
        cfg.runs > 0
            && cfg.fragment_vars > 0
            && cfg.fragment_vars <= cfg.vars
            && cfg.vars < (usize::BITS - 1) as usize
    );
    match args[1].as_str() {
        "babybear" => prime::<algebra::BabyBear>(&args[1], &cfg),
        "goldilocks" => prime::<algebra::Goldilocks>(&args[1], &cfg),
        "babybear-ext4" => {
            extension::<algebra::BabyBear, algebra::BabyBearExetension>(&args[1], &cfg)
        }
        "goldilocks-ext2" => {
            extension::<algebra::Goldilocks, algebra::GoldilocksExtension>(&args[1], &cfg)
        }
        "babybear-ext8" => {
            extension::<algebra::BabyBear, algebra::BabyBearExtension8>(&args[1], &cfg)
        }
        "goldilocks-ext4" => {
            extension::<algebra::Goldilocks, algebra::GoldilocksExtension4>(&args[1], &cfg)
        }
        "babybear-ext5" => {
            extension::<algebra::BabyBear, algebra::BabyBearExtension5>(&args[1], &cfg)
        }
        "goldilocks-ext5" => {
            extension::<algebra::Goldilocks, algebra::GoldilocksExtension5>(&args[1], &cfg)
        }
        _ => panic!("unknown field"),
    }
}
