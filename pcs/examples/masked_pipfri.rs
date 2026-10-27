//! Synthetic masked scalar smoke; no PBS or concrete security claim.
use algebra::{
    AbstractExtensionField, DenseMultilinearExtension, NTTField, transformation::AbstractNTT,
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::pipfri::{
    Basis,
    masked::{self, Parameters, Proof, VerifierSession},
};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::time::Instant;

fn run<B, F>(field: &str, vars: usize, fragment_vars: usize, queries: usize, openings: usize)
where
    B: NTTField,
    F: AbstractExtensionField<B> + Serialize + DeserializeOwned,
{
    assert!(fragment_vars > 0 && fragment_vars <= vars && vars < usize::BITS as usize - 1);
    let root = B::generate_ntt_table((fragment_vars + 2) as u32)
        .unwrap()
        .root();
    let pp = Parameters::new(
        1 << fragment_vars,
        1 << (vars - fragment_vars),
        2,
        queries,
        openings,
        F::from_base(root),
        Basis::BooleanEvaluations,
    )
    .unwrap()
    .with_base_field_encoder::<B>()
    .unwrap();
    let data = (0..1usize << vars)
        .map(|i| F::from_base_fn(|j| B::from((i * 17 + 11 + 37 * j) % 100003)))
        .collect::<Vec<_>>();
    let fixture_bytes = bincode::serde::encode_to_vec(&data, bincode::config::standard()).unwrap();
    let fixture_sha256 = format!("{:x}", Sha256::digest(&fixture_bytes));
    drop(fixture_bytes);
    let mle = DenseMultilinearExtension::from_evaluations_vec(vars, data.clone());
    // The fixture is public; masks come from fresh OS-seeded private randomness.
    let mut rng = rand::rng();
    let start = Instant::now();
    let mut session = masked::commit::<F, Sha256, _>(&pp, &data, &mut rng).unwrap();
    let commit_s = start.elapsed().as_secs_f64();
    let root = session.commitment();
    let mut verifier = VerifierSession::<F, Sha256>::new(&pp, root);
    let mut fixture = Transcript::<F>::new_direct_extension::<B>();
    for opening in 0..openings {
        let point = fixture.get_vec_challenge(b"masked PipFRI synthetic point", vars);
        let value = mle.evaluate(&point);
        let mut prover_t = Transcript::<F>::new_direct_extension::<B>();
        let start = Instant::now();
        let proof = session.open(&mut prover_t, &point, value).unwrap();
        let open_s = start.elapsed().as_secs_f64();
        let start = Instant::now();
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let serialization_s = start.elapsed().as_secs_f64();
        let (proof, used): (Proof<F, [u8; 32]>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let mut verifier_t = Transcript::<F>::new_direct_extension::<B>();
        let start = Instant::now();
        verifier
            .verify(&mut verifier_t, &point, value, &proof)
            .unwrap();
        let verify_s = start.elapsed().as_secs_f64();
        assert_eq!(
            prover_t.get_challenge(b"after"),
            verifier_t.get_challenge(b"after")
        );
        println!(
            "{{\"backend\":\"masked-pipfri-reference-v1\",\"security\":\"experimental-unbudgeted\",\"workload\":\"synthetic-boolean-table\",\"field\":\"{field}\",\"fixture_sha256\":\"{fixture_sha256}\",\"vars\":{vars},\"fragment_vars\":{fragment_vars},\"queries\":{queries},\"opening_budget\":{openings},\"opening\":{opening},\"commit_s\":{commit_s},\"open_s\":{open_s},\"serialization_s\":{serialization_s},\"verify_s\":{verify_s},\"proof_bytes\":{},\"verified\":true}}",
            bytes.len()
        );
    }
    assert_eq!(session.remaining_openings(), 0);
    assert_eq!(verifier.remaining_openings(), 0);
}
fn main() {
    let a = std::env::args().collect::<Vec<_>>();
    assert_eq!(
        a.len(),
        6,
        "usage: masked_pipfri babybear-ext5|goldilocks-ext5 vars fragment_vars queries openings"
    );
    let (v, m, q, b) = (
        a[2].parse().unwrap(),
        a[3].parse().unwrap(),
        a[4].parse().unwrap(),
        a[5].parse().unwrap(),
    );
    match a[1].as_str() {
        "babybear-ext5" => run::<algebra::BabyBear, algebra::BabyBearExtension5>(&a[1], v, m, q, b),
        "goldilocks-ext5" => {
            run::<algebra::Goldilocks, algebra::GoldilocksExtension5>(&a[1], v, m, q, b)
        }
        _ => panic!("unknown field"),
    }
}
