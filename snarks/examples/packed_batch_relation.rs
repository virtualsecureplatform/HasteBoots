//! Independent packed relations: separate certificates versus joint authentication.
//! Component benchmark only; this is not complete cross-statement PBS.
use algebra::{AbstractExtensionField, NTTField, matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted::Parameters,
    utils::code::{BlockReedSolomonCode, RowCode},
};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use snarks::packed_relation::{ProverStatistics, aggregate, batch};
use std::time::Instant;
use sumcheck::packed::PackedShape;

fn run<F, EF>(field: &str, k: usize, n: usize, reverse: bool)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(n, k, 544, 2).unwrap();
    for count in [1, 4, 16] {
        let timer = Instant::now();
        let capacity = (1 << n) * k;
        let mut fixture = Transcript::<F>::new_direct();
        fixture.append_message(b"shared relation benchmark fixture", &(n, k, count));
        let mut factors = Vec::new();
        let mut shapes = Vec::new();
        for instance in 0..count {
            let a = fixture.get_vec_challenge(b"factor a", capacity);
            let b = fixture.get_vec_challenge(b"factor b", capacity);
            let coefficient = F::from(instance + 1);
            let c = a
                .iter()
                .zip(&b)
                .map(|(&a, &b)| coefficient * a * b)
                .collect();
            factors.push(vec![
                PackedTable::new(n, k, a).unwrap(),
                PackedTable::new(n, k, b).unwrap(),
                PackedTable::new(n, k, c).unwrap(),
            ]);
            shapes.push(PackedShape {
                num_vars: n,
                width: k,
                num_factors: 3,
                terms: vec![(coefficient, vec![0, 1]), (-F::one(), vec![2])],
            });
        }
        let pairs: Vec<Vec<_>> = factors
            .iter()
            .map(|f| {
                f.iter()
                    .map(|t| pp.commit::<F, Sha256>(t).unwrap())
                    .collect()
            })
            .collect();
        let roots: Vec<Vec<_>> = pairs
            .iter()
            .map(|p| p.iter().map(|(root, _)| root.clone()).collect())
            .collect();
        let states: Vec<Vec<_>> = pairs
            .iter()
            .map(|p| p.iter().map(|(_, state)| state).collect())
            .collect();
        let tables: Vec<_> = factors.iter().map(Vec::as_slice).collect();
        let setup_ns = timer.elapsed().as_nanos();
        let statement = bincode::serde::encode_to_vec(
            &(pp.context_digest::<F, Sha256>().unwrap(), &shapes, &roots),
            bincode::config::standard(),
        )
        .unwrap();
        let statement_sha256 = format!("{:x}", Sha256::digest(&statement));
        let transcript = || {
            let mut t = Transcript::new_direct();
            t.append_message(b"requested relation batch", &statement);
            t
        };
        for joint in if reverse {
            [true, false]
        } else {
            [false, true]
        } {
            macro_rules! certificate {
                ($prove:expr,$ty:ty,$verify:expr) => {{
                    let timer = Instant::now();
                    let proof = $prove;
                    let prove_ns = timer.elapsed().as_nanos();
                    let timer = Instant::now();
                    let bytes =
                        bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
                    let serialization_ns = timer.elapsed().as_nanos();
                    let proof_bytes = bytes.len();
                    let proof_sha256 = format!("{:x}", Sha256::digest(&bytes));
                    drop(proof);
                    let timer = Instant::now();
                    let (proof, used): ($ty, _) =
                        bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                            .unwrap();
                    assert_eq!(used, proof_bytes);
                    let deserialize_ns = timer.elapsed().as_nanos();
                    let timer = Instant::now();
                    ($verify)(&proof);
                    let verify_ns = timer.elapsed().as_nanos();
                    (
                        prove_ns,
                        serialization_ns,
                        deserialize_ns,
                        verify_ns,
                        proof_bytes,
                        proof_sha256,
                    )
                }};
            }
            let (prove_ns, serialization_ns, deserialize_ns, verify_ns, proof_bytes, proof_sha256) =
                if joint {
                    certificate!(batch::prove::<F,EF,Sha256,_>(&mut transcript(),&shapes,&pp,&tables,&roots,&states).unwrap(),batch::Proof<F,EF,[u8;32]>,
                    |proof|batch::verify::<F,EF,Sha256,_>(&mut transcript(),&shapes,&pp,&roots,proof).unwrap())
                } else {
                    certificate!(
                        {
                            let mut trans = transcript();
                            (0..count)
                                .map(|i| {
                                    aggregate::prove_with_state_references::<F, EF, Sha256, _>(
                                        &mut trans,
                                        &shapes[i],
                                        &pp,
                                        &factors[i],
                                        &roots[i],
                                        &states[i],
                                        &mut ProverStatistics::default(),
                                    )
                                    .unwrap()
                                })
                                .collect::<Vec<_>>()
                        },
                        Vec<aggregate::Proof<F, EF, [u8; 32]>>,
                        |proof: &Vec<aggregate::Proof<F, EF, [u8; 32]>>| {
                            assert_eq!(proof.len(), count);
                            let mut trans = transcript();
                            for i in 0..count {
                                aggregate::verify::<F, EF, Sha256, _>(
                                    &mut trans, &shapes[i], &pp, &roots[i], &proof[i],
                                )
                                .unwrap();
                            }
                        }
                    )
                };
            let mode = if joint { "joint" } else { "separate" };
            let complete_ns = prove_ns + serialization_ns;
            println!(
                "HB_BATCH_RELATION {{\"scope\":\"independent-relations-shared-challenge-pcs\",\"field\":\"{field}\",\"mode\":\"{mode}\",\"instances\":{count},\"roots\":{},\"extension_degree\":{},\"variables\":{n},\"width\":{k},\"left_vars\":{},\"message_blocks\":{},\"encoded_blocks\":{},\"queries\":544,\"reverse\":{reverse},\"setup_ns\":{setup_ns},\"prove_ns\":{prove_ns},\"serialization_ns\":{serialization_ns},\"complete_ns\":{complete_ns},\"deserialize_ns\":{deserialize_ns},\"verify_ns\":{verify_ns},\"proof_bytes\":{proof_bytes},\"proof_sha256\":\"{proof_sha256}\",\"statement_sha256\":\"{statement_sha256}\",\"verified\":true,\"whole_proof_security_certified\":false}}",
                3 * count,
                EF::D,
                pp.left_vars(),
                pp.code().message_blocks(),
                pp.code().codeword_blocks()
            );
        }
    }
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let full = args.iter().any(|s| s == "--full");
    let reverse = args.iter().any(|s| s == "--reverse");
    if args.iter().any(|s| s == "--goldilocks") {
        run::<algebra::Goldilocks, algebra::GoldilocksExtension3>(
            "goldilocks",
            4,
            if full { 19 } else { 5 },
            reverse,
        );
    } else {
        run::<algebra::BabyBear, algebra::BabyBearExtension6>(
            "babybear",
            8,
            if full { 18 } else { 4 },
            reverse,
        );
    }
}
