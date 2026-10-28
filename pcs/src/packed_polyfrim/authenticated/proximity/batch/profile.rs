//! Opt-in process resource control, not a masked-PCS security benchmark.
use super::*;
use algebra::{
    AbstractExtensionField, NTTField,
    matrix_weighted::{Matrix, PackedTable},
    transformation::AbstractNTT,
};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

fn run<B, E>(mode: &str, count: usize)
where
    B: NTTField + Serialize,
    E: AbstractExtensionField<B> + Serialize + DeserializeOwned,
{
    let variables = 15;
    let width = 2;
    let pp = Parameters::new(
        1 << variables,
        width,
        4,
        8,
        E::from_base(B::generate_ntt_table(variables as u32 + 2).unwrap().root()),
    )
    .unwrap()
    .with_base_field_encoder::<B>()
    .unwrap();
    let table = PackedTable::new(
        variables,
        width,
        (0..(1 << variables) * width)
            .map(|i| E::from_base_fn(|j| B::from(17 * i + 9 * i * j + 13 * j + 1)))
            .collect(),
    )
    .unwrap();
    let base =
        super::super::super::commit::<E, Sha256>(&pp, Polynomial::from_table(&table).unwrap())
            .unwrap();
    let mut coins = Transcript::<E>::new_direct_extension::<B>();
    let queries: Vec<Vec<_>> = (0..count)
        .map(|_| {
            (0..variables)
                .map(|_| {
                    let v = coins.get_vec_challenge(b"resource dense matrices", 2 * width * width);
                    MatrixPair {
                        zero: Matrix::new(width, v[..width * width].to_vec()).unwrap(),
                        one: Matrix::new(width, v[width * width..].to_vec()).unwrap(),
                    }
                })
                .collect()
        })
        .collect();
    let alphas: Vec<_> = (0..count)
        .map(|_| coins.get_challenge(b"resource source scale"))
        .collect();
    let roots: Vec<_> = alphas
        .iter()
        .enumerate()
        .map(|(i, alpha)| hash::<Sha256, _>(&(b"resource virtual source", base.root(), i, alpha)))
        .collect();
    let claims: Vec<Vec<_>> = queries
        .iter()
        .zip(&alphas)
        .map(|(q, alpha)| {
            table
                .evaluate(q)
                .unwrap()
                .into_iter()
                .map(|v| (v * *alpha).canonicalized())
                .collect()
        })
        .collect();
    let source = |i: usize| {
        let mut tree = MerkleTree::<Sha256>::new();
        tree.root = roots[i];
        State {
            polynomial: Polynomial {
                width,
                coefficients: base
                    .polynomial
                    .coefficients
                    .iter()
                    .map(|v| (*v * alphas[i]).canonicalized())
                    .collect(),
            },
            values: std::sync::OnceLock::from(
                base.values()
                    .iter()
                    .map(|v| (*v * alphas[i]).canonicalized())
                    .collect::<Vec<_>>(),
            ),
            encoding: pp.clone(),
            tree,
            context: base.context,
            layer: 0,
        }
    };
    let mut t = Transcript::<E>::new_direct_extension::<B>();
    let proof = if mode == "retained" {
        let sources: Vec<_> = (0..count).map(source).collect();
        let refs: Vec<_> = sources.iter().collect();
        prove_sources::<E, Sha256>(&mut t, &pp, &base.root(), &refs, &queries, &claims)
            .unwrap()
            .0
    } else {
        prove_generated_sources::<E, Sha256>(&mut t, &pp, &base.root(), &queries, &claims, source)
            .unwrap()
            .0
    };
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (decoded, used): (Proof<E, [u8; 32]>, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut v = Transcript::<E>::new_direct_extension::<B>();
    verify_sources::<E, Sha256>(
        &mut v,
        &pp,
        &base.root(),
        &roots,
        &queries,
        &claims,
        &decoded,
        true,
        |member, index, pair| {
            let position = index / 2;
            let expected: Vec<_> = base.values()[position * 2 * width..(position + 1) * 2 * width]
                .iter()
                .map(|value| (*value * alphas[member]).canonicalized())
                .collect();
            if pair.values != expected || !pair.path.is_empty() {
                return Err(Error("resource initial virtual source"));
            }
            Ok(())
        },
    )
    .unwrap();
    let mut after = [0u8; 32];
    let mut verifier_after = [0u8; 32];
    t.get_challenge_bytes(b"resource proof after", &mut after);
    v.get_challenge_bytes(b"resource proof after", &mut verifier_after);
    assert_eq!(after, verifier_after);
    let hwm = std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmHWM:")
                .map(|v| v.split_whitespace().next().unwrap().parse::<u64>().unwrap())
        })
        .unwrap();
    println!(
        "HB_GENERATED_SOURCE_RESOURCE {{\"prime\":{},\"extension_degree\":{},\"variables\":{},\"width\":{},\"blowup\":4,\"queries\":8,\"batch_size\":{},\"mode\":\"{}\",\"proof_bytes\":{},\"proof_sha256\":\"{:x}\",\"fixture_sha256\":\"{:x}\",\"transcript_sha256\":\"{:x}\",\"peak_rss_kib\":{},\"verified\":true,\"complete_pbs\":false,\"original_size\":false,\"whole_security_matched\":false,\"performance_gate\":false}}",
        B::MODULUS_VALUE,
        E::D,
        variables,
        width,
        count,
        mode,
        bytes.len(),
        Sha256::digest(&bytes),
        Sha256::digest(
            bincode::serde::encode_to_vec(
                (&pp, base.root(), &roots, &queries, &claims),
                bincode::config::standard()
            )
            .unwrap()
        ),
        Sha256::digest(after),
        hwm
    );
}

#[test]
#[ignore = "manual separate-process source memory control"]
fn generated_source_resource_profile() {
    let mode = std::env::var("HB_SOURCE_MODE").unwrap();
    assert!(matches!(mode.as_str(), "retained" | "generated"));
    let count = std::env::var("HB_SOURCE_BATCH").unwrap().parse().unwrap();
    assert!([1, 4, 16].contains(&count));
    match std::env::var("HB_SOURCE_FIELD").unwrap().as_str() {
        "babybear" => run::<algebra::BabyBear, algebra::BabyBearExtension6>(&mode, count),
        "goldilocks" => run::<algebra::Goldilocks, algebra::GoldilocksExtension3>(&mode, count),
        _ => panic!("unsupported field"),
    }
}
