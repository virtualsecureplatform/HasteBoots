//! Synthetic lookup-only profiling; not a complete PBS or security comparison.
use algebra::{
    AbstractExtensionField, BabyBear, BabyBearExtension5, Goldilocks, GoldilocksExtension5,
    NTTField, PrimeField, matrix_weighted::PackedTable,
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted::Parameters,
    utils::code::{BlockReedSolomonCode, RowCode},
};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_extension_lookup as extension, packed_lane_lookup as lanes, packed_oracle::ProverOracle,
    packed_tuple_lookup::Config,
};
use std::time::Instant;

fn run<F, EF>(variables: usize, backend: &str, field: &str)
where
    F: PrimeField + NTTField + Serialize + DeserializeOwned + From<usize>,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    assert!(
        (1..=18).contains(&variables),
        "source variables must be 1..=18"
    );
    let width = 8;
    let count = (1usize << variables) * width;
    // A real borrow-transition table for one radix-256 decomposition limb.
    let tuples = snarks::packed_decomposition::Config::new::<F>(8, count, 1)
        .unwrap()
        .comparison_table::<F>(0)
        .unwrap();
    let columns: Vec<_> = (0..3)
        .map(|j| {
            PackedTable::new(
                variables,
                width,
                (0..count)
                    .map(|row| tuples[row % tuples.len()][j])
                    .collect(),
            )
            .unwrap()
        })
        .collect();
    let source =
        Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(variables, width, 544, 2).unwrap();
    let helper =
        Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(variables + 3, width, 544, 2)
            .unwrap();
    let (roots, states): (Vec<_>, Vec<_>) = columns
        .iter()
        .map(|t| source.commit::<F, Sha256>(t).unwrap())
        .unzip();
    let oracles: Vec<_> = columns
        .iter()
        .zip(&roots)
        .zip(&states)
        .map(|((table, commitment), state)| ProverOracle {
            parameters: &source,
            table,
            commitment,
            state,
        })
        .collect();
    let private: Vec<_> = oracles.iter().collect();
    let public: Vec<_> = oracles.iter().map(|o| o.verifier()).collect();
    let repetitions = if backend == "extension" { 1 } else { 16 };
    let config = Config::new(count, tuples, repetitions).unwrap();
    let mut statistics = lanes::ProverStatistics::default();
    let mut prover = Transcript::new_direct();
    prover.append_message(
        b"synthetic lookup profiling v1",
        &(field, backend, variables),
    );
    let mut verifier = Transcript::new_direct();
    verifier.append_message(
        b"synthetic lookup profiling v1",
        &(field, backend, variables),
    );
    let timer = Instant::now();
    let (bytes, prove_ns, verify_ns) = if backend == "extension" {
        let proof = extension::prove_with_statistics::<F, EF, Sha256, _>(
            &mut prover,
            &config,
            &helper,
            &private,
            &mut statistics,
        )
        .unwrap();
        let prove_ns = timer.elapsed().as_nanos();
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (extension::Proof<F, EF, [u8; 32]>, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let timer = Instant::now();
        extension::verify::<F, EF, Sha256, _>(&mut verifier, &config, &helper, &public, &proof)
            .unwrap();
        let verify_ns = timer.elapsed().as_nanos();
        assert_eq!(
            prover.get_challenge(b"after"),
            verifier.get_challenge(b"after")
        );
        (bytes, prove_ns, verify_ns)
    } else {
        let proof = lanes::prove_with_statistics::<F, Sha256, _>(
            &mut prover,
            &config,
            &helper,
            &private,
            &mut statistics,
        )
        .unwrap();
        let prove_ns = timer.elapsed().as_nanos();
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (lanes::Proof<F, [u8; 32]>, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let timer = Instant::now();
        lanes::verify::<F, Sha256, _>(&mut verifier, &config, &helper, &public, &proof).unwrap();
        let verify_ns = timer.elapsed().as_nanos();
        assert_eq!(
            prover.get_challenge(b"after"),
            verifier.get_challenge(b"after")
        );
        (bytes, prove_ns, verify_ns)
    };
    println!(
        "HB_EXTENSION_LOOKUP {{\"kind\":\"synthetic-borrow-transition-lookup\",\"field\":\"{field}\",\"backend\":\"{backend}\",\"source_variables\":{variables},\"width\":{width},\"logical_len\":{count},\"tuple_columns\":3,\"public_table_len\":512,\"extension_degree\":{},\"repetitions\":{repetitions},\"queries\":544,\"source_left_vars\":{},\"helper_left_vars\":{},\"source_row_message_blocks\":{},\"source_row_encoded_blocks\":{},\"helper_row_message_blocks\":{},\"helper_row_encoded_blocks\":{},\"proof_bytes\":{},\"prove_ns\":{prove_ns},\"verify_ns\":{verify_ns},\"preparation_ns\":{},\"commitment_ns\":{},\"sumcheck_ns\":{},\"zero_check_ns\":{},\"terminal_evaluation_ns\":{},\"openings_ns\":{},\"verified\":true}}",
        if backend == "extension" { EF::D } else { 1 },
        source.left_vars(),
        helper.left_vars(),
        source.code().message_blocks(),
        source.code().codeword_blocks(),
        helper.code().message_blocks(),
        helper.code().codeword_blocks(),
        bytes.len(),
        statistics.preparation.as_nanos(),
        statistics.commitment.as_nanos(),
        statistics.sumcheck.as_nanos(),
        statistics.zero_check.as_nanos(),
        statistics.terminal_evaluation.as_nanos(),
        statistics.openings.as_nanos()
    );
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert!(
        args.len() == 3,
        "usage: extension_lookup babybear|goldilocks extension|lanes SOURCE_VARIABLES"
    );
    assert!(
        matches!(args[1].as_str(), "extension" | "lanes"),
        "unknown backend"
    );
    let variables = args[2].parse().expect("integer source variables");
    match args[0].as_str() {
        "babybear" => run::<BabyBear, BabyBearExtension5>(variables, &args[1], &args[0]),
        "goldilocks" => run::<Goldilocks, GoldilocksExtension5>(variables, &args[1], &args[0]),
        _ => panic!("unknown field"),
    }
}
