//! Existing scalar LogUp SNARK, using the opt-in masked PipFRI adapter.
use algebra::{AbstractExtensionField, NTTField};
use helper::{FiatShamirTranscript, Transcript};
use pcs::multilinear::masked_pipfri::{MaskedPipFRIPCS, Specification};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::lookup::unindexed_small_table::{LogUpParams, LogUpSnarks};
use trace::lookup_trace::small_table::{LookupTrace, LookupTraceMLE};
fn exercise<F, EF>()
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    for vars in [3, 5, 8] {
        let trace = LookupTrace {
            num_vars: vars,
            num_vec: 2,
            range: 8,
            vec_input: (0..2)
                .map(|j| {
                    (0..1 << vars)
                        .map(|i| F::from((3 * i + 7 * j) % 8))
                        .collect()
                })
                .collect(),
        };
        let trace: LookupTraceMLE<F> = trace.into();
        let snark = LogUpSnarks::<F, EF, Specification, MaskedPipFRIPCS<F, EF, Sha256>>::default();
        let mut params = LogUpParams::new(Specification::new(9, 2, 1, 8).unwrap(), 2, &trace);
        let mut prover = Transcript::new_direct_extension::<F>();
        let proof = snark.prove(&mut prover, trace, &mut params);
        let mut verifier = Transcript::new_direct_extension::<F>();
        assert!(snark.verify(&mut verifier, &proof));
        assert_eq!(
            prover.get_challenge(b"after scalar SNARK"),
            verifier.get_challenge(b"after scalar SNARK")
        );
        let mut bad = proof;
        bad.eval_trace_proof.low_degree.terminal += EF::one();
        assert!(!snark.verify(&mut Transcript::new_direct_extension::<F>(), &bad));
    }
}
#[test]
fn babybear_logup_with_masked_pipfri() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension5>();
}
#[test]
fn goldilocks_logup_with_masked_pipfri() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension5>();
}
