//! Complete binary NAND PBS version 11 with shared canonical radix comparisons.
//! Public algebra and backend-selected PCS packets; not a whole-proof security claim.
pub use super::Parameters;
use super::*;
pub const PROTOCOL_VERSION: u32 = 11;
pub type Proof<F, EF, O, S, B> = BackendProof<
    F,
    O,
    S,
    B,
    decomp::canonical::shared::Proof<F, EF, O, S, B>,
    final_stage::shared::Proof<F, EF, O, S, B>,
>;
/// Prove all original PBS stages using shared comparisons in each decomposition.
pub fn prove<F, EF, H, P, R>(
    pp: &Parameters<'_, P>,
    setup: &canonical_setup::ProverSetup<F, H, P>,
    s: &Statement<'_, F>,
    trace: &PBSTrace<F>,
    rng: &mut R,
) -> Result<Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>, Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    prove_with_statistics::<F, EF, H, P, R>(
        pp,
        setup,
        s,
        trace,
        rng,
        &mut ProverStatistics::default(),
    )
}
/// Same phase accounting as version 10; not a security-matched timing certificate.
pub fn prove_with_statistics<F, EF, H, P, R>(
    pp: &Parameters<'_, P>,
    setup: &canonical_setup::ProverSetup<F, H, P>,
    s: &Statement<'_, F>,
    trace: &PBSTrace<F>,
    rng: &mut R,
    stats: &mut ProverStatistics,
) -> Result<Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>, Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    super::prove_inner::<F, EF, H, P, R, stages::Shared>(pp, setup, s, trace, rng, stats, None)
}
/// Verify using only trusted setup/PCS parameters and public input/output ciphertexts.
pub fn verify<F, EF, H, P>(
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<H::Output>,
    s: &Statement<'_, F>,
    proof: &Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    super::verify_inner::<F, EF, H, P, stages::Shared>(pp, setup, s, proof, None)
}
