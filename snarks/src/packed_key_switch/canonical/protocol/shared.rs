//! Complete final stage with shared canonical digit comparisons.
//! Trusted explicit selection; public algebra is not a hiding certificate.
pub use super::Parameters;
use super::*;
pub type Proof<F, EF, O, S, B> =
    BackendProof<F, O, S, B, packed_decomposition::canonical::shared::Proof<F, EF, O, S, B>>;
/// Prove original-key products, canonical negative-a digits and extraction.
pub fn prove<F, EF, H, P, R>(
    trans: &mut Transcript<F>,
    pp: &Parameters<'_, P>,
    key: &ProverKey<F, H, P>,
    acc: &[F],
    a: &[F],
    b: F,
    coefficients: &[PackedTable<F>],
    rng: &mut R,
) -> Result<Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>, Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    super::prove_inner::<F, EF, H, P, R, comparison::Shared>(
        trans,
        pp,
        key,
        acc,
        a,
        b,
        coefficients,
        rng,
    )
}
/// Verify using only trusted key/parameters and the original public endpoints.
pub fn verify<F, EF, H, P>(
    trans: &mut Transcript<F>,
    pp: &Parameters<'_, P>,
    key: &ExpectedKey<H::Output>,
    acc: &[F],
    a: &[F],
    b: F,
    proof: &Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    super::verify_inner::<F, EF, H, P, comparison::Shared>(trans, pp, key, acc, a, b, proof)
}
