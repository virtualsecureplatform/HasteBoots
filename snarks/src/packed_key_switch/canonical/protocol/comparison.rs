use super::*;
use crate::packed_decomposition::canonical::shared;
use crate::packed_decomposition::{Config as Radix, canonical as per_limb};
pub(super) trait Comparison<F, EF, H, P>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    type Proof;
    fn bind(trans: &mut Transcript<F>);
    fn prove<R: Rng + CryptoRng>(
        trans: &mut Transcript<F>,
        cfg: &Radix,
        source: &CanonicalProverOracle<'_, F, H, P>,
        borrow: &P,
        helper: &P,
        digits: &[&CanonicalProverOracle<'_, F, H, P>],
        rng: &mut R,
    ) -> Result<Self::Proof, Error>;
    fn verify(
        trans: &mut Transcript<F>,
        cfg: &Radix,
        source: &CanonicalVerifierOracle<'_, H::Output, P>,
        borrow: &P,
        helper: &P,
        digits: &[CanonicalVerifierOracle<'_, H::Output, P>],
        proof: &Self::Proof,
    ) -> Result<(), Error>;
    #[cfg(test)]
    fn audit_prove<R: Rng + CryptoRng>(
        trans: &mut Transcript<F>,
        cfg: &Radix,
        source: &CanonicalProverOracle<'_, F, H, P>,
        borrow: &P,
        helper: &P,
        digits: &[&CanonicalProverOracle<'_, F, H, P>],
        false_lookup: bool,
        rng: &mut R,
    ) -> Result<Self::Proof, Error>;
    #[cfg(test)]
    fn audit_verify(
        trans: &mut Transcript<F>,
        cfg: &Radix,
        source: &CanonicalVerifierOracle<'_, H::Output, P>,
        borrow: &P,
        helper: &P,
        digits: &[CanonicalVerifierOracle<'_, H::Output, P>],
        proof: &Self::Proof,
    ) -> Result<
        (
            ([bool; 3], bool),
            Vec<Vec<algebra::matrix_weighted::MatrixPair<F>>>,
            Option<crate::packed_extension_lookup::canonical::shared::audit::SourceClaims<F>>,
        ),
        Error,
    >;
}
macro_rules! backend {
    ($name:ident,$module:ident,$domain:expr) => {
        pub(super) struct $name;
        impl<F, EF, H, P> Comparison<F, EF, H, P> for $name
        where
            F: NTTField + Serialize,
            EF: AbstractExtensionField<F> + Serialize,
            H: Hash + Send + Sync,
            P: CanonicalPcs<F, H>,
        {
            type Proof = $module::Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>;
            fn bind(trans: &mut Transcript<F>) {
                let domain: Option<&[u8]> = $domain;
                if let Some(domain) = domain {
                    trans.append_message(domain, &());
                }
            }
            fn prove<R: Rng + CryptoRng>(
                trans: &mut Transcript<F>,
                cfg: &Radix,
                source: &CanonicalProverOracle<'_, F, H, P>,
                borrow: &P,
                helper: &P,
                digits: &[&CanonicalProverOracle<'_, F, H, P>],
                rng: &mut R,
            ) -> Result<Self::Proof, Error> {
                $module::prove::<F, EF, H, P, R>(trans, cfg, source, borrow, helper, digits, rng)
                    .map_err(convert)
            }
            fn verify(
                trans: &mut Transcript<F>,
                cfg: &Radix,
                source: &CanonicalVerifierOracle<'_, H::Output, P>,
                borrow: &P,
                helper: &P,
                digits: &[CanonicalVerifierOracle<'_, H::Output, P>],
                proof: &Self::Proof,
            ) -> Result<(), Error> {
                $module::verify::<F, EF, H, P>(trans, cfg, source, borrow, helper, digits, proof)
                    .map_err(convert)
            }
            #[cfg(test)]
            fn audit_prove<R: Rng + CryptoRng>(
                trans: &mut Transcript<F>,
                cfg: &Radix,
                source: &CanonicalProverOracle<'_, F, H, P>,
                borrow: &P,
                helper: &P,
                digits: &[&CanonicalProverOracle<'_, F, H, P>],
                false_lookup: bool,
                rng: &mut R,
            ) -> Result<Self::Proof, Error> {
                if false_lookup {
                    $module::audit::prove_false_lookup::<F, EF, H, P, R>(
                        trans, cfg, source, borrow, helper, digits, rng,
                    )
                } else {
                    $module::audit::prove::<F, EF, H, P, R>(
                        trans, cfg, source, borrow, helper, digits, rng,
                    )
                }
                .map_err(convert)
            }
            #[cfg(test)]
            fn audit_verify(
                trans: &mut Transcript<F>,
                cfg: &Radix,
                source: &CanonicalVerifierOracle<'_, H::Output, P>,
                borrow: &P,
                helper: &P,
                digits: &[CanonicalVerifierOracle<'_, H::Output, P>],
                proof: &Self::Proof,
            ) -> Result<
                (
                    ([bool; 3], bool),
                    Vec<Vec<algebra::matrix_weighted::MatrixPair<F>>>,
                    Option<
                        crate::packed_extension_lookup::canonical::shared::audit::SourceClaims<F>,
                    >,
                ),
                Error,
            > {
                $module::audit::verify_queries::<F, EF, H, P>(
                    trans, cfg, source, borrow, helper, digits, proof,
                )
                .map_err(convert)
            }
        }
    };
}
backend!(PerLimb, per_limb, None);
backend!(
    Shared,
    shared,
    Some(b"canonical shared-comparison final key switch v1")
);
