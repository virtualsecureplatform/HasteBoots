//! Test-only stage adapters; production entry points retain their strict checks.
use super::*;
use crate::packed_decomposition::canonical::audit as per_limb;
use crate::packed_decomposition::canonical::shared::audit as shared_radix;
use crate::packed_key_switch::canonical::protocol::audit as key_audit;
pub(super) trait AuditStages<F, EF, H, P>: stages::Stages<F, EF, H, P>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    fn audit_decompose<R: Rng + CryptoRng>(
        trans: &mut Transcript<F>,
        cfg: &decomp::Config,
        source: &CanonicalProverOracle<'_, F, H, P>,
        borrow: &P,
        helper: &P,
        digits: &[&CanonicalProverOracle<'_, F, H, P>],
        false_lookup: bool,
        rng: &mut R,
    ) -> Result<Self::Decomposition, Error>;
    fn audit_verify_decomposition(
        trans: &mut Transcript<F>,
        cfg: &decomp::Config,
        source: &CanonicalVerifierOracle<'_, H::Output, P>,
        borrow: &P,
        helper: &P,
        digits: &[CanonicalVerifierOracle<'_, H::Output, P>],
        proof: &Self::Decomposition,
    ) -> Result<
        (
            ([bool; 3], bool),
            Vec<Vec<algebra::matrix_weighted::MatrixPair<F>>>,
            Option<crate::packed_extension_lookup::canonical::shared::audit::SourceClaims<F>>,
        ),
        Error,
    >;
    fn audit_key_switch<R: Rng + CryptoRng>(
        trans: &mut Transcript<F>,
        pp: &final_stage::Parameters<'_, P>,
        key: &ks::canonical::ProverKey<F, H, P>,
        acc: &[F],
        a: &[F],
        b: F,
        actual_a: &[F],
        actual_b: F,
        coefficients: &[PackedTable<F>],
        foreign_key: bool,
        false_lookup: bool,
        rng: &mut R,
    ) -> Result<Self::KeySwitch, Error>;
    fn audit_verify_key_switch(
        trans: &mut Transcript<F>,
        pp: &final_stage::Parameters<'_, P>,
        key: &ks::ExpectedKey<H::Output>,
        acc: &[F],
        a: &[F],
        b: F,
        proof: &Self::KeySwitch,
    ) -> Result<((bool, bool, [bool; 3], bool), key_audit::FinalQueries<F>), Error>;
}
macro_rules! adapter {
    ($name:ident,$radix:ident,$key_prove:ident,$key_verify:ident) => {
        impl<F, EF, H, P> AuditStages<F, EF, H, P> for stages::$name
        where
            F: NTTField + Serialize,
            EF: AbstractExtensionField<F> + Serialize,
            H: Hash + Send + Sync,
            P: CanonicalPcs<F, H>,
        {
            fn audit_decompose<R: Rng + CryptoRng>(
                trans: &mut Transcript<F>,
                cfg: &decomp::Config,
                source: &CanonicalProverOracle<'_, F, H, P>,
                borrow: &P,
                helper: &P,
                digits: &[&CanonicalProverOracle<'_, F, H, P>],
                false_lookup: bool,
                rng: &mut R,
            ) -> Result<Self::Decomposition, Error> {
                if false_lookup {
                    $radix::prove_false_lookup::<F, EF, H, P, R>(
                        trans, cfg, source, borrow, helper, digits, rng,
                    )
                } else {
                    $radix::prove::<F, EF, H, P, R>(trans, cfg, source, borrow, helper, digits, rng)
                }
                .map_err(convert)
            }
            fn audit_verify_decomposition(
                trans: &mut Transcript<F>,
                cfg: &decomp::Config,
                source: &CanonicalVerifierOracle<'_, H::Output, P>,
                borrow: &P,
                helper: &P,
                digits: &[CanonicalVerifierOracle<'_, H::Output, P>],
                proof: &Self::Decomposition,
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
                $radix::verify_queries::<F, EF, H, P>(
                    trans, cfg, source, borrow, helper, digits, proof,
                )
                .map_err(convert)
            }
            fn audit_key_switch<R: Rng + CryptoRng>(
                trans: &mut Transcript<F>,
                pp: &final_stage::Parameters<'_, P>,
                key: &ks::canonical::ProverKey<F, H, P>,
                acc: &[F],
                a: &[F],
                b: F,
                actual_a: &[F],
                actual_b: F,
                coefficients: &[PackedTable<F>],
                foreign_key: bool,
                false_lookup: bool,
                rng: &mut R,
            ) -> Result<Self::KeySwitch, Error> {
                key_audit::$key_prove::<F, EF, H, P, R>(
                    trans,
                    pp,
                    key,
                    acc,
                    a,
                    b,
                    actual_a,
                    actual_b,
                    coefficients,
                    foreign_key,
                    false_lookup,
                    rng,
                )
                .map_err(convert)
            }
            fn audit_verify_key_switch(
                trans: &mut Transcript<F>,
                pp: &final_stage::Parameters<'_, P>,
                key: &ks::ExpectedKey<H::Output>,
                acc: &[F],
                a: &[F],
                b: F,
                proof: &Self::KeySwitch,
            ) -> Result<((bool, bool, [bool; 3], bool), key_audit::FinalQueries<F>), Error> {
                key_audit::$key_verify::<F, EF, H, P>(trans, pp, key, acc, a, b, proof)
                    .map_err(convert)
            }
        }
    };
}
adapter!(PerLimb, per_limb, prove_foreign, verify_queries);
adapter!(Shared, shared_radix, prove_shared, verify_shared_queries);
adapter!(
    ClassicalShared,
    shared_radix,
    prove_shared,
    verify_shared_queries
);
