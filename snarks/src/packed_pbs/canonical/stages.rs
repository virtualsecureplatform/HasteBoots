use super::*;
use crate::packed_decomposition::canonical as per_limb;
use crate::packed_decomposition::canonical::shared as shared_radix;
use crate::packed_key_switch::canonical::protocol as per_limb_key;
use crate::packed_key_switch::canonical::protocol::shared as shared_key;
pub(super) trait Mode {
    const VERSION: u32;
    const DOMAIN: &'static [u8];
}
pub(super) trait Stages<F, EF, H, P>: Mode
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    type Decomposition;
    type KeySwitch;
    fn decompose<R: Rng + CryptoRng>(
        trans: &mut Transcript<F>,
        cfg: &decomp::Config,
        source: &CanonicalProverOracle<'_, F, H, P>,
        borrow: &P,
        helper: &P,
        digits: &[&CanonicalProverOracle<'_, F, H, P>],
        statistics: &mut crate::packed_extension_lookup::ProverStatistics,
        rng: &mut R,
    ) -> Result<Self::Decomposition, Error>;
    fn verify_decomposition(
        trans: &mut Transcript<F>,
        cfg: &decomp::Config,
        source: &CanonicalVerifierOracle<'_, H::Output, P>,
        borrow: &P,
        helper: &P,
        digits: &[CanonicalVerifierOracle<'_, H::Output, P>],
        proof: &Self::Decomposition,
    ) -> Result<(), Error>;
    fn key_switch<R: Rng + CryptoRng>(
        trans: &mut Transcript<F>,
        pp: &final_stage::Parameters<'_, P>,
        key: &ks::canonical::ProverKey<F, H, P>,
        acc: &[F],
        a: &[F],
        b: F,
        coefficients: &[PackedTable<F>],
        rng: &mut R,
    ) -> Result<Self::KeySwitch, Error>;
    fn verify_key_switch(
        trans: &mut Transcript<F>,
        pp: &final_stage::Parameters<'_, P>,
        key: &ks::ExpectedKey<H::Output>,
        acc: &[F],
        a: &[F],
        b: F,
        proof: &Self::KeySwitch,
    ) -> Result<(), Error>;
}
macro_rules! backend {
    ($name:ident,$radix:ident,$key:ident,$version:expr,$domain:expr) => {
        pub(super) struct $name;
        impl Mode for $name {
            const VERSION: u32 = $version;
            const DOMAIN: &'static [u8] = $domain;
        }
        impl<F, EF, H, P> Stages<F, EF, H, P> for $name
        where
            F: NTTField + Serialize,
            EF: AbstractExtensionField<F> + Serialize,
            H: Hash + Send + Sync,
            P: CanonicalPcs<F, H>,
        {
            type Decomposition = $radix::Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>;
            type KeySwitch = $key::Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>;
            fn decompose<R: Rng + CryptoRng>(
                trans: &mut Transcript<F>,
                cfg: &decomp::Config,
                source: &CanonicalProverOracle<'_, F, H, P>,
                borrow: &P,
                helper: &P,
                digits: &[&CanonicalProverOracle<'_, F, H, P>],
                statistics: &mut crate::packed_extension_lookup::ProverStatistics,
                rng: &mut R,
            ) -> Result<Self::Decomposition, Error> {
                $radix::prove_with_statistics::<F, EF, H, P, R>(
                    trans, cfg, source, borrow, helper, digits, statistics, rng,
                )
                .map_err(convert)
            }
            fn verify_decomposition(
                trans: &mut Transcript<F>,
                cfg: &decomp::Config,
                source: &CanonicalVerifierOracle<'_, H::Output, P>,
                borrow: &P,
                helper: &P,
                digits: &[CanonicalVerifierOracle<'_, H::Output, P>],
                proof: &Self::Decomposition,
            ) -> Result<(), Error> {
                $radix::verify::<F, EF, H, P>(trans, cfg, source, borrow, helper, digits, proof)
                    .map_err(convert)
            }
            fn key_switch<R: Rng + CryptoRng>(
                trans: &mut Transcript<F>,
                pp: &final_stage::Parameters<'_, P>,
                key: &ks::canonical::ProverKey<F, H, P>,
                acc: &[F],
                a: &[F],
                b: F,
                coefficients: &[PackedTable<F>],
                rng: &mut R,
            ) -> Result<Self::KeySwitch, Error> {
                $key::prove::<F, EF, H, P, R>(trans, pp, key, acc, a, b, coefficients, rng)
                    .map_err(convert)
            }
            fn verify_key_switch(
                trans: &mut Transcript<F>,
                pp: &final_stage::Parameters<'_, P>,
                key: &ks::ExpectedKey<H::Output>,
                acc: &[F],
                a: &[F],
                b: F,
                proof: &Self::KeySwitch,
            ) -> Result<(), Error> {
                $key::verify::<F, EF, H, P>(trans, pp, key, acc, a, b, proof).map_err(convert)
            }
        }
    };
}
backend!(
    PerLimb,
    per_limb,
    per_limb_key,
    super::PROTOCOL_VERSION,
    b"HasteBoots complete canonical-backend binary NAND PBS v10"
);
backend!(
    Shared,
    shared_radix,
    shared_key,
    11,
    b"HasteBoots complete canonical-backend binary NAND PBS v11"
);
backend!(
    ClassicalShared,
    shared_radix,
    shared_key,
    12,
    b"HasteBoots complete classical-profile binary NAND PBS v12"
);
