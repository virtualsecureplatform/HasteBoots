//! Experimental profile-bound complete PBS; versioning is not certification.
//! The complete wire version below is distinct from profile schedules 4/5.
//! Proof-review boundaries and source mapping: `docs/security-proof-guide.md`.
use super::*;
use pcs::{classical_profile::ProfileParameters, utils::hash::Digest512};
use sha2::Sha512;

/// Dedicated complete wire/transcript version for classical-profile plumbing.
pub const PROTOCOL_VERSION: u32 = 12;

/// Complete proof carrying the independently expected profile identifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F: Field, EF: Field, S, B> {
    pub(super) profile_id: Digest512,
    pub(super) payload: shared::Proof<F, EF, Digest512, S, B>,
}

/// Retained public-key preprocessing, bound to its original trusted profile.
pub struct ProverSetup<F, P>
where
    F: NTTField,
    P: CanonicalPcs<F, Sha512>,
{
    profile_id: Digest512,
    pub(super) inner: canonical_setup::ProverSetup<F, Sha512, P>,
}

/// Public setup only: no retained source state or private trace.
#[derive(Clone, Debug, Serialize)]
pub struct VerifierSetup {
    profile_id: Digest512,
    inner: super::super::VerifierSetup<Digest512>,
}

impl<F, P> ProverSetup<F, P>
where
    F: NTTField + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    /// Obtain standalone verification material for this exact profile/key pair.
    pub fn verifier(&self) -> VerifierSetup {
        VerifierSetup {
            profile_id: self.profile_id,
            inner: self.inner.verifier(),
        }
    }
}

pub(super) fn parameters<P>(bundle: &ProfileParameters<P>) -> Parameters<'_, P> {
    let p = bundle.roles();
    Parameters {
        coefficients: &p[0],
        evaluations: &p[0],
        key: &p[0],
        inputs: &p[0],
        borrows: &p[0],
        helper: &p[1],
        accumulators: [&p[0]; 4],
        monomial: &p[0],
        final_stage: final_stage::Parameters {
            coefficients: &p[2],
            evaluations: &p[2],
            key: &p[2],
            input: &p[2],
            borrows: &p[2],
            helper: &p[3],
        },
    }
}

/// Preprocess original public evaluation keys with profile-constructed oracles.
pub fn preprocess<F, EF, P, R>(
    bundle: &ProfileParameters<P>,
    config: Config,
    br: &[NTTRGSW<F>],
    ks: &[NTTGadgetRLWE<F>],
    rng: &mut R,
) -> Result<ProverSetup<F, P>, Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    P: CanonicalPcs<F, Sha512>,
    R: Rng + CryptoRng,
{
    bundle
        .profile()
        .validate_field::<F, EF>()
        .map_err(convert)?;
    let roles = bundle.roles();
    let dimensions = config.variables(roles[0].width())?;
    if roles.iter().zip(dimensions).any(|(p, n)| p.num_vars() != n) {
        return Err(error("profile differs from native PBS dimensions"));
    }
    let inner = canonical_setup::preprocess::<F, Sha512, P, R>(
        &canonical_setup::Parameters {
            source: &roles[0],
            helper: &roles[1],
            final_source: &roles[2],
            final_helper: &roles[3],
        },
        config,
        br,
        ks,
        rng,
    )?;
    Ok(ProverSetup {
        profile_id: bundle.profile().id(),
        inner,
    })
}

/// Prove every native PBS stage with an explicit profile and version-12 framing.
pub fn prove<F, EF, P, R>(
    bundle: &ProfileParameters<P>,
    setup: &ProverSetup<F, P>,
    s: &Statement<'_, F>,
    trace: &PBSTrace<F>,
    rng: &mut R,
) -> Result<Proof<F, EF, P::SingleProof, P::BatchProof>, Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    P: CanonicalPcs<F, Sha512>,
    R: Rng + CryptoRng,
{
    bundle
        .profile()
        .validate_field::<F, EF>()
        .map_err(convert)?;
    let id = bundle.profile().id();
    if id != setup.profile_id {
        return Err(error("classical prover profile mismatch"));
    }
    let transcript = bundle.profile().parent_transcript::<F>().map_err(convert)?;
    let payload = super::prove_inner::<F, EF, Sha512, P, R, stages::ClassicalShared>(
        &parameters(bundle),
        &setup.inner,
        s,
        trace,
        rng,
        &mut ProverStatistics::default(),
        Some(transcript),
    )?;
    Ok(Proof {
        profile_id: id,
        payload,
    })
}

/// Verify from trusted profile parameters, public setup and ciphertexts only.
pub fn verify<F, EF, P>(
    bundle: &ProfileParameters<P>,
    setup: &VerifierSetup,
    s: &Statement<'_, F>,
    proof: &Proof<F, EF, P::SingleProof, P::BatchProof>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    bundle
        .profile()
        .validate_field::<F, EF>()
        .map_err(convert)?;
    let id = bundle.profile().id();
    if id != setup.profile_id || id != proof.profile_id {
        return Err(error("classical verifier profile mismatch"));
    }
    let transcript = bundle.profile().parent_transcript::<F>().map_err(convert)?;
    super::verify_inner::<F, EF, Sha512, P, stages::ClassicalShared>(
        &parameters(bundle),
        &setup.inner,
        s,
        &proof.payload,
        Some(transcript),
    )
}

/// Optional measured verifier oracle interfaces; excluded from default builds.
#[cfg(feature = "transcript-audit")]
pub mod oracle_audit;
