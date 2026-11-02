use std::marker::PhantomData;

use rand::SeedableRng;
use serde::Serialize;

use algebra::{AbstractExtensionField, AsFrom, AsInto, Field, PrimeField};

use algebra::utils::{Block, Prg};

use crate::FiatShamirTranscript;
use crate::classical_transcript::ClassicalTranscript;

/// Explicit framed SHAKE256 sampling protocol; not a security certificate.
pub const CLASSICAL_TRANSCRIPT_ID: &str = "framed-shake256-canonical-rejection-v1";

/// Direct prime-field sampling protocol identifier.
pub const DIRECT_TRANSCRIPT_ID: &str = "merlin-direct-canonical-rejection-v1";
/// Direct polynomial-basis extension-field sampling protocol identifier.
pub const DIRECT_EXTENSION_TRANSCRIPT_ID: &str = "merlin-direct-extension-canonical-rejection-v1";
const EXTENSION_DOMAIN: &[u8] = b"HasteBoots direct-extension transcript v1";
const DIRECT_DOMAIN: &[u8] = b"HasteBoots direct-field transcript v1";
const STREAM_LABEL: &[u8] = b"direct canonical field stream";
const STREAM_BLOCK: usize = 256;

#[derive(Clone, Copy)]
enum Sampling<F> {
    LegacyPrg128,
    Direct,
    Extension(fn(&mut merlin::Transcript, &'static [u8], usize, &[u8]) -> Vec<F>),
}

struct ParentBinding {
    profile: [u8; 64],
    checkpoint: [u8; 64],
    label: &'static [u8],
}

/// Versioned field transcript: legacy Merlin constructors or explicit SHAKE256.
pub struct Transcript<F: Field> {
    transcript: merlin::Transcript,
    sampling: Sampling<F>,
    classical_parent: Option<ParentBinding>,
    atomic_ntt_rows: bool,
    atomic_joint_projections: bool,
    atomic_zerocheck: bool,
    atomic_brakedown_columns: bool,
    classical: Option<(
        ClassicalTranscript,
        fn(&mut ClassicalTranscript, &'static [u8], usize, &[u8]) -> Vec<F>,
    )>,
    _marker: PhantomData<F>,
}

impl<F: Field> Transcript<F> {
    /// Optional analysis event; never transcript data or a runtime limit.
    #[cfg(feature = "transcript-audit")]
    pub fn audit_resource_event(&self, event: crate::classical_transcript::audit::ResourceEvent) {
        if let Some((classical, _)) = &self.classical {
            classical.audit_resource_event(event);
        }
    }
    /// Create a new IOP transcript.
    #[inline]
    pub fn new() -> Self {
        Self {
            transcript: merlin::Transcript::new(b""),
            sampling: Sampling::LegacyPrg128,
            classical_parent: None,
            atomic_ntt_rows: false,
            atomic_joint_projections: false,
            atomic_zerocheck: false,
            atomic_brakedown_columns: false,
            classical: None,
            _marker: PhantomData,
        }
    }
    /// Use versioned, direct transcript bytes with canonical rejection sampling.
    /// The default constructor keeps the legacy AES-seeded protocol unchanged.
    pub fn new_direct() -> Self
    where
        F: PrimeField,
    {
        Self {
            transcript: merlin::Transcript::new(DIRECT_DOMAIN),
            sampling: Sampling::Direct,
            classical_parent: None,
            atomic_ntt_rows: false,
            atomic_joint_projections: false,
            atomic_zerocheck: false,
            atomic_brakedown_columns: false,
            classical: None,
            _marker: PhantomData,
        }
    }

    /// Sample every polynomial-basis coefficient independently and uniformly
    /// over a prime base field, directly from Merlin bytes. The constructor
    /// binds the base characteristic, extension degree, and the complete basis
    /// multiplication table; different extension representations are separated.
    /// This is a distinct protocol from both legacy and direct prime sampling.
    /// It assumes the supplied algebra traits describe a valid field extension;
    /// uniform sampling alone does not establish protocol security.
    pub fn new_direct_extension<Base: PrimeField>() -> Self
    where
        F: AbstractExtensionField<Base>,
    {
        assert!(F::D > 0, "extension degree must be positive");
        let mut transcript = merlin::Transcript::new(EXTENSION_DOMAIN);
        let p: u128 = Base::MODULUS_VALUE.as_into();
        transcript.append_message(b"extension characteristic", &p.to_le_bytes());
        transcript.append_message(
            b"extension degree",
            &u64::try_from(F::D).expect("degree fits u64").to_le_bytes(),
        );
        // Canonical fixed-width integers avoid relying on a field's serde or
        // internal Montgomery/lazy representation for its mathematical identity.
        let mut products = Vec::new();
        for i in 0..F::D {
            for j in 0..F::D {
                let product = F::monomial(i) * F::monomial(j);
                let coefficients = product.as_base_slice();
                assert!(
                    coefficients.len() <= F::D,
                    "invalid extension basis representation"
                );
                for k in 0..F::D {
                    let value: u128 = coefficients
                        .get(k)
                        .copied()
                        .unwrap_or_else(Base::zero)
                        .value()
                        .as_into();
                    products.extend_from_slice(&value.to_le_bytes());
                }
            }
        }
        transcript.append_message(b"extension basis products", &products);
        Self {
            transcript,
            sampling: Sampling::Extension(extension_values::<Base, F>),
            classical_parent: None,
            atomic_ntt_rows: false,
            atomic_joint_projections: false,
            atomic_zerocheck: false,
            atomic_brakedown_columns: false,
            classical: None,
            _marker: PhantomData,
        }
    }

    /// Select the new prime-field protocol with an independently trusted profile.
    /// Existing constructors continue to select their original protocols.
    pub fn new_classical(profile: &[u8; 64]) -> Self
    where
        F: PrimeField,
    {
        let mut value = Self::new();
        let mut bytes = ClassicalTranscript::new(b"HasteBoots typed classical prime v1", profile);
        let p: u128 = F::MODULUS_VALUE.as_into();
        bytes.append_bytes(b"typed prime field", &p.to_le_bytes());
        value.classical = Some((bytes, classical_prime::<F>));
        value
    }

    /// Select the new extension-field protocol, binding its full basis before
    /// any caller challenge through a zero-element identity phase.
    pub fn new_classical_extension<Base: PrimeField>(profile: &[u8; 64]) -> Self
    where
        F: AbstractExtensionField<Base>,
    {
        let mut value = Self::new();
        let mut bytes =
            ClassicalTranscript::new(b"HasteBoots typed classical extension v1", profile);
        bytes
            .challenge_extension::<Base, F>(b"typed extension identity", 0)
            .expect("trusted extension field identity");
        value.classical = Some((bytes, classical_extension::<Base, F>));
        value
    }

    /// Whether this transcript uses the explicitly selected classical byte engine.
    pub fn is_classical(&self) -> bool {
        self.classical.is_some()
    }

    /// Opt-in schedule: draw the complete NTT row-point block in one phase.
    /// Existing classical constructors retain their original schedules.
    pub fn new_classical_atomic_ntt(profile: &[u8; 64]) -> Self
    where
        F: PrimeField,
    {
        let mut value = Self::new_classical(profile);
        value.atomic_ntt_rows = true;
        value
            .classical
            .as_mut()
            .expect("classical engine")
            .0
            .append_bytes(b"classical challenge schedule", b"atomic NTT row phase v2");
        value
    }

    /// Version-three schedule: atomic NTT rows and joint PolyFRIM projections.
    pub fn new_classical_atomic_phases(profile: &[u8; 64]) -> Self
    where
        F: PrimeField,
    {
        let mut value = Self::new_classical_atomic_ntt(profile);
        value.atomic_joint_projections = true;
        value
            .classical
            .as_mut()
            .expect("classical engine")
            .0
            .append_bytes(
                b"classical challenge schedule",
                b"atomic joint projections v3",
            );
        value
    }

    /// Version four also groups packed ZeroCheck equality and first-round coins.
    pub fn new_classical_atomic_zerocheck(profile: &[u8; 64]) -> Self
    where
        F: PrimeField,
    {
        let mut value = Self::new_classical_atomic_phases(profile);
        value.atomic_zerocheck = true;
        value
            .classical
            .as_mut()
            .expect("classical engine")
            .0
            .append_bytes(
                b"classical challenge schedule",
                b"atomic packed zerocheck v4",
            );
        value
    }

    /// Version five also draws a complete Brakedown column block atomically.
    pub fn new_classical_atomic_columns(profile: &[u8; 64]) -> Self
    where
        F: PrimeField,
    {
        let mut value = Self::new_classical_atomic_zerocheck(profile);
        value.atomic_brakedown_columns = true;
        value
            .classical
            .as_mut()
            .expect("classical engine")
            .0
            .append_bytes(
                b"classical challenge schedule",
                b"atomic Brakedown columns v5",
            );
        value
    }

    /// Whether the trusted schedule groups all Brakedown column indices.
    pub fn uses_atomic_brakedown_columns(&self) -> bool {
        self.atomic_brakedown_columns
    }

    /// Selected by the trusted profile; previous schedules keep separate phases.
    pub fn uses_atomic_zerocheck(&self) -> bool {
        self.atomic_zerocheck
    }

    /// Selected by a trusted versioned profile, including for extension children.
    pub fn uses_atomic_joint_projections(&self) -> bool {
        self.atomic_joint_projections
    }

    /// Selected by a trusted versioned profile, never inferred from a proof.
    pub fn uses_atomic_ntt_rows(&self) -> bool {
        self.atomic_ntt_rows
    }

    /// Start a detached extension child whose finalization checks parent lineage.
    /// Classical protocol callers must finish it before advancing the parent.
    pub fn fork_classical_extension<Base: PrimeField, EF: AbstractExtensionField<Base>>(
        &mut self,
        label: &'static [u8],
        context: &[u8],
    ) -> Result<Transcript<EF>, &'static str> {
        let (parent, _) = self.classical.as_mut().ok_or("classical parent required")?;
        let mut bytes = parent.fork_child(label, context);
        let binding = ParentBinding {
            profile: parent.profile_id(),
            checkpoint: parent.checkpoint(),
            label,
        };
        bytes
            .challenge_extension::<Base, EF>(b"typed extension identity", 0)
            .expect("trusted extension identity");
        let mut child = Transcript::<EF>::new();
        child.classical = Some((bytes, classical_extension::<Base, EF>));
        child.classical_parent = Some(binding);
        child.atomic_ntt_rows = self.atomic_ntt_rows;
        child.atomic_joint_projections = self.atomic_joint_projections;
        child.atomic_zerocheck = self.atomic_zerocheck;
        child.atomic_brakedown_columns = self.atomic_brakedown_columns;
        Ok(child)
    }

    /// Absorb a linked child's finish fingerprint exactly once. A wrong or
    /// advanced parent rejects without changing either transcript.
    pub fn finish_classical_child<EF: Field>(
        &mut self,
        child: &mut Transcript<EF>,
    ) -> Result<(), &'static str> {
        let binding = child
            .classical_parent
            .as_ref()
            .ok_or("missing or spent child binding")?;
        let (parent, _) = self.classical.as_mut().ok_or("classical parent required")?;
        let (bytes, _) = child.classical.as_mut().ok_or("classical child required")?;
        if parent.profile_id() != binding.profile
            || bytes.profile_id() != binding.profile
            || parent.checkpoint() != binding.checkpoint
        {
            return Err("classical child parent mismatch");
        }
        parent.finish_linked_child(binding.label, bytes);
        child.classical_parent = None;
        Ok(())
    }

    /// Run a scoped extension-field child without permitting an implicit
    /// downgrade to Merlin. Legacy parents reject before transcript mutation.
    /// The closure is trusted protocol code; replacing its transcript with a
    /// legacy instance is a programmer error and panics at finalization.
    pub fn with_classical_extension_child<Base, EF, R>(
        &mut self,
        label: &[u8],
        context: &[u8],
        run: impl FnOnce(&mut Transcript<EF>) -> R,
    ) -> Result<R, &'static str>
    where
        Base: PrimeField,
        EF: AbstractExtensionField<Base>,
    {
        let atomic_columns = self.atomic_brakedown_columns;
        let (parent, _) = self
            .classical
            .as_mut()
            .ok_or("classical child requires a classical parent")?;
        Ok(parent.with_owned_child(label, context, |mut bytes| {
            bytes
                .challenge_extension::<Base, EF>(b"typed extension identity", 0)
                .expect("trusted extension field identity");
            let mut child = Transcript::<EF>::new();
            child.classical = Some((bytes, classical_extension::<Base, EF>));
            if atomic_columns {
                child.atomic_ntt_rows = true;
                child.atomic_joint_projections = true;
                child.atomic_zerocheck = true;
                child.atomic_brakedown_columns = true;
            }
            let result = run(&mut child);
            let (bytes, _) = child
                .classical
                .take()
                .expect("classical child mode must remain fixed");
            (bytes, result)
        }))
    }

    fn direct_values(&mut self, label: &'static [u8], count: usize, kind: &[u8]) -> Vec<F> {
        let p: u128 = F::MODULUS_VALUE.as_into();
        // Fixed encodings, independent of rand's distribution implementation.
        self.transcript.append_message(b"direct request kind", kind);
        self.transcript
            .append_message(b"direct request label", label);
        self.transcript
            .append_message(b"direct field characteristic", &p.to_le_bytes());
        self.transcript.append_message(
            b"direct field count",
            &u64::try_from(count)
                .expect("challenge count fits u64")
                .to_le_bytes(),
        );
        let sampler = CanonicalSampler::new(p);
        let mut reader = DirectReader {
            transcript: &mut self.transcript,
            bytes: [0; STREAM_BLOCK],
            cursor: STREAM_BLOCK,
        };
        (0..count)
            .map(|_| {
                F::new(F::Value::as_from(
                    sampler.sample(&mut |out| reader.read(out)),
                ))
            })
            .collect()
    }

    /// Sample one complete index phase in classical mode. Existing modes keep
    /// their original sequence of eight-byte requests without extra framing.
    pub fn get_index_challenges(
        &mut self,
        label: &'static [u8],
        domain: usize,
        count: usize,
    ) -> Result<Vec<usize>, &'static str> {
        if !domain.is_power_of_two() || count.checked_mul(8).is_none() {
            return Err("invalid index phase dimensions");
        }
        if let Some((bytes, _)) = &mut self.classical {
            return bytes.challenge_indices(label, domain, count);
        }
        Ok((0..count)
            .map(|_| {
                let mut bytes = [0; 8];
                self.get_challenge_bytes(label, &mut bytes);
                (u64::from_le_bytes(bytes) & (domain as u64 - 1)) as usize
            })
            .collect())
    }
}

impl<F: Field> FiatShamirTranscript<F> for Transcript<F> {
    /// Append the message to the transcript.
    fn append_message<M: Serialize>(&mut self, label: &'static [u8], msg: &M) {
        if let Some((bytes, _)) = &mut self.classical {
            bytes
                .append_message(label, msg)
                .expect("serializable public message");
            return;
        }
        self.transcript.append_message(
            label,
            &bincode::serde::encode_to_vec(msg, bincode::config::standard()).unwrap(),
        );
    }

    /// Generate the challenge bytes from the current transcript
    #[inline]
    fn get_challenge_bytes(&mut self, label: &'static [u8], bytes: &mut [u8]) {
        if let Some((transcript, _)) = &mut self.classical {
            transcript.challenge_bytes(label, bytes);
            return;
        }
        self.transcript.challenge_bytes(label, bytes);
    }

    /// Generate the challenge from the current transcript
    fn get_challenge(&mut self, label: &'static [u8]) -> F {
        if let Some((bytes, sample)) = &mut self.classical {
            return sample(bytes, label, 1, b"scalar")[0];
        }
        if matches!(self.sampling, Sampling::Direct) {
            return self.direct_values(label, 1, b"scalar")[0];
        }
        if let Sampling::Extension(sample) = self.sampling {
            return sample(&mut self.transcript, label, 1, b"scalar")[0];
        }
        let mut seed = [0u8; 16];
        self.transcript.challenge_bytes(label, &mut seed);
        let mut prg = Prg::from_seed(Block::from(seed));
        F::random(&mut prg)
    }

    /// Generate the challenge vector from the current transcript
    fn get_vec_challenge(&mut self, label: &'static [u8], num: usize) -> Vec<F> {
        if let Some((bytes, sample)) = &mut self.classical {
            return sample(bytes, label, num, b"vector");
        }
        if matches!(self.sampling, Sampling::Direct) {
            return self.direct_values(label, num, b"vector");
        }
        if let Sampling::Extension(sample) = self.sampling {
            return sample(&mut self.transcript, label, num, b"vector");
        }
        let mut seed = [0u8; 16];
        self.transcript.challenge_bytes(label, &mut seed);
        let mut prg = Prg::from_seed(Block::from(seed));
        (0..num).map(|_| F::random(&mut prg)).collect()
    }
}

fn classical_prime<F: PrimeField>(
    t: &mut ClassicalTranscript,
    label: &'static [u8],
    count: usize,
    kind: &[u8],
) -> Vec<F> {
    t.append_bytes(b"typed request kind", kind);
    t.challenge_prime(label, count)
}
fn classical_extension<Base: PrimeField, F: AbstractExtensionField<Base>>(
    t: &mut ClassicalTranscript,
    label: &'static [u8],
    count: usize,
    kind: &[u8],
) -> Vec<F> {
    t.append_bytes(b"typed request kind", kind);
    t.challenge_extension::<Base, F>(label, count)
        .expect("trusted extension challenge dimensions")
}

impl<F: Field> Default for Transcript<F> {
    fn default() -> Self {
        Self::new()
    }
}

fn extension_values<Base: PrimeField, EF: AbstractExtensionField<Base>>(
    transcript: &mut merlin::Transcript,
    label: &'static [u8],
    count: usize,
    kind: &[u8],
) -> Vec<EF> {
    transcript.append_message(b"extension request kind", kind);
    transcript.append_message(b"extension request label", label);
    transcript.append_message(
        b"extension value count",
        &u64::try_from(count)
            .expect("challenge count fits u64")
            .to_le_bytes(),
    );
    let sampler = CanonicalSampler::new(Base::MODULUS_VALUE.as_into());
    let mut reader = DirectReader {
        transcript,
        bytes: [0; STREAM_BLOCK],
        cursor: STREAM_BLOCK,
    };
    // Consume bytes in explicit ascending basis order, independently of how
    // an extension implementation might order calls to from_base_fn.
    let mut coefficients = vec![Base::zero(); EF::D];
    (0..count)
        .map(|_| {
            for coefficient in &mut coefficients {
                *coefficient = Base::new(Base::Value::as_from(
                    sampler.sample(&mut |out| reader.read(out)),
                ));
            }
            EF::from_base_slice(&coefficients)
        })
        .collect()
}

pub(crate) struct CanonicalSampler {
    p: u128,
    mask: u128,
    bytes: usize,
}
impl CanonicalSampler {
    pub(crate) fn new(p: u128) -> Self {
        assert!(p > 1, "field characteristic must exceed one");
        let bits = u128::BITS - (p - 1).leading_zeros();
        Self {
            p,
            mask: if bits == 128 {
                u128::MAX
            } else {
                (1u128 << bits) - 1
            },
            bytes: bits.div_ceil(8) as usize,
        }
    }
    pub(crate) fn sample(&self, read: &mut impl FnMut(&mut [u8])) -> u128 {
        loop {
            let mut bytes = [0u8; 16];
            read(&mut bytes[..self.bytes]);
            let value = u128::from_le_bytes(bytes) & self.mask;
            if value < self.p {
                return value;
            }
        }
    }
}

struct DirectReader<'a> {
    transcript: &'a mut merlin::Transcript,
    bytes: [u8; STREAM_BLOCK],
    cursor: usize,
}
impl DirectReader<'_> {
    fn read(&mut self, mut out: &mut [u8]) {
        while !out.is_empty() {
            if self.cursor == STREAM_BLOCK {
                self.transcript
                    .challenge_bytes(STREAM_LABEL, &mut self.bytes);
                self.cursor = 0;
            }
            let take = out.len().min(STREAM_BLOCK - self.cursor);
            out[..take].copy_from_slice(&self.bytes[self.cursor..self.cursor + take]);
            self.cursor += take;
            out = &mut out[take..];
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn atomic_column_schedule_is_opt_in_and_inherited() {
        let mut parent = Transcript::<BabyBear>::new_classical_atomic_columns(&[76; 64]);
        assert!(parent.uses_atomic_brakedown_columns());
        assert!(parent.uses_atomic_zerocheck());
        assert!(
            !Transcript::<BabyBear>::new_classical_atomic_zerocheck(&[76; 64])
                .uses_atomic_brakedown_columns()
        );
        let mut child = parent
            .fork_classical_extension::<BabyBear, algebra::BabyBearExtension6>(
                b"columns", b"context",
            )
            .unwrap();
        assert!(child.uses_atomic_brakedown_columns());
        parent.finish_classical_child(&mut child).unwrap();
        assert!(
            parent
                .with_classical_extension_child::<BabyBear, algebra::BabyBearExtension6, _>(
                    b"scoped columns",
                    b"context",
                    |child| child.uses_atomic_brakedown_columns() && child.uses_atomic_zerocheck()
                )
                .unwrap()
        );
    }

    #[test]
    fn atomic_zerocheck_schedule_is_inherited_and_keeps_v3_separate() {
        let mut parent = Transcript::<BabyBear>::new_classical_atomic_zerocheck(&[75; 64]);
        assert!(parent.uses_atomic_ntt_rows());
        assert!(parent.uses_atomic_joint_projections());
        assert!(parent.uses_atomic_zerocheck());
        assert!(
            !Transcript::<BabyBear>::new_classical_atomic_phases(&[75; 64]).uses_atomic_zerocheck()
        );
        let mut child = parent
            .fork_classical_extension::<BabyBear, algebra::BabyBearExtension6>(
                b"zero child",
                b"context",
            )
            .unwrap();
        assert!(child.uses_atomic_zerocheck());
        parent.finish_classical_child(&mut child).unwrap();
    }
    #[test]
    fn atomic_phase_schedule_is_inherited_without_changing_old_flags() {
        let mut parent = Transcript::<BabyBear>::new_classical_atomic_phases(&[74; 64]);
        assert!(parent.uses_atomic_ntt_rows());
        assert!(parent.uses_atomic_joint_projections());
        assert!(
            !Transcript::<BabyBear>::new_classical_atomic_ntt(&[74; 64])
                .uses_atomic_joint_projections()
        );
        assert!(!Transcript::<BabyBear>::new_classical(&[74; 64]).uses_atomic_joint_projections());
        let mut child = parent
            .fork_classical_extension::<BabyBear, algebra::BabyBearExtension6>(
                b"phase child",
                b"context",
            )
            .unwrap();
        assert!(child.uses_atomic_ntt_rows());
        assert!(child.uses_atomic_joint_projections());
        parent.finish_classical_child(&mut child).unwrap();
    }
    #[test]
    fn atomic_ntt_schedule_is_explicit_and_inherited() {
        use crate::Transcript;
        use algebra::{BabyBear, BabyBearExtension6};
        let mut parent = Transcript::<BabyBear>::new_classical_atomic_ntt(&[73; 64]);
        assert!(parent.uses_atomic_ntt_rows());
        assert!(!Transcript::<BabyBear>::new_classical(&[73; 64]).uses_atomic_ntt_rows());
        let mut child = parent
            .fork_classical_extension::<BabyBear, BabyBearExtension6>(b"atomic child", b"context")
            .unwrap();
        assert!(child.uses_atomic_ntt_rows());
        parent.finish_classical_child(&mut child).unwrap();
    }
    use super::*;
    use algebra::{BabyBear, Goldilocks};

    #[test]
    fn linked_children_reject_wrong_advanced_and_spent_parents() {
        type E = algebra::BabyBearExtension6;
        let mut parent = Transcript::<BabyBear>::new_classical(&[1; 64]);
        let mut child = parent
            .fork_classical_extension::<BabyBear, E>(b"child", b"context")
            .unwrap();
        let mut wrong = Transcript::<BabyBear>::new_classical(&[2; 64]);
        assert!(wrong.finish_classical_child(&mut child).is_err());
        child.get_challenge(b"point");
        parent.finish_classical_child(&mut child).unwrap();
        assert!(parent.finish_classical_child(&mut child).is_err());
        let mut parent = Transcript::<BabyBear>::new_classical(&[1; 64]);
        let mut child = parent
            .fork_classical_extension::<BabyBear, E>(b"child", b"context")
            .unwrap();
        parent.append_message(b"unexpected parent progress", &1u64);
        assert!(parent.finish_classical_child(&mut child).is_err());
    }

    #[test]
    fn index_phase_preserves_legacy_requests_and_uses_classical_block() {
        let mut actual = Transcript::<BabyBear>::new_direct();
        let mut reference = Transcript::<BabyBear>::new_direct();
        let got = actual.get_index_challenges(b"indices", 32, 17).unwrap();
        let expected: Vec<_> = (0..17)
            .map(|_| {
                let mut bytes = [0; 8];
                reference.get_challenge_bytes(b"indices", &mut bytes);
                (u64::from_le_bytes(bytes) & 31) as usize
            })
            .collect();
        assert_eq!(got, expected);
        let mut a = [0; 64];
        let mut b = [0; 64];
        actual.get_challenge_bytes(b"after", &mut a);
        reference.get_challenge_bytes(b"after", &mut b);
        assert_eq!(a, b);
        let profile = [2; 64];
        let mut actual = Transcript::<BabyBear>::new_classical(&profile);
        let mut reference =
            ClassicalTranscript::new(b"HasteBoots typed classical prime v1", &profile);
        let p: u128 = BabyBear::MODULUS_VALUE.as_into();
        reference.append_bytes(b"typed prime field", &p.to_le_bytes());
        assert!(actual.get_index_challenges(b"indices", 3, 17).is_err());
        assert_eq!(
            actual.get_index_challenges(b"indices", 32, 17).unwrap(),
            reference.challenge_indices(b"indices", 32, 17).unwrap()
        );
        actual.get_challenge_bytes(b"after", &mut a);
        reference.challenge_bytes(b"after", &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn classical_typed_child_matches_byte_link_and_legacy_rejects_unchanged() {
        type E = algebra::BabyBearExtension6;
        let profile = [8; 64];
        let mut typed = Transcript::<BabyBear>::new_classical(&profile);
        let mut bytes = ClassicalTranscript::new(b"HasteBoots typed classical prime v1", &profile);
        let p: u128 = BabyBear::MODULUS_VALUE.as_into();
        bytes.append_bytes(b"typed prime field", &p.to_le_bytes());
        let got = typed
            .with_classical_extension_child::<BabyBear, E, _>(b"lookup", b"root/context", |child| {
                child.append_message(b"message", &42u64);
                child.get_vec_challenge(b"points", 4)
            })
            .unwrap();
        let expected = bytes.with_child(b"lookup", b"root/context", |child| {
            child
                .challenge_extension::<BabyBear, E>(b"typed extension identity", 0)
                .unwrap();
            child.append_message(b"message", &42u64).unwrap();
            child.append_bytes(b"typed request kind", b"vector");
            child
                .challenge_extension::<BabyBear, E>(b"points", 4)
                .unwrap()
        });
        assert_eq!(got, expected);
        let mut a = [0; 64];
        let mut b = [0; 64];
        typed.get_challenge_bytes(b"after", &mut a);
        bytes.challenge_bytes(b"after", &mut b);
        assert_eq!(a, b);
        let mut legacy = Transcript::<BabyBear>::new_direct();
        let mut reference = Transcript::<BabyBear>::new_direct();
        assert!(
            legacy
                .with_classical_extension_child::<BabyBear, E, _>(
                    b"lookup",
                    b"context",
                    |_| panic!("must not run")
                )
                .is_err()
        );
        legacy.get_challenge_bytes(b"after", &mut a);
        reference.get_challenge_bytes(b"after", &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn classical_typed_prime_dispatch_matches_byte_protocol() {
        let profile = [3; 64];
        let mut actual = Transcript::<BabyBear>::new_classical(&profile);
        let mut expected =
            ClassicalTranscript::new(b"HasteBoots typed classical prime v1", &profile);
        let p: u128 = BabyBear::MODULUS_VALUE.as_into();
        expected.append_bytes(b"typed prime field", &p.to_le_bytes());
        actual.append_message(b"statement", &17u64);
        expected.append_message(b"statement", &17u64).unwrap();
        expected.append_bytes(b"typed request kind", b"scalar");
        assert_eq!(
            actual.get_challenge(b"point"),
            expected.challenge_prime::<BabyBear>(b"point", 1)[0]
        );
        for count in [0, 1, 17] {
            expected.append_bytes(b"typed request kind", b"vector");
            assert_eq!(
                actual.get_vec_challenge(b"points", count),
                expected.challenge_prime::<BabyBear>(b"points", count)
            );
        }
        let mut a = [0; 64];
        let mut b = [0; 64];
        actual.get_challenge_bytes(b"after", &mut a);
        expected.challenge_bytes(b"after", &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn classical_typed_extension_dispatch_matches_byte_protocol() {
        type E = algebra::GoldilocksExtension3;
        let profile = [5; 64];
        let mut actual = Transcript::<E>::new_classical_extension::<Goldilocks>(&profile);
        let mut expected =
            ClassicalTranscript::new(b"HasteBoots typed classical extension v1", &profile);
        expected
            .challenge_extension::<Goldilocks, E>(b"typed extension identity", 0)
            .unwrap();
        for count in [0, 1, 17] {
            expected.append_bytes(b"typed request kind", b"vector");
            assert_eq!(
                actual.get_vec_challenge(b"points", count),
                expected
                    .challenge_extension::<Goldilocks, E>(b"points", count)
                    .unwrap()
            );
        }
        expected.append_bytes(b"typed request kind", b"scalar");
        assert_eq!(
            actual.get_challenge(b"point"),
            expected
                .challenge_extension::<Goldilocks, E>(b"point", 1)
                .unwrap()[0]
        );
        let mut a = [0; 64];
        let mut b = [0; 64];
        actual.get_challenge_bytes(b"after", &mut a);
        expected.challenge_bytes(b"after", &mut b);
        assert_eq!(a, b);
    }

    fn legacy_reference<F: Field>() {
        let mut actual = Transcript::<F>::default();
        let mut reference = merlin::Transcript::new(b"");
        actual.append_message(b"legacy fixture", &17u64);
        reference.append_message(
            b"legacy fixture",
            &bincode::serde::encode_to_vec(17u64, bincode::config::standard()).unwrap(),
        );
        for count in [0, 1, 3, 2048] {
            let mut seed = [0u8; 16];
            reference.challenge_bytes(b"legacy vector", &mut seed);
            let mut prg = Prg::from_seed(Block::from(seed));
            let expected = (0..count).map(|_| F::random(&mut prg)).collect::<Vec<_>>();
            assert_eq!(actual.get_vec_challenge(b"legacy vector", count), expected);
        }
        let mut seed = [0u8; 16];
        reference.challenge_bytes(b"legacy scalar", &mut seed);
        let expected = F::random(&mut Prg::from_seed(Block::from(seed)));
        assert_eq!(actual.get_challenge(b"legacy scalar"), expected);
        let mut a = [0u8; 32];
        let mut b = a;
        actual.get_challenge_bytes(b"after legacy", &mut a);
        reference.challenge_bytes(b"after legacy", &mut b);
        assert_eq!(a, b);
    }
    #[test]
    fn default_legacy_bytes_and_prg_sampling_are_unchanged() {
        legacy_reference::<BabyBear>();
        legacy_reference::<Goldilocks>();
        legacy_reference::<algebra::BabyBearExetension>();
    }
    #[test]
    fn canonical_sampling_rejects_the_modulus_instead_of_reducing_it() {
        for p in [3u128, 257, 2013265921, 18446744069414584321, u128::MAX] {
            let sampler = CanonicalSampler::new(p);
            let mut count = 0;
            let got = sampler.sample(&mut |out| {
                let value = if count < 2 { p } else { p - 1 };
                count += 1;
                out.copy_from_slice(&value.to_le_bytes()[..out.len()]);
            });
            assert_eq!(got, p - 1);
            assert_eq!(count, 3);
        }
        assert_eq!(CanonicalSampler::new(2).sample(&mut |out| out.fill(255)), 1);
    }
    #[test]
    fn canonical_sampler_continues_beyond_analytical_candidate_threshold() {
        for p in [3u128, 2013265921, 18446744069414584321, u128::MAX] {
            let sampler = CanonicalSampler::new(p);
            let mut candidates = 0usize;
            let value = sampler.sample(&mut |out| {
                candidates += 1;
                let candidate = if candidates <= 513 { p } else { 0 };
                out.copy_from_slice(&candidate.to_le_bytes()[..out.len()]);
            });
            assert_eq!(value, 0);
            assert_eq!(candidates, 514);
        }
    }
    #[test]
    fn stream_reads_preserve_bytes_across_every_buffer_boundary() {
        let mut actual = merlin::Transcript::new(b"reader fixture");
        let mut reference = merlin::Transcript::new(b"reader fixture");
        let mut expected = Vec::new();
        for _ in 0..5 {
            let mut block = [0u8; 256];
            reference.challenge_bytes(b"direct canonical field stream", &mut block);
            expected.extend(block);
        }
        let mut got = Vec::new();
        {
            let mut reader = DirectReader {
                transcript: &mut actual,
                bytes: [0; STREAM_BLOCK],
                cursor: STREAM_BLOCK,
            };
            for len in [1, 3, 253, 8, 511, 251] {
                let mut part = vec![0; len];
                reader.read(&mut part);
                got.extend(part);
            }
        }
        assert_eq!(got, &expected[..1027]);
        let mut a = [0u8; 32];
        let mut b = a;
        actual.challenge_bytes(b"after stream", &mut a);
        reference.challenge_bytes(b"after stream", &mut b);
        assert_eq!(a, b);
    }
    fn direct_reference<F: PrimeField>(bytes_per_value: usize, mask: u128) {
        let p: u128 = F::MODULUS_VALUE.as_into();
        let mut actual = Transcript::<F>::new_direct();
        let mut reference = merlin::Transcript::new(b"HasteBoots direct-field transcript v1");
        // Independently frame the public protocol and decode complete blocks.
        for (kind, count) in [
            (b"vector".as_slice(), 0usize),
            (b"vector", 2000),
            (b"scalar", 1),
        ] {
            reference.append_message(b"direct request kind", kind);
            reference.append_message(b"direct request label", b"reference field challenge");
            reference.append_message(b"direct field characteristic", &p.to_le_bytes());
            reference.append_message(b"direct field count", &(count as u64).to_le_bytes());
            let mut expected = Vec::new();
            let mut block = [0u8; 256];
            let mut cursor = 256;
            while expected.len() < count {
                if cursor == 256 {
                    reference.challenge_bytes(b"direct canonical field stream", &mut block);
                    cursor = 0;
                }
                let mut bytes = [0u8; 16];
                bytes[..bytes_per_value].copy_from_slice(&block[cursor..cursor + bytes_per_value]);
                cursor += bytes_per_value;
                let candidate = u128::from_le_bytes(bytes) & mask;
                if candidate < p {
                    expected.push(F::new(F::Value::as_from(candidate)));
                }
            }
            let got = if kind == b"scalar" {
                vec![actual.get_challenge(b"reference field challenge")]
            } else {
                actual.get_vec_challenge(b"reference field challenge", count)
            };
            assert_eq!(got, expected);
        }
        let mut a = [0u8; 32];
        let mut b = a;
        actual.get_challenge_bytes(b"after direct", &mut a);
        reference.challenge_bytes(b"after direct", &mut b);
        assert_eq!(a, b);
    }
    #[test]
    fn direct_fields_match_explicit_merlin_frames_and_rejection_reference() {
        direct_reference::<BabyBear>(4, (1u128 << 31) - 1);
        direct_reference::<Goldilocks>(8, u64::MAX as u128);
    }
    #[test]
    fn request_kind_label_count_and_empty_vectors_are_domain_separated() {
        let mut outputs = Vec::new();
        for mode in 0..5 {
            let mut transcript = Transcript::<BabyBear>::new_direct();
            match mode {
                0 => {
                    transcript.get_challenge(b"a");
                }
                1 => {
                    transcript.get_vec_challenge(b"a", 1);
                }
                2 => {
                    transcript.get_vec_challenge(b"b", 1);
                }
                3 => {
                    transcript.get_vec_challenge(b"a", 2);
                }
                _ => {
                    transcript.get_vec_challenge(b"a", 0);
                }
            }
            let mut bytes = [0u8; 32];
            transcript.get_challenge_bytes(b"after request", &mut bytes);
            outputs.push(bytes);
        }
        for i in 0..outputs.len() {
            for j in 0..i {
                assert_ne!(outputs[i], outputs[j]);
            }
        }
        let mut bb = Transcript::<BabyBear>::new_direct();
        let mut gold = Transcript::<Goldilocks>::new_direct();
        bb.get_vec_challenge(b"same", 0);
        gold.get_vec_challenge(b"same", 0);
        let mut a = [0u8; 32];
        let mut b = a;
        bb.get_challenge_bytes(b"after field", &mut a);
        gold.get_challenge_bytes(b"after field", &mut b);
        assert_ne!(a, b);
    }
    fn extension_frame(p: u128, degree: usize, w: u128) -> merlin::Transcript {
        let mut reference = merlin::Transcript::new(b"HasteBoots direct-extension transcript v1");
        reference.append_message(b"extension characteristic", &p.to_le_bytes());
        reference.append_message(b"extension degree", &(degree as u64).to_le_bytes());
        // Independently derive multiplication from X^degree=w, without
        // invoking the extension arithmetic used by the production framing.
        let mut products = Vec::new();
        for i in 0..degree {
            for j in 0..degree {
                for k in 0..degree {
                    let value: u128 = if k == (i + j) % degree {
                        if i + j < degree { 1 } else { w }
                    } else {
                        0
                    };
                    products.extend_from_slice(&value.to_le_bytes());
                }
            }
        }
        reference.append_message(b"extension basis products", &products);
        reference
    }
    fn extension_reference<Base: PrimeField, EF: AbstractExtensionField<Base>>(
        width: usize,
        mask: u128,
        w: u128,
    ) {
        let p: u128 = Base::MODULUS_VALUE.as_into();
        let mut actual = Transcript::<EF>::new_direct_extension::<Base>();
        let mut reference = extension_frame(p, EF::D, w);
        for (kind, count) in [
            (b"vector".as_slice(), 0usize),
            (b"vector", 1300),
            (b"scalar", 1),
            (b"vector", 17),
        ] {
            reference.append_message(b"extension request kind", kind);
            reference.append_message(b"extension request label", b"reference extension challenge");
            reference.append_message(b"extension value count", &(count as u64).to_le_bytes());
            let mut coefficients = Vec::new();
            let mut block = [0u8; 256];
            let mut cursor = 256;
            while coefficients.len() < count * EF::D {
                if cursor == 256 {
                    reference.challenge_bytes(b"direct canonical field stream", &mut block);
                    cursor = 0;
                }
                let mut bytes = [0u8; 16];
                bytes[..width].copy_from_slice(&block[cursor..cursor + width]);
                cursor += width;
                let value = u128::from_le_bytes(bytes) & mask;
                if value < p {
                    coefficients.push(Base::new(Base::Value::as_from(value)));
                }
            }
            let expected: Vec<EF> = coefficients
                .chunks_exact(EF::D)
                .map(EF::from_base_slice)
                .collect();
            let got = if kind == b"scalar" {
                vec![actual.get_challenge(b"reference extension challenge")]
            } else {
                actual.get_vec_challenge(b"reference extension challenge", count)
            };
            assert_eq!(got, expected);
            if count > 100 {
                for coordinate in 0..EF::D {
                    assert!(
                        got.iter()
                            .any(|x| x.as_base_slice()[coordinate] != Base::zero())
                    );
                }
            }
        }
        let mut a = [0u8; 32];
        let mut b = a;
        actual.get_challenge_bytes(b"after extension", &mut a);
        reference.challenge_bytes(b"after extension", &mut b);
        assert_eq!(a, b);
        for (degree, w) in [(EF::D, w + 1), (EF::D + 1, w)] {
            let mut actual = Transcript::<EF>::new_direct_extension::<Base>();
            let mut wrong = extension_frame(p, degree, w);
            actual.get_challenge_bytes(b"field identity", &mut a);
            wrong.challenge_bytes(b"field identity", &mut b);
            assert_ne!(a, b);
        }
    }
    #[test]
    fn extension_challenges_match_independent_binomial_and_byte_reference() {
        extension_reference::<BabyBear, algebra::BabyBearExetension>(4, (1u128 << 31) - 1, 11);
        extension_reference::<Goldilocks, algebra::GoldilocksExtension>(8, u64::MAX as u128, 7);
    }
    #[test]
    fn larger_extension_challenges_match_independent_polynomial_and_byte_reference() {
        extension_reference::<BabyBear, algebra::BabyBearExtension6>(4, (1u128 << 31) - 1, 31);
        extension_reference::<BabyBear, algebra::BabyBearExtension8>(4, (1u128 << 31) - 1, 11);
        extension_reference::<Goldilocks, algebra::GoldilocksExtension4>(8, u64::MAX as u128, 7);
        extension_reference::<BabyBear, algebra::BabyBearExtension5>(4, (1u128 << 31) - 1, 2);
        extension_reference::<Goldilocks, algebra::GoldilocksExtension5>(8, u64::MAX as u128, 3);
        extension_reference::<Goldilocks, algebra::GoldilocksExtension3>(8, u64::MAX as u128, 7);
    }
    #[test]
    fn extension_request_kinds_labels_counts_and_sampling_modes_are_separated() {
        type EF = algebra::BabyBearExetension;
        let mut outputs = Vec::new();
        for mode in 0..6 {
            let mut t = if mode == 5 {
                Transcript::<EF>::new()
            } else {
                Transcript::<EF>::new_direct_extension::<BabyBear>()
            };
            match mode {
                0 | 5 => {
                    t.get_challenge(b"a");
                }
                1 => {
                    t.get_vec_challenge(b"a", 1);
                }
                2 => {
                    t.get_vec_challenge(b"b", 1);
                }
                3 => {
                    t.get_vec_challenge(b"a", 2);
                }
                _ => {
                    t.get_vec_challenge(b"a", 0);
                }
            }
            let mut bytes = [0u8; 32];
            t.get_challenge_bytes(b"after request", &mut bytes);
            outputs.push(bytes);
        }
        for i in 0..outputs.len() {
            for j in 0..i {
                assert_ne!(outputs[i], outputs[j]);
            }
        }
    }
}
