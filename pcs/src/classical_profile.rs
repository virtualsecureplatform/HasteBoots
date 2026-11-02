//! Immutable trusted descriptors, never security assertions supplied by a proof.
use crate::utils::hash::Digest512;
use algebra::{AbstractExtensionField, AsInto, NTTField, PrimeField};
use serde::Serialize;
use sha2::{Digest, Sha512};

/// Canonical PCS family selected by the caller, not by a proof packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Backend {
    /// Matrix-weighted row-code commitment.
    Brakedown,
    /// Ordered-matrix PolyFRIM.
    Polyfrim,
    /// Ordered-matrix bridge to fragmented scalar PipFRI.
    FragmentedPipfri,
    /// The same ordered-matrix PolyFRIM family with canonical hash dictionaries.
    /// Kept distinct so the trusted profile binds the proof encoding.
    PolyfrimDictionary,
    /// Fragmented PipFRI with an unmasked virtual initial word and shared queries.
    FragmentedPipfriVirtual,
}

/// One trusted source/helper geometry, in the canonical four-role order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Role {
    /// Logical Boolean cell variables.
    pub num_vars: usize,
    /// Consecutive base-field lanes.
    pub width: usize,
    /// Number of independent sampled positions.
    pub queries: usize,
    /// Brakedown's row split; absent in direct/fragmented protocols.
    pub left_vars: Option<usize>,
    /// Whole-symbol row-code width; absent outside Brakedown.
    pub block_width: Option<usize>,
}

/// Checked inputs to the version-one SHA-512 / framed-SHAKE256 profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Specification {
    /// Trusted PCS family.
    pub backend: Backend,
    /// Main source, main helper, final source, final helper.
    pub roles: [Role; 4],
    /// Power-of-two RS domain expansion, at least two.
    pub blowup: usize,
    /// Fragment-variable cap, required only for fragmented PipFRI.
    pub fragment_vars: Option<usize>,
}

/// Validated immutable descriptor. Construction does not qualify 128-bit security.
#[derive(Clone, Debug, Serialize)]
pub struct ClassicalProfile {
    version: u32,
    specification: Specification,
    prime: String,
    extension_degree: usize,
    basis_products: Vec<u128>,
    merkle_suite: &'static str,
    transcript_suite: &'static str,
}

/// Backend parameters constructed from—and kept with—their trusted descriptor.
/// Roles are exposed immutably, preventing accidental descriptor/parameter drift.
pub struct ProfileParameters<P> {
    profile: ClassicalProfile,
    roles: [P; 4],
}
impl<P> ProfileParameters<P> {
    /// Independently expected descriptor for proof framing and setup.
    pub fn profile(&self) -> &ClassicalProfile {
        &self.profile
    }
    /// Main source/helper and final source/helper, in that order.
    pub fn roles(&self) -> &[P; 4] {
        &self.roles
    }
}

fn basis<F: PrimeField, E: AbstractExtensionField<F>>() -> Result<Vec<u128>, &'static str> {
    if E::D == 0 {
        return Err("zero extension degree");
    }
    let capacity = E::D
        .checked_mul(E::D)
        .and_then(|v| v.checked_mul(E::D))
        .ok_or("basis size overflow")?;
    let mut products = Vec::with_capacity(capacity);
    for i in 0..E::D {
        for j in 0..E::D {
            let value = E::monomial(i) * E::monomial(j);
            if value.as_base_slice().len() > E::D {
                return Err("invalid extension basis");
            }
            for k in 0..E::D {
                products.push(
                    value
                        .as_base_slice()
                        .get(k)
                        .copied()
                        .unwrap_or_else(F::zero)
                        .value()
                        .as_into(),
                );
            }
        }
    }
    Ok(products)
}

impl ClassicalProfile {
    /// Construct all four row-code parameter sets, checking native NTT support.
    pub fn brakedown_parameters<F, E>(
        &self,
    ) -> Result<
        ProfileParameters<
            crate::matrix_weighted::Parameters<crate::utils::code::BlockReedSolomonCode<F>>,
        >,
        &'static str,
    >
    where
        F: NTTField + Serialize,
        E: AbstractExtensionField<F>,
    {
        self.validate_field::<F, E>()?;
        if self.specification.backend != Backend::Brakedown {
            return Err("profile backend mismatch");
        }
        let mut roles = Vec::with_capacity(4);
        for role in &self.specification.roles {
            let left = role.left_vars.ok_or("missing row split")?;
            let code = crate::utils::code::BlockReedSolomonCode::<F>::new(
                1usize << (role.num_vars - left),
                role.block_width.ok_or("missing block width")?,
                self.specification.blowup,
            )
            .map_err(|_| "unsupported row-code domain")?;
            roles.push(
                crate::matrix_weighted::Parameters::new_encoded::<F>(
                    role.num_vars,
                    role.width,
                    left,
                    role.queries,
                    code,
                )
                .map_err(|_| "invalid row-code parameter geometry")?,
            );
        }
        Ok(ProfileParameters {
            profile: self.clone(),
            roles: roles.try_into().map_err(|_| "role count")?,
        })
    }

    /// Construct all four direct PolyFRIM parameter sets with the bound basis.
    pub fn polyfrim_parameters<F, E>(
        &self,
    ) -> Result<ProfileParameters<crate::matrix_weighted::polyfrim::Parameters<F, E>>, &'static str>
    where
        F: NTTField + Serialize,
        E: AbstractExtensionField<F> + Serialize,
    {
        self.validate_field::<F, E>()?;
        if self.specification.backend != Backend::Polyfrim {
            return Err("profile backend mismatch");
        }
        let roles = self
            .specification
            .roles
            .iter()
            .map(|role| {
                crate::matrix_weighted::polyfrim::Parameters::<F, E>::new(
                    role.num_vars,
                    role.width,
                    self.specification.blowup,
                    role.queries,
                )
                .map_err(|_| "unsupported PolyFRIM geometry or domain")
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ProfileParameters {
            profile: self.clone(),
            roles: roles.try_into().map_err(|_| "role count")?,
        })
    }
    /// Construct the PolyFRIM family's dictionary-encoded parameter sets.
    pub fn polyfrim_dictionary_parameters<F, E>(
        &self,
    ) -> Result<
        ProfileParameters<crate::matrix_weighted::polyfrim::compact::Parameters<F, E>>,
        &'static str,
    >
    where
        F: NTTField + Serialize,
        E: AbstractExtensionField<F> + Serialize,
    {
        self.validate_field::<F, E>()?;
        if self.specification.backend != Backend::PolyfrimDictionary {
            return Err("profile backend mismatch");
        }
        let roles = self
            .specification
            .roles
            .iter()
            .map(|role| {
                crate::matrix_weighted::polyfrim::compact::Parameters::<F, E>::new(
                    role.num_vars,
                    role.width,
                    self.specification.blowup,
                    role.queries,
                )
                .map_err(|_| "unsupported dictionary PolyFRIM geometry or domain")
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ProfileParameters {
            profile: self.clone(),
            roles: roles.try_into().map_err(|_| "role count")?,
        })
    }
    /// Construct all four unmasked fragmented PipFRI parameter sets.
    pub fn fragmented_parameters<F, E>(
        &self,
    ) -> Result<
        ProfileParameters<crate::matrix_weighted::fragmented_pipfri::Parameters<F, E>>,
        &'static str,
    >
    where
        F: NTTField + Serialize,
        E: AbstractExtensionField<F> + Serialize + serde::de::DeserializeOwned,
    {
        self.validate_field::<F, E>()?;
        if self.specification.backend != Backend::FragmentedPipfri {
            return Err("profile backend mismatch");
        }
        let fragment_vars = self
            .specification
            .fragment_vars
            .ok_or("missing fragment cap")?;
        let roles = self
            .specification
            .roles
            .iter()
            .map(|role| {
                crate::matrix_weighted::fragmented_pipfri::Parameters::<F, E>::new(
                    role.num_vars,
                    role.width,
                    self.specification.blowup,
                    role.queries,
                    fragment_vars,
                )
                .map_err(|_| "unsupported fragmented PipFRI geometry or domain")
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ProfileParameters {
            profile: self.clone(),
            roles: roles.try_into().map_err(|_| "role count")?,
        })
    }
    /// Construct the explicitly versioned shared-query fragmented variant.
    pub fn fragmented_virtual_parameters<F, E>(
        &self,
    ) -> Result<
        ProfileParameters<
            crate::matrix_weighted::fragmented_pipfri::virtual_source::Parameters<F, E>,
        >,
        &'static str,
    >
    where
        F: NTTField + Serialize,
        E: AbstractExtensionField<F> + Serialize + serde::de::DeserializeOwned,
    {
        self.validate_field::<F, E>()?;
        if self.specification.backend != Backend::FragmentedPipfriVirtual {
            return Err("profile backend mismatch");
        }
        let cap = self
            .specification
            .fragment_vars
            .ok_or("missing fragment cap")?;
        let roles = self
            .specification
            .roles
            .iter()
            .map(|role| {
                crate::matrix_weighted::fragmented_pipfri::virtual_source::Parameters::<F, E>::new(
                    role.num_vars,
                    role.width,
                    self.specification.blowup,
                    role.queries,
                    cap,
                )
                .map_err(|_| "unsupported virtual fragmented geometry or domain")
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ProfileParameters {
            profile: self.clone(),
            roles: roles.try_into().map_err(|_| "role count")?,
        })
    }
    /// Validate descriptor structure and bind the trusted field representation.
    /// Native-domain availability and actual PCS-context equality are checked
    /// by backend setup; this descriptor cannot stand in for those checks.
    pub fn new<F: PrimeField, E: AbstractExtensionField<F>>(
        specification: Specification,
    ) -> Result<Self, &'static str> {
        let k = specification.roles[0].width;
        if !k.is_power_of_two()
            || E::D == 0
            || k < E::D
            || specification.blowup < 2
            || !specification.blowup.is_power_of_two()
        {
            return Err("invalid packing, extension or blowup");
        }
        for (index, role) in specification.roles.iter().enumerate() {
            if role.width == 0
                || role.queries == 0
                || (index % 2 == 0 && role.width != k)
                || (index % 2 == 1 && role.width != k && role.width != E::D)
            {
                return Err("invalid canonical role geometry");
            }
            let cells = 1usize
                .checked_shl(role.num_vars.try_into().map_err(|_| "dimension overflow")?)
                .ok_or("dimension overflow")?;
            cells
                .checked_mul(role.width)
                .and_then(|v| v.checked_mul(specification.blowup))
                .ok_or("oracle size overflow")?;
            match specification.backend {
                Backend::Brakedown => {
                    if !matches!(role.left_vars,Some(v) if v<=role.num_vars)
                        || !matches!(role.block_width,Some(v) if v>0)
                    {
                        return Err("missing row-code geometry");
                    }
                }
                _ => {
                    if role.left_vars.is_some() || role.block_width.is_some() {
                        return Err("unexpected row-code geometry");
                    }
                }
            }
            if matches!(
                specification.backend,
                Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual
            ) && role.width != k
            {
                return Err("fragmented bridge requires power-of-two helper packing");
            }
        }
        match (specification.backend, specification.fragment_vars) {
            (Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual, Some(v))
                if v > 0 && v < (usize::BITS as usize) =>
            {
                ()
            }
            (Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual, _) => {
                return Err("invalid fragment cap");
            }
            (_, Some(_)) => return Err("unexpected fragment cap"),
            _ => (),
        }
        Ok(Self {
            version: 1,
            specification,
            prime: F::MODULUS_VALUE.to_string(),
            extension_degree: E::D,
            basis_products: basis::<F, E>()?,
            merkle_suite: "sha512-v1",
            transcript_suite: helper::transcript::CLASSICAL_TRANSCRIPT_ID,
        })
    }

    /// Opt-in version-two challenge schedule; retains the version-one constructor.
    pub fn new_atomic_ntt<F: PrimeField, E: AbstractExtensionField<F>>(
        specification: Specification,
    ) -> Result<Self, &'static str> {
        let mut profile = Self::new::<F, E>(specification)?;
        profile.version = 2;
        profile.transcript_suite = "framed-shake256-canonical-rejection-atomic-ntt-v2";
        Ok(profile)
    }

    /// Opt-in version-three schedule: atomic NTT rows and joint projection weights.
    pub fn new_atomic_phases<F: PrimeField, E: AbstractExtensionField<F>>(
        specification: Specification,
    ) -> Result<Self, &'static str> {
        let mut profile = Self::new::<F, E>(specification)?;
        profile.version = 3;
        profile.transcript_suite = "framed-shake256-canonical-rejection-atomic-phases-v3";
        Ok(profile)
    }

    /// Version four additionally groups packed ZeroCheck equality/first-round coins.
    pub fn new_atomic_zerocheck<F: PrimeField, E: AbstractExtensionField<F>>(
        specification: Specification,
    ) -> Result<Self, &'static str> {
        let mut profile = Self::new::<F, E>(specification)?;
        profile.version = 4;
        profile.transcript_suite = "framed-shake256-canonical-rejection-atomic-zerocheck-v4";
        Ok(profile)
    }

    /// Version five also groups all Brakedown column draws in one byte phase.
    pub fn new_atomic_columns<F: PrimeField, E: AbstractExtensionField<F>>(
        specification: Specification,
    ) -> Result<Self, &'static str> {
        if specification.roles.iter().any(|role| {
            role.queries
                .checked_mul(8)
                .is_none_or(|bytes| bytes > isize::MAX as usize)
        }) {
            return Err("atomic column byte count overflow");
        }
        let mut profile = Self::new::<F, E>(specification)?;
        profile.version = 5;
        profile.transcript_suite = "framed-shake256-canonical-rejection-atomic-columns-v5";
        Ok(profile)
    }

    /// Borrow validated inputs without permitting mutation of the descriptor.
    pub fn specification(&self) -> &Specification {
        &self.specification
    }

    /// Immutable descriptor/schedule version, for trusted setup inventories.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Start a profile-bound parent transcript after checking its prime field.
    /// This selects the specified byte protocol, not a security qualification.
    pub fn parent_transcript<F: PrimeField>(&self) -> Result<helper::Transcript<F>, &'static str> {
        if self.prime != F::MODULUS_VALUE.to_string() {
            return Err("profile prime field mismatch");
        }
        let mut transcript = if self.version == 5 {
            helper::Transcript::new_classical_atomic_columns(&self.id().0)
        } else if self.version == 4 {
            helper::Transcript::new_classical_atomic_zerocheck(&self.id().0)
        } else if self.version == 3 {
            helper::Transcript::new_classical_atomic_phases(&self.id().0)
        } else if self.version == 2 {
            helper::Transcript::new_classical_atomic_ntt(&self.id().0)
        } else {
            helper::Transcript::new_classical(&self.id().0)
        };
        helper::FiatShamirTranscript::append_message(
            &mut transcript,
            b"classical trusted profile",
            self,
        );
        Ok(transcript)
    }

    /// Stable identifier of the complete canonical descriptor and suite version.
    pub fn id(&self) -> Digest512 {
        let bytes = bincode::serde::encode_to_vec(
            (b"HasteBoots classical profile v1", self),
            bincode::config::standard(),
        )
        .expect("serializable profile");
        Digest512(Sha512::digest(bytes).into())
    }

    /// Reject attempts to reuse a descriptor with another field representation.
    pub fn validate_field<F: PrimeField, E: AbstractExtensionField<F>>(
        &self,
    ) -> Result<(), &'static str> {
        if self.prime != F::MODULUS_VALUE.to_string()
            || self.extension_degree != E::D
            || self.basis_products != basis::<F, E>()?
        {
            return Err("profile field mismatch");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn atomic_column_profile_binds_new_suite_and_keeps_version_four() {
        let spec = specification(Backend::Brakedown);
        let old =
            ClassicalProfile::new_atomic_zerocheck::<BabyBear, BabyBearExtension6>(spec.clone())
                .unwrap();
        let new =
            ClassicalProfile::new_atomic_columns::<BabyBear, BabyBearExtension6>(spec).unwrap();
        assert_eq!(new.version(), 5);
        assert_ne!(new.id(), old.id());
        assert!(
            new.parent_transcript::<BabyBear>()
                .unwrap()
                .uses_atomic_brakedown_columns()
        );
        assert!(
            !old.parent_transcript::<BabyBear>()
                .unwrap()
                .uses_atomic_brakedown_columns()
        );
        let mut oversized = specification(Backend::Brakedown);
        oversized.roles[0].queries = usize::MAX;
        assert!(
            ClassicalProfile::new_atomic_columns::<BabyBear, BabyBearExtension6>(oversized)
                .is_err()
        );
    }

    #[test]
    fn atomic_zerocheck_profile_has_distinct_id_and_all_atomic_flags() {
        let spec = specification(Backend::Polyfrim);
        let old = ClassicalProfile::new_atomic_phases::<BabyBear, BabyBearExtension6>(spec.clone())
            .unwrap();
        let new =
            ClassicalProfile::new_atomic_zerocheck::<BabyBear, BabyBearExtension6>(spec).unwrap();
        assert_eq!(new.version(), 4);
        assert_ne!(new.id(), old.id());
        let t = new.parent_transcript::<BabyBear>().unwrap();
        assert!(
            t.uses_atomic_ntt_rows()
                && t.uses_atomic_joint_projections()
                && t.uses_atomic_zerocheck()
        );
        assert!(
            !old.parent_transcript::<BabyBear>()
                .unwrap()
                .uses_atomic_zerocheck()
        );
        new.polyfrim_parameters::<BabyBear, BabyBearExtension6>()
            .unwrap();
    }
    #[test]
    fn atomic_phase_profile_has_separate_id_and_parameters() {
        let spec = specification(Backend::Polyfrim);
        let v1 = ClassicalProfile::new::<BabyBear, BabyBearExtension6>(spec.clone()).unwrap();
        let v2 =
            ClassicalProfile::new_atomic_ntt::<BabyBear, BabyBearExtension6>(spec.clone()).unwrap();
        let v3 = ClassicalProfile::new_atomic_phases::<BabyBear, BabyBearExtension6>(spec).unwrap();
        assert_eq!(v3.version(), 3);
        assert_ne!(v3.id(), v1.id());
        assert_ne!(v3.id(), v2.id());
        assert!(
            v3.parent_transcript::<BabyBear>()
                .unwrap()
                .uses_atomic_joint_projections()
        );
        assert!(
            !v2.parent_transcript::<BabyBear>()
                .unwrap()
                .uses_atomic_joint_projections()
        );
        v3.polyfrim_parameters::<BabyBear, BabyBearExtension6>()
            .unwrap();
    }
    #[test]
    fn atomic_ntt_profile_binds_schedule_and_preserves_v1_selection() {
        let spec = specification(Backend::Polyfrim);
        let legacy = ClassicalProfile::new::<BabyBear, BabyBearExtension6>(spec.clone()).unwrap();
        let atomic =
            ClassicalProfile::new_atomic_ntt::<BabyBear, BabyBearExtension6>(spec).unwrap();
        assert_ne!(legacy.id(), atomic.id());
        assert!(
            !legacy
                .parent_transcript::<BabyBear>()
                .unwrap()
                .uses_atomic_ntt_rows()
        );
        assert!(
            atomic
                .parent_transcript::<BabyBear>()
                .unwrap()
                .uses_atomic_ntt_rows()
        );
        atomic
            .polyfrim_parameters::<BabyBear, BabyBearExtension6>()
            .unwrap();
    }
    use algebra::{
        BabyBear, BabyBearExtension6, BabyBearExtension8, Goldilocks, GoldilocksExtension3,
    };
    fn specification(backend: Backend) -> Specification {
        Specification {
            backend,
            roles: [5, 8, 4, 7].map(|num_vars| Role {
                num_vars,
                width: 8,
                queries: 128,
                left_vars: if backend == Backend::Brakedown {
                    Some(num_vars / 2)
                } else {
                    None
                },
                block_width: if backend == Backend::Brakedown {
                    Some(8)
                } else {
                    None
                },
            }),
            blowup: 2,
            fragment_vars: if matches!(
                backend,
                Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual
            ) {
                Some(8)
            } else {
                None
            },
        }
    }
    #[test]
    fn identities_bind_backend_role_parameters_and_basis() {
        let input = specification(Backend::Polyfrim);
        let profile = ClassicalProfile::new::<BabyBear, BabyBearExtension6>(input.clone()).unwrap();
        assert_eq!(
            profile.id(),
            ClassicalProfile::new::<BabyBear, BabyBearExtension6>(input.clone())
                .unwrap()
                .id()
        );
        let mut changed = input.clone();
        changed.roles[1].queries += 1;
        assert_ne!(
            profile.id(),
            ClassicalProfile::new::<BabyBear, BabyBearExtension6>(changed)
                .unwrap()
                .id()
        );
        assert_ne!(
            profile.id(),
            ClassicalProfile::new::<BabyBear, BabyBearExtension8>(input)
                .unwrap()
                .id()
        );
        for backend in [Backend::Brakedown, Backend::FragmentedPipfri] {
            assert_ne!(
                profile.id(),
                ClassicalProfile::new::<BabyBear, BabyBearExtension6>(specification(backend))
                    .unwrap()
                    .id()
            );
        }
        assert!(
            profile
                .validate_field::<BabyBear, BabyBearExtension6>()
                .is_ok()
        );
        assert!(
            profile
                .validate_field::<BabyBear, BabyBearExtension8>()
                .is_err()
        );
        assert!(
            profile
                .validate_field::<Goldilocks, GoldilocksExtension3>()
                .is_err()
        );
    }
    #[test]
    fn incompatible_geometries_reject() {
        for mutation in 0..5 {
            let mut input = specification(Backend::Polyfrim);
            match mutation {
                0 => input.roles[0].queries = 0,
                1 => input.roles[0].num_vars = usize::BITS as usize,
                2 => input.roles[1].width = 7,
                3 => input.roles[0].left_vars = Some(1),
                _ => input.fragment_vars = Some(8),
            }
            assert!(ClassicalProfile::new::<BabyBear, BabyBearExtension6>(input).is_err());
        }
        let mut input = specification(Backend::FragmentedPipfri);
        input.roles[1].width = 6;
        assert!(ClassicalProfile::new::<BabyBear, BabyBearExtension6>(input).is_err());
        let mut input = specification(Backend::Brakedown);
        input.roles[0].left_vars = None;
        assert!(ClassicalProfile::new::<BabyBear, BabyBearExtension6>(input).is_err());
    }

    #[test]
    fn factories_preserve_roles_and_reject_foreign_backends() {
        let profile = ClassicalProfile::new::<BabyBear, BabyBearExtension6>(specification(
            Backend::Brakedown,
        ))
        .unwrap();
        let built = profile
            .brakedown_parameters::<BabyBear, BabyBearExtension6>()
            .unwrap();
        assert_eq!(built.profile().id(), profile.id());
        for (actual, expected) in built.roles().iter().zip(&profile.specification().roles) {
            assert_eq!(actual.num_vars(), expected.num_vars);
            assert_eq!(actual.width(), expected.width);
            assert_eq!(actual.left_vars(), expected.left_vars.unwrap());
        }
        assert!(
            profile
                .polyfrim_parameters::<BabyBear, BabyBearExtension6>()
                .is_err()
        );
        let profile =
            ClassicalProfile::new::<BabyBear, BabyBearExtension6>(specification(Backend::Polyfrim))
                .unwrap();
        let built = profile
            .polyfrim_parameters::<BabyBear, BabyBearExtension6>()
            .unwrap();
        assert_eq!(built.profile().id(), profile.id());
        assert!(
            profile
                .brakedown_parameters::<BabyBear, BabyBearExtension6>()
                .is_err()
        );
        assert!(
            profile
                .polyfrim_parameters::<Goldilocks, GoldilocksExtension3>()
                .is_err()
        );
        assert!(profile.parent_transcript::<Goldilocks>().is_err());
        let mut a = profile.parent_transcript::<BabyBear>().unwrap();
        let mut b = profile.parent_transcript::<BabyBear>().unwrap();
        use helper::FiatShamirTranscript;
        assert_eq!(a.get_challenge(b"point"), b.get_challenge(b"point"));
        let dictionary = ClassicalProfile::new::<BabyBear, BabyBearExtension6>(specification(
            Backend::PolyfrimDictionary,
        ))
        .unwrap();
        assert_ne!(profile.id(), dictionary.id());
        assert!(
            profile
                .polyfrim_dictionary_parameters::<BabyBear, BabyBearExtension6>()
                .is_err()
        );
        assert!(
            dictionary
                .polyfrim_parameters::<BabyBear, BabyBearExtension6>()
                .is_err()
        );
        let built = dictionary
            .polyfrim_dictionary_parameters::<BabyBear, BabyBearExtension6>()
            .unwrap();
        assert_eq!(built.profile().id(), dictionary.id());
        for (actual, expected) in built.roles().iter().zip(&dictionary.specification().roles) {
            assert_eq!(actual.num_vars(), expected.num_vars);
            assert_eq!(actual.width(), expected.width);
        }
        let ordinary = ClassicalProfile::new::<BabyBear, BabyBearExtension6>(specification(
            Backend::FragmentedPipfri,
        ))
        .unwrap();
        let virtual_profile = ClassicalProfile::new::<BabyBear, BabyBearExtension6>(specification(
            Backend::FragmentedPipfriVirtual,
        ))
        .unwrap();
        assert_ne!(ordinary.id(), virtual_profile.id());
        assert!(
            ordinary
                .fragmented_virtual_parameters::<BabyBear, BabyBearExtension6>()
                .is_err()
        );
        assert!(
            virtual_profile
                .fragmented_parameters::<BabyBear, BabyBearExtension6>()
                .is_err()
        );
        let built = virtual_profile
            .fragmented_virtual_parameters::<BabyBear, BabyBearExtension6>()
            .unwrap();
        assert_eq!(built.profile().id(), virtual_profile.id());
        for (actual, expected) in built
            .roles()
            .iter()
            .zip(&virtual_profile.specification().roles)
        {
            use crate::matrix_weighted::backend::CanonicalPcs;
            assert_eq!(
                CanonicalPcs::<BabyBear, sha2::Sha512>::num_vars(actual),
                expected.num_vars
            );
            assert_eq!(
                CanonicalPcs::<BabyBear, sha2::Sha512>::width(actual),
                expected.width
            );
        }
    }
}
