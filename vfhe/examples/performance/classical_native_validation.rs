//! Correctness only: native FHE parameters do not qualify proof security.
//! Usage: classical_native_validation babybear|goldilocks BACKEND [--toy]
//! [--fresh-21] [--queries N] [--fragment-vars N] [--width N] [--blowup N]. BACKEND is brakedown,
//! polyfrim, dictionary, fragmented or virtual. No performance timing is emitted.
//! --extension-degree selects an existing trusted field representation.
//! --helper-basis selects extension-degree helper packing for nonfragmented backends.
//! --atomic-ntt selects the separately bound version-two row-challenge schedule.
//! --atomic-phases selects version three, also grouping joint projection weights.
//! --atomic-zerocheck selects version four, additionally grouping packed ZeroCheck coins.
//! --role-queries A,B,C,D is an alternative to uniform --queries, in canonical role order.
//! --reader-events captures the first accepted/rejected verifier pair (audit feature).
use algebra::{
    AbstractExtensionField, AsInto, Field, NTTField,
    utils::{Block, Prg},
};
use fhe_core::{Parameters as FheParameters, SecretKeyPack};
use pcs::{
    classical_profile::{Backend, ClassicalProfile, ProfileParameters, Role, Specification},
    matrix_weighted::backend::CanonicalPcs,
};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256, Sha512};
use snarks::packed_pbs::{self as pbs, canonical::classical};
use vfhe::{
    Decryptor, Encryptor,
    bfhe::{BABYBEAR_BINARY_128_BITS_PARAMETERS, Evaluator, GOLDILOCKS_BINARY_128_BITS_PARAMETERS},
};
#[path = "../../tests/common/canonical_pbs.rs"]
mod fixture;

#[cfg(not(feature = "transcript-audit"))]
trait NativeAuditBackend<F: NTTField, E>: CanonicalPcs<F, Sha512> {}
#[cfg(not(feature = "transcript-audit"))]
impl<F: NTTField, E, P: CanonicalPcs<F, Sha512>> NativeAuditBackend<F, E> for P {}

#[cfg(feature = "transcript-audit")]
trait NativeAuditBackend<F: NTTField, E: Field>: CanonicalPcs<F, Sha512> {
    fn observed_verification(
        bundle: &ProfileParameters<Self>,
        setup: &classical::VerifierSetup,
        statement: &pbs::Statement<'_, F>,
        proof: &classical::Proof<F, E, Self::SingleProof, Self::BatchProof>,
        events: Option<classical::oracle_audit::EventCallback>,
    ) -> classical::oracle_audit::VerificationObservation
    where
        Self: Sized;
}
#[cfg(feature = "transcript-audit")]
impl<F, E, P> NativeAuditBackend<F, E> for P
where
    F: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512> + CanonicalPcs<F, classical::oracle_audit::CountingSha512>,
    <P as CanonicalPcs<F, classical::oracle_audit::CountingSha512>>::SingleProof: DeserializeOwned,
    <P as CanonicalPcs<F, classical::oracle_audit::CountingSha512>>::BatchProof: DeserializeOwned,
{
    fn observed_verification(
        bundle: &ProfileParameters<Self>,
        setup: &classical::VerifierSetup,
        statement: &pbs::Statement<'_, F>,
        proof: &classical::Proof<
            F,
            E,
            <P as CanonicalPcs<F, Sha512>>::SingleProof,
            <P as CanonicalPcs<F, Sha512>>::BatchProof,
        >,
        events: Option<classical::oracle_audit::EventCallback>,
    ) -> classical::oracle_audit::VerificationObservation {
        classical::oracle_audit::verify_with_optional_events::<F, E, P>(
            bundle, setup, statement, proof, events,
        )
        .unwrap()
    }
}

#[cfg(feature = "transcript-audit")]
struct ReaderCapture {
    path: std::path::PathBuf,
    writer: std::sync::Arc<std::sync::Mutex<classical::oracle_audit::reader_stream::ReaderStream>>,
}
#[cfg(feature = "transcript-audit")]
impl ReaderCapture {
    fn create(directory: &Option<std::path::PathBuf>, ordinal: usize, kind: &str) -> Option<Self> {
        directory
            .as_ref()
            .filter(|_| ordinal == 0)
            .map(|directory| {
                let path = directory.join(format!("{kind}-{ordinal}.reader-events"));
                let writer =
                    classical::oracle_audit::reader_stream::ReaderStream::create(&path).unwrap();
                Self {
                    path,
                    writer: std::sync::Arc::new(std::sync::Mutex::new(writer)),
                }
            })
    }
    fn callback(&self) -> classical::oracle_audit::EventCallback {
        let writer = std::sync::Arc::clone(&self.writer);
        std::sync::Arc::new(move |event| writer.lock().unwrap().record(2, event).unwrap())
    }
    fn emit(
        &self,
        kind: &str,
        profile: &str,
        proof: &str,
        statement: &str,
        setup: &str,
        native: bool,
        ring: usize,
        lwe: usize,
    ) {
        let fingerprint = self.writer.lock().unwrap().finish().unwrap();
        let path_hex: String = self
            .path
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        println!(
            "HB_CLASSICAL_READER_TRACE {{\"kind\":\"{kind}\",\"ordinal\":0,\"profile_id_sha512\":\"{profile}\",\"proof_sha256\":\"{proof}\",\"statement_sha256\":\"{statement}\",\"trusted_setup_sha256\":\"{setup}\",\"trace_path_hex\":\"{path_hex}\",\"trace_sha512\":\"{fingerprint}\",\"native\":{native},\"ring_dimension\":{ring},\"lwe_dimension\":{lwe},\"ordinary_counter_match\":true,\"direct_primitive_calls_included\":false,\"security_qualified\":false,\"performance_gate\":false}}"
        );
    }
}

#[cfg(feature = "transcript-audit")]
fn emit_honest_activity(
    stage: &str,
    ordinal: Option<usize>,
    proof_hash: Option<&str>,
    profile_id: &str,
    setup_hash: &str,
    native: bool,
    ring: usize,
    lwe: usize,
    counts: &classical::oracle_audit::HonestOracleActivity,
) {
    let ordinal = ordinal.map_or_else(|| "null".to_owned(), |v| v.to_string());
    let proof_hash = proof_hash.map_or_else(|| "null".to_owned(), |v| format!("\"{v}\""));
    println!(
        "HB_CLASSICAL_HONEST_ORACLE_ACTIVITY {{\"stage\":\"{stage}\",\"ordinal\":{ordinal},\"profile_id_sha512\":\"{profile_id}\",\"trusted_setup_sha256\":\"{setup_hash}\",\"proof_sha256\":{proof_hash},\"native\":{native},\"ring_dimension\":{ring},\"lwe_dimension\":{lwe},\"hash_queries\":{},\"hash_input_bytes_recorded\":false,\"xof_queries\":{},\"xof_input_bytes\":{},\"max_xof_input\":{},\"xof_output_bytes\":{},\"max_xof_output\":{},\"lookup_reciprocal_rejections\":{},\"column_sampling_phases\":{},\"column_values_sampled\":{},\"column_candidate_draws\":{},\"max_column_candidates_per_value\":{},\"field_sampling_phases\":{},\"field_values_sampled\":{},\"field_candidate_draws\":{},\"max_field_candidates_per_value\":{},\"field_output_bytes\":{},\"max_field_phase_output_bytes\":{},\"max_field_values_per_phase\":{},\"max_column_values_per_phase\":{},\"direct_primitive_calls_included\":false,\"security_qualified\":false,\"performance_gate\":false}}",
        counts.hash_queries,
        counts.xof_queries,
        counts.xof_input_bytes,
        counts.max_xof_input,
        counts.xof_output_bytes,
        counts.max_xof_output,
        counts.lookup_reciprocal_rejections,
        counts.column_sampling_phases,
        counts.column_values_sampled,
        counts.column_candidate_draws,
        counts.max_column_candidates_per_value,
        counts.field_sampling_phases,
        counts.field_values_sampled,
        counts.field_candidate_draws,
        counts.max_field_candidates_per_value,
        counts.field_output_bytes,
        counts.max_field_phase_output_bytes,
        counts.max_field_values_per_phase,
        counts.max_column_values_per_phase
    );
}

fn digest<T: Serialize>(value: &T) -> String {
    format!(
        "{:x}",
        Sha256::digest(bincode::serde::encode_to_vec(value, bincode::config::standard()).unwrap())
    )
}
struct Options {
    backend: Backend,
    toy: bool,
    fresh: bool,
    role_queries: [usize; 4],
    fragment_vars: usize,
    blowup: usize,
    helper_basis: bool,
    atomic_ntt: bool,
    atomic_phases: bool,
    atomic_zerocheck: bool,
    atomic_columns: bool,
    reader_events: bool,
}
fn run<F, E, P>(bundle: ProfileParameters<P>, native: FheParameters<F>, options: &Options)
where
    F: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: NativeAuditBackend<F, E>,
    P::SingleProof: DeserializeOwned,
    P::BatchProof: DeserializeOwned,
{
    #[cfg(feature = "transcript-audit")]
    let reader_directory = options.reader_events.then(|| {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../target/performance/native-reader-event-traces")
            .join(format!("run-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        path
    });
    if !options.toy {
        assert_eq!(
            (native.ring_dimension(), native.lwe_dimension()),
            (1024, 728)
        );
    }
    let cfg =
        pbs::Config::new::<F>(native.ring_dimension(), native.lwe_dimension(), 8, 5, 1, 1).unwrap();
    let fhe_digest = format!("{:x}", Sha256::digest(format!("{native:?}")));
    let mut seed = [0; 16];
    seed[..8].copy_from_slice(&42u64.to_le_bytes());
    let secret = SecretKeyPack::with_rng(native, Prg::from_seed(Block::from(seed)));
    let encryptor = Encryptor::new(secret.clone());
    let decryptor = Decryptor::new(secret.clone());
    let evaluator =
        Evaluator::from_public_evaluation_key(Evaluator::new(&secret).public_evaluation_key());
    let br = evaluator.binary_bootstrap_key().unwrap();
    let ks = evaluator.rlwe_key_switching_key().unwrap();
    let br_data: Vec<_> = br
        .iter()
        .map(|r| {
            (
                r.basis().bits(),
                [r.c_neg_s_m(), r.c_m()]
                    .map(|g| g.data().iter().map(|p| p.a_b_slice()).collect::<Vec<_>>()),
            )
        })
        .collect();
    let ks_data: Vec<_> = ks
        .as_slice()
        .iter()
        .map(|g| {
            (
                g.basis().bits(),
                g.data().iter().map(|p| p.a_b_slice()).collect::<Vec<_>>(),
            )
        })
        .collect();
    let key_digest = digest(&(br_data, ks_data));
    let descriptor =
        bincode::serde::encode_to_vec(bundle.profile(), bincode::config::standard()).unwrap();
    let profile_digest = format!("{:x}", Sha512::digest(&descriptor));
    eprintln!(
        "preprocess field={} backend={:?} native={}",
        F::MODULUS_VALUE,
        options.backend,
        !options.toy
    );
    let preprocess = || {
        classical::preprocess::<F, E, P, _>(
            &bundle,
            cfg,
            br,
            ks.as_slice(),
            &mut StdRng::seed_from_u64(941),
        )
    };
    #[cfg(feature = "transcript-audit")]
    let (setup, setup_activity) =
        classical::oracle_audit::measure_standard_sha512(preprocess).unwrap();
    #[cfg(not(feature = "transcript-audit"))]
    let setup = preprocess();
    let setup = setup.unwrap();
    let expected = setup.verifier();
    let setup_digest = digest(&expected);
    let profile_id = bundle
        .profile()
        .id()
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let fragment_vars = if matches!(
        options.backend,
        Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual
    ) {
        options.fragment_vars.to_string()
    } else {
        "null".to_owned()
    };
    let specification = bundle.profile().specification();
    let descriptor_hex: String = descriptor.iter().map(|b| format!("{b:02x}")).collect();
    println!(
        "HB_CLASSICAL_PROFILE {{\"profile_id_sha512\":\"{profile_id}\",\"profile_descriptor_sha512\":\"{profile_digest}\",\"descriptor_bincode_hex\":\"{descriptor_hex}\",\"descriptor_version\":{},\"prime\":\"{}\",\"extension_degree\":{},\"backend\":\"{:?}\",\"role_variables\":{:?},\"role_widths\":{:?},\"role_queries\":{:?},\"blowup\":{},\"fragment_vars\":{fragment_vars}}}",
        bundle.profile().version(),
        F::MODULUS_VALUE,
        E::D,
        specification.backend,
        specification.roles.each_ref().map(|role| role.num_vars),
        specification.roles.each_ref().map(|role| role.width),
        specification.roles.each_ref().map(|role| role.queries),
        specification.blowup,
    );
    if options.reader_events {
        let contexts: Vec<String> = bundle
            .roles()
            .iter()
            .map(|role| {
                let context = <P as CanonicalPcs<F, Sha512>>::context(role)
                    .unwrap_or_else(|error| panic!("{error}"));
                context.0.iter().map(|byte| format!("{byte:02x}")).collect()
            })
            .collect();
        println!(
            "HB_CLASSICAL_ROLE_CONTEXTS {{\"profile_id_sha512\":\"{profile_id}\",\"role_contexts_sha512\":{contexts:?},\"caller_factory_contexts\":true,\"native\":{},\"ring_dimension\":{},\"lwe_dimension\":{},\"security_qualified\":false,\"performance_gate\":false}}",
            !options.toy,
            evaluator.parameters().ring_dimension(),
            evaluator.parameters().lwe_dimension()
        );
    }
    #[cfg(feature = "transcript-audit")]
    emit_honest_activity(
        "setup",
        None,
        None,
        &profile_id,
        &setup_digest,
        !options.toy,
        evaluator.parameters().ring_dimension(),
        evaluator.parameters().lwe_dimension(),
        &setup_activity,
    );
    let schedule: Vec<(usize, usize)> = if options.fresh {
        [1, 4, 16]
            .into_iter()
            .flat_map(|group| (0..group).map(move |i| (group, i)))
            .collect()
    } else {
        (0..4).map(|i| (4, i)).collect()
    };
    let uniform = options
        .role_queries
        .iter()
        .all(|&q| q == options.role_queries[0]);
    let query_count = if uniform {
        options.role_queries[0].to_string()
    } else {
        "null".to_owned()
    };
    let query_suffix = if uniform {
        String::new()
    } else {
        format!(",\"role_queries\":{:?}", options.role_queries)
    };
    for (ordinal, (group, index)) in schedule.into_iter().enumerate() {
        let left = ordinal / 2 % 2;
        let right = ordinal % 2;
        let x = encryptor.encrypt(left.as_into());
        let y = encryptor.encrypt(right.as_into());
        let (out, trace) = evaluator.nand(&x, &y);
        assert_eq!(out.a().len(), evaluator.parameters().lwe_dimension());
        let want: <F as Field>::Value = (1 - left * right).as_into();
        assert_eq!(decryptor.decrypt_with_noise(&out).0, want);
        let statement = pbs::Statement {
            left_a: x.a(),
            left_b: x.b(),
            right_a: y.a(),
            right_b: y.b(),
            output_a: out.a(),
            output_b: out.b(),
        };
        let statement_digest = digest(&statement);
        eprintln!("prove ordinal={ordinal} left={left} right={right}");
        let prove = || {
            classical::prove::<F, E, P, _>(
                &bundle,
                &setup,
                &statement,
                &trace,
                &mut StdRng::seed_from_u64(950 + ordinal as u64),
            )
        };
        #[cfg(feature = "transcript-audit")]
        let (proof, prove_activity) =
            classical::oracle_audit::measure_standard_sha512(prove).unwrap();
        #[cfg(not(feature = "transcript-audit"))]
        let proof = prove();
        let proof = proof.unwrap();
        drop(trace);
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        drop(proof);
        let (decoded, used): (classical::Proof<F, E, P::SingleProof, P::BatchProof>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        classical::verify::<F, E, P>(&bundle, &expected, &statement, &decoded).unwrap();
        #[cfg(feature = "transcript-audit")]
        {
            let capture = ReaderCapture::create(&reader_directory, ordinal, "accepted");
            let observed = P::observed_verification(
                &bundle,
                &expected,
                &statement,
                &decoded,
                capture.as_ref().map(ReaderCapture::callback),
            );
            if let Some(capture) = &capture {
                let ordinary =
                    P::observed_verification(&bundle, &expected, &statement, &decoded, None);
                ordinary.verification.unwrap();
                assert_eq!(ordinary.counts, observed.counts);
                capture.emit(
                    "accepted",
                    &profile_id,
                    &format!("{:x}", Sha256::digest(&bytes)),
                    &statement_digest,
                    &setup_digest,
                    !options.toy,
                    evaluator.parameters().ring_dimension(),
                    evaluator.parameters().lwe_dimension(),
                );
            }
            observed.verification.unwrap();
            let counts = observed.counts;
            assert!(counts.hash_queries > 0 && counts.xof_queries > 0);
            println!(
                "HB_CLASSICAL_ORACLE_COUNTS {{\"profile_id_sha512\":\"{profile_id}\",\"proof_sha256\":\"{:x}\",\"ordinal\":{ordinal},\"native\":{},\"ring_dimension\":{},\"lwe_dimension\":{},\"hash_queries\":{},\"hash_input_bytes\":{},\"max_hash_input\":{},\"xof_queries\":{},\"xof_input_bytes\":{},\"max_xof_input\":{},\"xof_output_bytes\":{},\"max_xof_output\":{},\"lookup_reciprocal_rejections\":{},\"column_sampling_phases\":{},\"column_values_sampled\":{},\"column_candidate_draws\":{},\"max_column_candidates_per_value\":{},\"field_sampling_phases\":{},\"field_values_sampled\":{},\"field_candidate_draws\":{},\"max_field_candidates_per_value\":{},\"field_output_bytes\":{},\"max_field_phase_output_bytes\":{},\"max_field_values_per_phase\":{},\"max_column_values_per_phase\":{},\"direct_primitive_calls_included\":false,\"security_qualified\":false,\"performance_gate\":false}}",
                Sha256::digest(&bytes),
                !options.toy,
                evaluator.parameters().ring_dimension(),
                evaluator.parameters().lwe_dimension(),
                counts.hash_queries,
                counts.hash_input_bytes,
                counts.max_hash_input,
                counts.xof_queries,
                counts.xof_input_bytes,
                counts.max_xof_input,
                counts.xof_output_bytes,
                counts.max_xof_output,
                counts.lookup_reciprocal_rejections,
                counts.column_sampling_phases,
                counts.column_values_sampled,
                counts.column_candidate_draws,
                counts.max_column_candidates_per_value,
                counts.field_sampling_phases,
                counts.field_values_sampled,
                counts.field_candidate_draws,
                counts.max_field_candidates_per_value,
                counts.field_output_bytes,
                counts.max_field_phase_output_bytes,
                counts.max_field_values_per_phase,
                counts.max_column_values_per_phase
            );
        }

        #[cfg(feature = "transcript-audit")]
        emit_honest_activity(
            "prove",
            Some(ordinal),
            Some(&format!("{:x}", Sha256::digest(&bytes))),
            &profile_id,
            &setup_digest,
            !options.toy,
            evaluator.parameters().ring_dimension(),
            evaluator.parameters().lwe_dimension(),
            &prove_activity,
        );
        let mut altered = statement.clone();
        altered.output_b += F::one();
        assert!(classical::verify::<F, E, P>(&bundle, &expected, &altered, &decoded).is_err());
        #[cfg(feature = "transcript-audit")]
        {
            let capture = ReaderCapture::create(&reader_directory, ordinal, "rejected");
            let observed = P::observed_verification(
                &bundle,
                &expected,
                &altered,
                &decoded,
                capture.as_ref().map(ReaderCapture::callback),
            );
            if let Some(capture) = &capture {
                let ordinary =
                    P::observed_verification(&bundle, &expected, &altered, &decoded, None);
                assert!(ordinary.verification.is_err());
                assert_eq!(ordinary.counts, observed.counts);
                capture.emit(
                    "rejected",
                    &profile_id,
                    &format!("{:x}", Sha256::digest(&bytes)),
                    &digest(&altered),
                    &setup_digest,
                    !options.toy,
                    evaluator.parameters().ring_dimension(),
                    evaluator.parameters().lwe_dimension(),
                );
            }
            assert!(observed.verification.is_err());
            let counts = observed.counts;
            let altered_statement_digest = digest(&altered);
            println!(
                "HB_CLASSICAL_ORACLE_REJECTION_COUNTS {{\"profile_id_sha512\":\"{profile_id}\",\"proof_sha256\":\"{:x}\",\"altered_statement_sha256\":\"{altered_statement_digest}\",\"ordinal\":{ordinal},\"native\":{},\"ring_dimension\":{},\"lwe_dimension\":{},\"rejected\":true,\"hash_queries\":{},\"hash_input_bytes\":{},\"max_hash_input\":{},\"xof_queries\":{},\"xof_input_bytes\":{},\"max_xof_input\":{},\"xof_output_bytes\":{},\"max_xof_output\":{},\"lookup_reciprocal_rejections\":{},\"column_sampling_phases\":{},\"column_values_sampled\":{},\"column_candidate_draws\":{},\"max_column_candidates_per_value\":{},\"field_sampling_phases\":{},\"field_values_sampled\":{},\"field_candidate_draws\":{},\"max_field_candidates_per_value\":{},\"field_output_bytes\":{},\"max_field_phase_output_bytes\":{},\"max_field_values_per_phase\":{},\"max_column_values_per_phase\":{},\"direct_primitive_calls_included\":false,\"security_qualified\":false,\"performance_gate\":false}}",
                Sha256::digest(&bytes),
                !options.toy,
                evaluator.parameters().ring_dimension(),
                evaluator.parameters().lwe_dimension(),
                counts.hash_queries,
                counts.hash_input_bytes,
                counts.max_hash_input,
                counts.xof_queries,
                counts.xof_input_bytes,
                counts.max_xof_input,
                counts.xof_output_bytes,
                counts.max_xof_output,
                counts.lookup_reciprocal_rejections,
                counts.column_sampling_phases,
                counts.column_values_sampled,
                counts.column_candidate_draws,
                counts.max_column_candidates_per_value,
                counts.field_sampling_phases,
                counts.field_values_sampled,
                counts.field_candidate_draws,
                counts.max_field_candidates_per_value,
                counts.field_output_bytes,
                counts.max_field_phase_output_bytes,
                counts.max_field_values_per_phase,
                counts.max_column_values_per_phase
            );
        }

        println!(
            "HB_CLASSICAL_VALIDATION {{\"prime\":\"{}\",\"extension_degree\":{},\"backend\":\"{:?}\",\"protocol_version\":12,\"original_size\":{},\"ring_dimension\":{},\"lwe_dimension\":{},\"output_dimension\":{},\"ordinal\":{ordinal},\"group_size\":{group},\"group_index\":{index},\"left\":{left},\"right\":{right},\"output\":{},\"queries\":{},\"fragment_vars\":{fragment_vars},\"fhe_parameters_sha256\":\"{fhe_digest}\",\"native_keys_sha256\":\"{key_digest}\",\"profile_descriptor_sha512\":\"{profile_digest}\",\"profile_id_sha512\":\"{profile_id}\",\"trusted_setup_sha256\":\"{setup_digest}\",\"statement_sha256\":\"{statement_digest}\",\"proof_sha256\":\"{:x}\",\"proof_bytes\":{},\"decoded_verified\":true,\"altered_output_rejected\":true,\"reused_public_key_setup\":true,\"separate_single_proofs\":true,\"correctness_only\":true,\"security_qualified\":false,\"performance_gate\":false{query_suffix}}}",
            F::MODULUS_VALUE,
            E::D,
            options.backend,
            !options.toy,
            evaluator.parameters().ring_dimension(),
            evaluator.parameters().lwe_dimension(),
            out.a().len(),
            1 - left * right,
            query_count,
            Sha256::digest(&bytes),
            bytes.len()
        );
    }
}
fn exercise<F, E>(native: FheParameters<F>, width: usize, options: &Options)
where
    F: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    eprintln!("geometry width={width} blowup={}", options.blowup);
    let cfg =
        pbs::Config::new::<F>(native.ring_dimension(), native.lwe_dimension(), 8, 5, 1, 1).unwrap();
    let variables = cfg.variables(width).unwrap();
    let roles = std::array::from_fn(|index| {
        let num_vars = variables[index];
        Role {
            num_vars,
            width: if options.helper_basis && index % 2 == 1 {
                E::D
            } else {
                width
            },
            queries: options.role_queries[index],
            left_vars: (options.backend == Backend::Brakedown).then_some(num_vars / 2),
            block_width: (options.backend == Backend::Brakedown).then_some(width),
        }
    });
    eprintln!("role widths={:?}", roles.each_ref().map(|role| role.width));
    let specification = Specification {
        backend: options.backend,
        roles,
        blowup: options.blowup,
        fragment_vars: matches!(
            options.backend,
            Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual
        )
        .then_some(options.fragment_vars),
    };
    let profile = if options.atomic_columns {
        ClassicalProfile::new_atomic_columns::<F, E>(specification)
    } else if options.atomic_zerocheck {
        ClassicalProfile::new_atomic_zerocheck::<F, E>(specification)
    } else if options.atomic_phases {
        ClassicalProfile::new_atomic_phases::<F, E>(specification)
    } else if options.atomic_ntt {
        ClassicalProfile::new_atomic_ntt::<F, E>(specification)
    } else {
        ClassicalProfile::new::<F, E>(specification)
    }
    .unwrap();
    match options.backend {
        Backend::Brakedown => run::<F, E, _>(
            profile.brakedown_parameters::<F, E>().unwrap(),
            native,
            options,
        ),
        Backend::Polyfrim => run::<F, E, _>(
            profile.polyfrim_parameters::<F, E>().unwrap(),
            native,
            options,
        ),
        Backend::PolyfrimDictionary => run::<F, E, _>(
            profile.polyfrim_dictionary_parameters::<F, E>().unwrap(),
            native,
            options,
        ),
        Backend::FragmentedPipfri => run::<F, E, _>(
            profile.fragmented_parameters::<F, E>().unwrap(),
            native,
            options,
        ),
        Backend::FragmentedPipfriVirtual => run::<F, E, _>(
            profile.fragmented_virtual_parameters::<F, E>().unwrap(),
            native,
            options,
        ),
    }
}
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let field = args.first().expect("field: babybear or goldilocks");
    let backend = match args.get(1).map(String::as_str) {
        Some("brakedown") => Backend::Brakedown,
        Some("polyfrim") => Backend::Polyfrim,
        Some("dictionary") => Backend::PolyfrimDictionary,
        Some("fragmented") => Backend::FragmentedPipfri,
        Some("virtual") => Backend::FragmentedPipfriVirtual,
        _ => panic!("backend: brakedown, polyfrim, dictionary, fragmented or virtual"),
    };
    let toy = args.iter().any(|a| a == "--toy");
    let mut position = 2;
    while position < args.len() {
        match args[position].as_str() {
            "--toy" | "--fresh-21" | "--helper-basis" | "--atomic-ntt" | "--atomic-phases"
            | "--atomic-zerocheck" | "--atomic-columns" | "--reader-events" => position += 1,
            "--queries" | "--role-queries" | "--fragment-vars" | "--width" | "--blowup"
            | "--extension-degree" => {
                assert!(position + 1 < args.len(), "missing option value");
                position += 2;
            }
            other => panic!("unknown option: {other}"),
        }
    }
    let number = |name: &str, default: usize| {
        args.iter()
            .position(|a| a == name)
            .map(|i| {
                args.get(i + 1)
                    .expect("missing number")
                    .parse::<usize>()
                    .expect("invalid number")
            })
            .unwrap_or(default)
    };
    let role_queries: [usize; 4] =
        if let Some(position) = args.iter().position(|a| a == "--role-queries") {
            assert!(
                !args.iter().any(|a| a == "--queries"),
                "choose --queries or --role-queries"
            );
            args[position + 1]
                .split(',')
                .map(|q| q.trim().parse::<usize>().expect("invalid role query count"))
                .collect::<Vec<_>>()
                .try_into()
                .expect("four role query counts required")
        } else {
            [number("--queries", 1); 4]
        };
    let options = Options {
        backend,
        toy,
        fresh: args.iter().any(|a| a == "--fresh-21"),
        role_queries,
        fragment_vars: number("--fragment-vars", if toy { 4 } else { 12 }),
        blowup: number("--blowup", 2),
        helper_basis: args.iter().any(|a| a == "--helper-basis"),
        atomic_ntt: args.iter().any(|a| a == "--atomic-ntt"),
        atomic_phases: args.iter().any(|a| a == "--atomic-phases"),
        atomic_zerocheck: args.iter().any(|a| a == "--atomic-zerocheck"),
        atomic_columns: args.iter().any(|a| a == "--atomic-columns"),
        reader_events: args.iter().any(|a| a == "--reader-events"),
    };
    assert!(
        !options.reader_events || cfg!(feature = "transcript-audit"),
        "reader event recording requires transcript-audit"
    );
    assert!(
        usize::from(options.atomic_ntt)
            + usize::from(options.atomic_phases)
            + usize::from(options.atomic_zerocheck)
            + usize::from(options.atomic_columns)
            <= 1,
        "choose one atomic schedule"
    );
    assert!(options.role_queries.iter().all(|&q| q > 0));
    assert!(
        !options.helper_basis
            || !matches!(
                backend,
                Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual
            ),
        "fragmented helper packing must match source width"
    );
    assert!([2, 4, 8].contains(&options.blowup), "blowup: 2, 4 or 8");
    let width = match field.as_str() {
        "babybear" => {
            let width = number("--width", 8);
            assert!([8, 16].contains(&width), "BabyBear width: 8 or 16");
            width
        }
        "goldilocks" => {
            let width = number("--width", 4);
            assert!([4, 8].contains(&width), "Goldilocks width: 4 or 8");
            width
        }
        _ => panic!("field: babybear or goldilocks"),
    };
    if !toy {
        assert!([8, 10, 12, 14, 16].contains(&options.fragment_vars));
    }
    assert_eq!(rayon::current_num_threads(), 16, "set RAYON_NUM_THREADS=16");
    let degree = number(
        "--extension-degree",
        if field == "babybear" { 6 } else { 3 },
    );
    macro_rules! dispatch {
        ($base:ty, $extension:ty, $native:expr) => {
            exercise::<$base, $extension>(
                if toy { fixture::params() } else { *$native },
                width,
                &options,
            )
        };
    }
    match (field.as_str(), degree) {
        ("babybear", 4) => dispatch!(
            algebra::BabyBear,
            algebra::BabyBearExetension,
            BABYBEAR_BINARY_128_BITS_PARAMETERS
        ),
        ("babybear", 5) => dispatch!(
            algebra::BabyBear,
            algebra::BabyBearExtension5,
            BABYBEAR_BINARY_128_BITS_PARAMETERS
        ),
        ("babybear", 6) => dispatch!(
            algebra::BabyBear,
            algebra::BabyBearExtension6,
            BABYBEAR_BINARY_128_BITS_PARAMETERS
        ),
        ("babybear", 8) => dispatch!(
            algebra::BabyBear,
            algebra::BabyBearExtension8,
            BABYBEAR_BINARY_128_BITS_PARAMETERS
        ),
        ("goldilocks", 2) => dispatch!(
            algebra::Goldilocks,
            algebra::GoldilocksExtension,
            GOLDILOCKS_BINARY_128_BITS_PARAMETERS
        ),
        ("goldilocks", 3) => dispatch!(
            algebra::Goldilocks,
            algebra::GoldilocksExtension3,
            GOLDILOCKS_BINARY_128_BITS_PARAMETERS
        ),
        ("goldilocks", 4) => dispatch!(
            algebra::Goldilocks,
            algebra::GoldilocksExtension4,
            GOLDILOCKS_BINARY_128_BITS_PARAMETERS
        ),
        ("goldilocks", 5) => dispatch!(
            algebra::Goldilocks,
            algebra::GoldilocksExtension5,
            GOLDILOCKS_BINARY_128_BITS_PARAMETERS
        ),
        _ => panic!("extension degree: BabyBear 4/5/6/8 or Goldilocks 2/3/4/5"),
    }
}
