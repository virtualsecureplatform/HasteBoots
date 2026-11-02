//! Replay generic temporal checks on an explicitly identified saved control.
//! This does not regenerate a proof or repeat source-word authentication.
use super::*;

fn fixture<F: NTTField, EF: AbstractExtensionField<F>>(
    version: u32,
    backend: Backend,
    block_width: usize,
) -> ClassicalProfile {
    assert!(matches!(version, 4 | 5), "unsupported replay schedule");
    assert!(
        block_width == 8 || (backend == Backend::Brakedown && block_width == 2),
        "unsupported replay fixture block width"
    );
    let cfg = Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
    let roles = cfg.variables(8).unwrap().map(|num_vars| Role {
        num_vars,
        width: 8,
        queries: 8,
        left_vars: (backend == Backend::Brakedown).then_some(num_vars / 2),
        block_width: (backend == Backend::Brakedown).then_some(block_width),
    });
    let spec = Specification {
        backend,
        roles,
        blowup: 2,
        fragment_vars: matches!(
            backend,
            Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual
        )
        .then_some(8),
    };
    if version == 4 {
        ClassicalProfile::new_atomic_zerocheck::<F, EF>(spec)
    } else {
        ClassicalProfile::new_atomic_columns::<F, EF>(spec)
    }
    .unwrap()
}

fn replay<F: NTTField, EF: AbstractExtensionField<F>>(
    version: u32,
    backend: Backend,
    block_width: usize,
    path: &std::path::Path,
    fingerprint: &str,
) {
    let profile = fixture::<F, EF>(version, backend, block_width);
    let report = temporal_child_stream_audit::check::<F, EF>(&profile, path, fingerprint).unwrap();
    assert_eq!(report.identities[0], 0);
    assert_eq!(report.identities[1], report.identities[2]);
    assert_eq!(report.later[1], report.later[2]);
    assert!(report.seeds[2] >= 3 && report.same_prover_verifier_seeds);
    assert_eq!(report.captured_availability_hits, [0, 0]);
    assert!(report.replayed_receipt_frames > 0);
    let profile_id: String = profile.id().0.iter().map(|b| format!("{b:02x}")).collect();
    println!(
        "HB_PRESERVED_COMPLETE_TEMPORAL {{\"prime\":\"{}\",\"degree\":{},\"version\":{},\"backend\":\"{:?}\",\"n\":32,\"lwe\":21,\"width\":8,\"queries\":8,\"block_width\":{},\"profile_id\":\"{}\",\"trace_sha512\":\"{}\",\"initial_identity_requests\":{:?},\"later_child_requests\":{:?},\"unique_child_seeds\":{:?},\"captured_availability_hits\":{:?},\"replayed_receipt_frames\":{},\"generic_completed_phase_streams_checked\":true,\"all_captured_input_windows_checked\":true,\"same_prover_verifier_seed_sets\":true,\"xof_output_collisions\":0,\"all_input_windows_registered\":false,\"availability_filter_checked\":false,\"source_words_rechecked\":false,\"encrypted_native\":false,\"security_qualified\":false}}",
        F::MODULUS_VALUE,
        EF::D,
        version,
        backend,
        block_width,
        profile_id,
        fingerprint,
        report.identities,
        report.later,
        report.seeds,
        report.captured_availability_hits,
        report.replayed_receipt_frames,
    );
}

#[test]
#[ignore = "requires explicit HB_REPLAY_* metadata and an immutable complete-PBS event trace"]
fn replay_preserved_complete_pbs_temporal_trace() {
    let required = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("missing {name}"));
    let path = required("HB_REPLAY_TRACE");
    let fingerprint = required("HB_REPLAY_SHA512");
    assert!(
        fingerprint.len() == 128 && fingerprint.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid replay trace SHA512"
    );
    let fingerprint = fingerprint.to_ascii_lowercase();
    let prime = required("HB_REPLAY_PRIME");
    let version: u32 = required("HB_REPLAY_VERSION")
        .parse()
        .expect("invalid replay version");
    let backend = match required("HB_REPLAY_BACKEND").as_str() {
        "Brakedown" => Backend::Brakedown,
        "Polyfrim" => Backend::Polyfrim,
        "PolyfrimDictionary" => Backend::PolyfrimDictionary,
        "FragmentedPipfri" => Backend::FragmentedPipfri,
        "FragmentedPipfriVirtual" => Backend::FragmentedPipfriVirtual,
        _ => panic!("unsupported replay backend"),
    };
    let block_width: usize = required("HB_REPLAY_BLOCK_WIDTH")
        .parse()
        .expect("invalid replay block width");
    let path = std::path::Path::new(&path);
    match prime.as_str() {
        "2013265921" => replay::<algebra::BabyBear, algebra::BabyBearExtension6>(
            version,
            backend,
            block_width,
            path,
            &fingerprint,
        ),
        "18446744069414584321" => replay::<algebra::Goldilocks, algebra::GoldilocksExtension3>(
            version,
            backend,
            block_width,
            path,
            &fingerprint,
        ),
        _ => panic!("unsupported replay field"),
    }
}
