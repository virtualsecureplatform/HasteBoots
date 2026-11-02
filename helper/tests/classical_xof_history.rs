#[path = "support/classical_xof_history.rs"]
mod history;

#[cfg(feature = "transcript-audit")]
#[test]
fn sampler_reader_chunks_feed_the_prefix_history_without_recreating_outputs() {
    use helper::classical_transcript::{ClassicalTranscript, audit};
    use history::{History, QueryActor};
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };
    let chunks = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&chunks);
    let guard = audit::observe_with_output_chunks(
        |_| {},
        |_| {},
        move |input, offset, output| {
            sink.lock()
                .unwrap()
                .push((input.to_vec(), offset, output.to_vec()));
        },
    )
    .unwrap();
    let mut transcript = ClassicalTranscript::new(b"reader provenance integration", &[3; 64]);
    let base = transcript.challenge_prime::<algebra::BabyBear>(b"base", 32);
    let extension = transcript
        .challenge_extension::<algebra::BabyBear, algebra::BabyBearExtension6>(b"extension", 32);
    let mut bytes = [0; 80];
    transcript.challenge_bytes(b"bytes", &mut bytes);
    drop(guard);
    let mut streams = HashMap::<Vec<u8>, Vec<u8>>::new();
    for (input, offset, output) in chunks.lock().unwrap().iter() {
        let stream = streams.entry(input.clone()).or_default();
        assert_eq!(*offset, stream.len() as u128);
        stream.extend_from_slice(output);
    }
    assert_eq!(streams.len(), 5); // Two field streams, their receipts, bytes.
    let mut recorded = History::default();
    for (input, output) in &streams {
        // All these actual reads exceed the history's 64-byte minimum, so no
        // virtual completion or independent oracle output is supplied here.
        assert!(output.len() >= 64);
        recorded
            .query_output_prefix(input, output, QueryActor::Verifier)
            .unwrap();
    }
    let answered = recorded.checkpoint();
    for (input, output) in &streams {
        assert_eq!(
            recorded.output_prefix_at(&answered, input),
            Some(output.as_slice())
        );
    }
    let mut replay = ClassicalTranscript::new(b"reader provenance integration", &[3; 64]);
    assert_eq!(
        replay.challenge_prime::<algebra::BabyBear>(b"base", 32),
        base
    );
    assert_eq!(
        replay.challenge_extension::<algebra::BabyBear, algebra::BabyBearExtension6>(
            b"extension",
            32,
        ),
        extension
    );
    let mut replay_bytes = [0; 80];
    replay.challenge_bytes(b"bytes", &mut replay_bytes);
    assert_eq!(replay_bytes, bytes);
}

#[test]
fn incremental_shake_reader_prefixes_preserve_first_exposure() {
    use history::{History, QueryActor};
    use sha3::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };

    let input = b"recorded full sampler stream";
    let mut shake = Shake256::default();
    shake.update(input);
    let mut reader = shake.finalize_xof();
    let mut prefix = vec![0; 64];
    reader.read(&mut prefix);
    let mut recorded = History::default();
    let before = recorded.checkpoint();
    let first = recorded
        .query_output_prefix(input, &prefix, QueryActor::Adversary)
        .unwrap();
    let short_boundary = recorded.checkpoint();
    let exposure = recorded.exposure();
    prefix.resize(4096, 0);
    reader.read(&mut prefix[64..]);
    let replay = recorded
        .query_output_prefix(input, &prefix, QueryActor::Verifier)
        .unwrap();
    let long_boundary = recorded.checkpoint();
    assert!(recorded.input_is_original_view(&first, input));
    assert!(recorded.input_is_original_view(&replay, input));
    assert_eq!(
        recorded.first_query_actor(&replay, input),
        Some(QueryActor::Adversary)
    );
    assert_eq!(recorded.exposure(), exposure);
    assert!(recorded.output_prefix_at(&before, input).is_none());
    assert_eq!(
        recorded.output_prefix_at(&short_boundary, input),
        Some(&prefix[..64])
    );
    assert_eq!(
        recorded.output_prefix_at(&long_boundary, input),
        Some(prefix.as_slice())
    );

    // An independently restarted real reader yields the same long prefix.
    let mut restarted = Shake256::default();
    restarted.update(input);
    let mut full = vec![0; prefix.len()];
    restarted.finalize_xof().read(&mut full);
    assert_eq!(prefix, full);
    recorded
        .query_output_prefix(input, &full, QueryActor::Setup)
        .unwrap();
    recorded
        .query(input, prefix[..64].try_into().unwrap())
        .unwrap();
    assert_eq!(
        recorded.output_prefix_at(&recorded.checkpoint(), input),
        Some(prefix.as_slice())
    );

    // Matching receipts alone cannot authorize different bytes in the tail.
    full[160] ^= 1;
    assert!(
        recorded
            .query_output_prefix(input, &full, QueryActor::Setup)
            .is_err()
    );
    assert_eq!(recorded.exposure(), exposure);
    assert_eq!(
        recorded.output_prefix_at(&recorded.checkpoint(), input),
        Some(prefix.as_slice())
    );
    assert!(
        recorded
            .query_output_prefix(b"short", &[0; 63], QueryActor::Verifier)
            .is_err()
    );
    assert!(recorded.first_view(b"short").is_none());
    assert!(
        recorded
            .output_prefix_at(&History::default().checkpoint(), input)
            .is_none()
    );
}
