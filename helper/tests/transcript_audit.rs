#![cfg(feature = "transcript-audit")]
use helper::classical_transcript::{ClassicalTranscript, audit};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::sync::{Arc, Mutex};

fn exercise() -> (
    Vec<algebra::BabyBear>,
    Vec<algebra::BabyBearExtension6>,
    Vec<usize>,
    [u8; 64],
) {
    let mut transcript = ClassicalTranscript::new(b"observed verifier", &[19; 64]);
    transcript.append_bytes(b"source root", &[73; 64]);
    let mut first = [0; 64];
    transcript.challenge_bytes(b"raw", &mut first);
    let prime = transcript.challenge_prime::<algebra::BabyBear>(b"prime", 3);
    let extension = transcript.with_child(b"PCS child", b"trusted parameters", |child| {
        child
            .challenge_extension::<algebra::BabyBear, algebra::BabyBearExtension6>(b"lanes", 2)
            .unwrap()
    });
    let indices = transcript.challenge_indices(b"columns", 32, 8).unwrap();
    let mut finish = [0; 64];
    transcript.challenge_bytes(b"finish", &mut finish);
    (prime, extension, indices, finish)
}
#[test]
fn exact_inputs_include_receipts_and_children_without_changing_outputs() {
    let inputs = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&inputs);
    let guard = audit::observe(move |input| observed.lock().unwrap().push(input.to_vec())).unwrap();
    assert!(audit::observe(|_| {}).is_err());
    let mut transcript = ClassicalTranscript::new(b"raw comparison", &[41; 64]);
    transcript.append_bytes(b"source", &[73; 64]);
    let mut output = [0; 64];
    transcript.challenge_bytes(b"draw", &mut output);
    // A single query has been reported before challenge_bytes returns.
    assert_eq!(inputs.lock().unwrap().len(), 1);
    let input = inputs.lock().unwrap()[0].clone();
    let mut reference = Shake256::default();
    reference.update(&input);
    let mut expected = [0; 64];
    reference.finalize_xof().read(&mut expected);
    assert_eq!(output, expected);
    let before_worker = inputs.lock().unwrap().len();
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                transcript.with_child(b"worker child", b"worker parameters", |child| {
                    child.challenge_prime::<algebra::BabyBear>(b"worker prime", 1)
                })
            })
            .join()
            .unwrap()
    });
    // Parent seed, worker prime phase, worker receipt fingerprint, child finish.
    assert_eq!(inputs.lock().unwrap().len(), before_worker + 4);
    let before_unrelated = inputs.lock().unwrap().len();
    std::thread::spawn(exercise).join().unwrap();
    assert_eq!(inputs.lock().unwrap().len(), before_unrelated);
    std::thread::spawn(|| {
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&count);
        let _guard = audit::observe(move |_| {
            observed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        })
        .unwrap();
        exercise();
        assert!(count.load(std::sync::atomic::Ordering::Relaxed) > 0);
    })
    .join()
    .unwrap();
    assert_eq!(inputs.lock().unwrap().len(), before_unrelated);
    let observed_result = exercise();
    let count = inputs.lock().unwrap().len();
    assert!(
        inputs
            .lock()
            .unwrap()
            .iter()
            .any(|input| input.starts_with(b"HasteBoots consumed field bytes v1"))
    );
    assert!(inputs.lock().unwrap().iter().any(|input| {
        input
            .windows(b"PCS child".len())
            .any(|part| part == b"PCS child")
    }));
    drop(guard);
    transcript.challenge_bytes(b"after observation scope", &mut output);
    assert_eq!(exercise(), observed_result);
    assert_eq!(inputs.lock().unwrap().len(), count);
}

#[test]
fn resource_events_follow_scope_and_workers_without_changing_bytes() {
    use audit::ResourceEvent::LookupReciprocalRejected;
    fn scenario() -> [u8; 64] {
        let mut parent = ClassicalTranscript::new(b"resource observation", &[91; 64]);
        parent.audit_resource_event(LookupReciprocalRejected);
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    parent.with_child(b"resource child", b"parameters", |child| {
                        child.audit_resource_event(LookupReciprocalRejected);
                        child.challenge_prime::<algebra::BabyBear>(b"worker field", 1)
                    })
                })
                .join()
                .unwrap();
        });
        let mut finish = [0; 64];
        parent.challenge_bytes(b"finish", &mut finish);
        finish
    }
    let events = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&events);
    let guard = audit::observe_with_resources(
        |_| {},
        move |event| {
            observed.lock().unwrap().push(event);
        },
    )
    .unwrap();
    let expected = scenario();
    let recorded = events.lock().unwrap().clone();
    assert_eq!(
        recorded
            .iter()
            .filter(|&&event| event == LookupReciprocalRejected)
            .count(),
        2
    );
    let field = recorded
        .iter()
        .filter_map(|event| match event {
            audit::ResourceEvent::FieldSampling {
                values,
                candidates,
                max_candidates_per_value,
                consumed_bytes,
            } => Some((
                *values,
                *candidates,
                *max_candidates_per_value,
                *consumed_bytes,
            )),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(field.len(), 1);
    assert_eq!(field[0].0, 1);
    assert!(field[0].1 >= 1 && field[0].2 == field[0].1);
    assert_eq!(field[0].3, 4 * field[0].1);
    let outputs = recorded
        .iter()
        .filter_map(|event| match event {
            audit::ResourceEvent::XofOutput {
                bytes,
                total_for_query,
            } => Some((*bytes, *total_for_query)),
            _ => None,
        })
        .collect::<Vec<_>>();
    // Child seed, sampled field bytes, field receipt, child finish, final bytes.
    assert_eq!(
        outputs.iter().map(|(bytes, _)| bytes).sum::<u128>(),
        4 * 64 + field[0].3
    );
    assert_eq!(outputs.iter().map(|(_, total)| *total).max(), Some(64));
    let field_reads = outputs
        .iter()
        .filter(|(bytes, _)| *bytes == 4)
        .collect::<Vec<_>>();
    assert_eq!(field_reads.len() as u128, field[0].1);
    assert_eq!(field_reads.last().unwrap().1, field[0].3);
    std::thread::spawn(scenario).join().unwrap();
    assert_eq!(events.lock().unwrap().len(), recorded.len());
    drop(guard);
    assert_eq!(scenario(), expected);
    assert_eq!(events.lock().unwrap().len(), recorded.len());
}
