//! Temporal origin checks across all typed child families in a captured control.
use super::*;

pub(super) fn seed_origin(
    profile: &ClassicalProfile,
    input: &[u8],
    label: &[u8],
    context: &[u8],
    seed: &[u8; 64],
) -> Option<()> {
    if shake64(input) != *seed {
        return None;
    }
    let mut rest = input;
    if message(&mut rest, 0, b"protocol")? != b"HasteBoots framed SHAKE256 v1" {
        return None;
    }
    let application = message(&mut rest, 0, b"application")?;
    if ![
        b"HasteBoots typed classical prime v1".as_slice(),
        b"HasteBoots typed classical extension v1".as_slice(),
        b"HasteBoots framed SHAKE256 child v1".as_slice(),
    ]
    .contains(&application)
        || message(&mut rest, 0, b"trusted profile")? != profile.id().0
    {
        return None;
    }
    let mut tail = Vec::new();
    frame(&mut tail, 6, label, context);
    frame(&mut tail, 2, b"classical child seed", &64u64.to_le_bytes());
    input.ends_with(&tail).then_some(())
}

pub(super) fn check<F, EF>(
    profile: &ClassicalProfile,
    events: &[Event],
    verifier: std::ops::Range<usize>,
) -> (usize, usize, usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    check_with_seed::<F, EF>(profile, events, verifier, |_, _, _| {})
}

pub(super) fn check_with_seed<F, EF>(
    profile: &ClassicalProfile,
    events: &[Event],
    verifier: std::ops::Range<usize>,
    mut seed_task: impl FnMut(&[u8], &[u8], &[u8]),
) -> (usize, usize, usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let mut history = classical_xof_history::History::default();
    let mut seen = std::collections::HashSet::<&[u8]>::new();
    let mut header = Vec::new();
    frame(
        &mut header,
        0,
        b"protocol",
        b"HasteBoots framed SHAKE256 v1",
    );
    frame(
        &mut header,
        0,
        b"application",
        b"HasteBoots framed SHAKE256 child v1",
    );
    frame(&mut header, 0, b"trusted profile", &profile.id().0);
    let empty_receipt = receipt(&[]).0;
    let empty_digest: [u8; 64] = empty_receipt[16..].try_into().unwrap();
    let mut identity_receipt = Vec::new();
    frame(
        &mut identity_receipt,
        5,
        b"typed extension identity",
        &empty_receipt,
    );
    let (mut checked, mut repeated_checked) = (0, 0);
    let mut identity_checked = 0;
    let mut seeds = std::collections::HashSet::new();
    for (index, event) in events.iter().enumerate() {
        let input = match event {
            Event::Hash(_, input) => {
                history.declare_external_input(input);
                continue;
            }
            Event::Xof(input) => input,
        };
        let repeated = !seen.insert(input.as_slice());
        let view = history.query(input, shake64(input)).unwrap();
        let Some(mut rest) = input.strip_prefix(header.as_slice()) else {
            continue;
        };
        let label = message(&mut rest, 1, b"child label").unwrap();
        let context = message(&mut rest, 1, b"child context").unwrap();
        let seed: [u8; 64] = message(&mut rest, 1, b"parent seed")
            .unwrap()
            .try_into()
            .unwrap();
        let identity = raw_child::<F, EF>(profile, label, context, &seed);
        if input == identity.strip_suffix(identity_receipt.as_slice()).unwrap() {
            // No empty receipt producer exists yet for this initial request.
            // Its seed producer must nevertheless be available in its own
            // original view, with the exact typed parent fork framing.
            let (parent_input, _) = history.producer_first_view(&view, &seed).unwrap();
            seed_origin(profile, parent_input, label, context, &seed).unwrap();
            if verifier.contains(&index) {
                assert!(repeated);
                identity_checked += 1;
                if seeds.insert(seed) {
                    seed_task(parent_input, label, context);
                }
            }
            continue;
        }
        assert!(input.starts_with(&identity));
        let mut before = Producers::new();
        for digest in [seed, empty_digest] {
            before.insert(digest, history.producer(&view, &digest).unwrap().to_vec());
        }
        let child = typed_child_prefix::<F, EF>(profile, input, &before).unwrap();
        let (parent_input, _) = history.producer_first_view(&view, &seed).unwrap();
        assert_eq!(child.parent_input, parent_input);
        assert_eq!(child.label, label);
        assert_eq!(child.context, context);
        if verifier.contains(&index) {
            checked += 1;
            repeated_checked += usize::from(repeated);
            if seeds.insert(seed) {
                seed_task(parent_input, label, context);
            }
        }
    }
    assert_eq!(history.availability_hits(), 0);
    assert_eq!(history.collisions(), 0);
    assert_eq!(checked, repeated_checked);
    assert!(checked + identity_checked > 0);
    (checked, seeds.len(), identity_checked)
}

#[test]
fn temporal_initial_identity_requires_an_earlier_typed_seed_producer() {
    type F = algebra::BabyBear;
    type EF = algebra::BabyBearExtension6;
    let profile = ClassicalProfile::new_atomic_columns::<F, EF>(Specification {
        backend: Backend::Brakedown,
        roles: std::array::from_fn(|_| Role {
            num_vars: 3,
            width: 8,
            queries: 8,
            left_vars: Some(1),
            block_width: Some(2),
        }),
        blowup: 2,
        fragment_vars: None,
    })
    .unwrap();
    let (label, context) = (b"child label".as_slice(), b"child context".as_slice());
    let mut parent = Vec::new();
    frame(
        &mut parent,
        0,
        b"protocol",
        b"HasteBoots framed SHAKE256 v1",
    );
    frame(
        &mut parent,
        0,
        b"application",
        b"HasteBoots typed classical prime v1",
    );
    frame(&mut parent, 0, b"trusted profile", &profile.id().0);
    frame(&mut parent, 6, label, context);
    frame(
        &mut parent,
        2,
        b"classical child seed",
        &64u64.to_le_bytes(),
    );
    let seed = shake64(&parent);
    assert!(seed_origin(&profile, &parent, label, context, &seed).is_some());
    assert!(seed_origin(&profile, &parent, b"wrong label", context, &seed).is_none());
    assert!(seed_origin(&profile, &parent, label, b"wrong context", &seed).is_none());
    let mut receipt_frame = Vec::new();
    frame(
        &mut receipt_frame,
        5,
        b"typed extension identity",
        &receipt(&[]).0,
    );
    let child = raw_child::<F, EF>(&profile, label, context, &seed);
    let request = child
        .strip_suffix(receipt_frame.as_slice())
        .unwrap()
        .to_vec();
    let events = vec![
        Event::Xof(parent.clone()),
        Event::Xof(request.clone()),
        Event::Xof(request.clone()),
    ];
    assert_eq!(check::<F, EF>(&profile, &events, 2..3), (0, 1, 1));
    let late = vec![
        Event::Xof(request.clone()),
        Event::Xof(parent),
        Event::Xof(request),
    ];
    assert!(std::panic::catch_unwind(|| check::<F, EF>(&profile, &late, 2..3)).is_err());
}
