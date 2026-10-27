use algebra::{BabyBear as F, Field, matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript, Transcript};
use sumcheck::{
    packed::{self, PackedShape},
    packed_zero,
};

fn fixture() -> (PackedShape<F>, Vec<PackedTable<F>>) {
    let make = |v| PackedTable::new(4, 2, v).unwrap();
    let a: Vec<_> = (0..32).map(|i| F::new(i + 1)).collect();
    let b: Vec<_> = a.iter().map(|&v| v + F::new(7)).collect();
    let c = a.iter().zip(&b).map(|(&a, &b)| a * b).collect();
    (
        PackedShape {
            num_vars: 4,
            width: 2,
            num_factors: 3,
            terms: vec![(F::new(1), vec![0, 1]), (-F::new(1), vec![2])],
        },
        vec![make(a), make(b), make(c)],
    )
}
#[test]
fn old_sumcheck_framing_matches_an_independent_replay() {
    let (mut shape, factors) = fixture();
    shape.terms.pop();
    let claim = packed::sum(&shape, &factors).unwrap();
    let mut t = Transcript::new_direct();
    let (proof, point) = packed::prove(&mut t, &shape, &factors, &claim).unwrap();
    // Original protocol labels/order, independently replayed without either
    // streaming wrapper. Empty callbacks must introduce no framing messages.
    let mut v = Transcript::new_direct();
    v.append_message(b"packed sumcheck v1", &shape);
    v.append_message(b"packed claimed sum", &claim.as_slice());
    let mut query = Vec::new();
    for round in &proof.rounds {
        v.append_message(b"packed round", round);
        query.push(
            packed::challenge_pair(&v.get_vec_challenge(b"packed independent challenges", 2))
                .unwrap(),
        );
    }
    assert_eq!(point.query, query);
    assert_eq!(t.get_challenge(b"after"), v.get_challenge(b"after"));
}
#[test]
fn oracle_callbacks_precede_future_zero_check_challenges() {
    let (shape, factors) = fixture();
    let mut old = Transcript::new_direct();
    let (_, old_point) = packed_zero::prove(&mut old, &shape, &factors).unwrap();
    let mut t = Transcript::new_direct();
    let mut called = Vec::new();
    let (proof, point, values) =
        packed_zero::prove_with_rounds(&mut t, &shape, &factors, |t, i, pair| {
            called.push(i);
            t.append_message(b"test committed oracle round", &(i, pair));
            Ok(())
        })
        .unwrap();
    assert_eq!(called, vec![0, 1, 2, 3]);
    assert_eq!(point.query[0], old_point.query[0]);
    assert_ne!(point.query[1], old_point.query[1]);
    point.check(&shape, &values).unwrap();
    let mut v = Transcript::new_direct();
    let mut verified = Vec::new();
    let claim = packed_zero::verify_with_rounds(&mut v, &shape, &proof, |t, i, pair| {
        verified.push(i);
        t.append_message(b"test committed oracle round", &(i, pair));
        Ok(())
    })
    .unwrap();
    assert_eq!(called, verified);
    assert_eq!(claim.query, point.query);
    let actual = factors
        .iter()
        .map(|f| f.evaluate(&claim.query).unwrap())
        .collect::<Vec<_>>();
    claim.check(&shape, &actual).unwrap();
    assert_eq!(t.get_challenge(b"after"), v.get_challenge(b"after"));
}
#[test]
fn oracle_callback_rejections_are_not_ignored() {
    let (shape, factors) = fixture();
    let fail = || sumcheck::error::Error::Reject(Some("oracle rejected".into()));
    assert!(
        packed_zero::prove_with_rounds(
            &mut Transcript::new_direct(),
            &shape,
            &factors,
            |_, _, _| Err(fail())
        )
        .is_err()
    );
    let (proof, _) = packed_zero::prove(&mut Transcript::new_direct(), &shape, &factors).unwrap();
    assert!(
        packed_zero::verify_with_rounds(
            &mut Transcript::new_direct(),
            &shape,
            &proof,
            |_, _, _| Err(fail())
        )
        .is_err()
    );
}
