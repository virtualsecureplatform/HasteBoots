//! Both interpolation and fallback must enforce one whole-column radius.
#[path = "support/classical_decode.rs"]
mod classical_decode;
use algebra::NTTField;

fn exercise<F: NTTField>() {
    let points = (0..9).map(F::from).collect::<Vec<_>>();
    let polynomials = (0..3)
        .map(|i| {
            vec![
                F::from(1 + i),
                F::from(3 + i),
                F::from(5 + i),
                F::from(7 + i),
            ]
        })
        .collect::<Vec<_>>();
    let word = points
        .iter()
        .map(|&point| {
            polynomials
                .iter()
                .map(|poly| {
                    poly.iter()
                        .rev()
                        .fold(F::zero(), |value, &coefficient| value * point + coefficient)
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        classical_decode::joint(&points, &word, 4, 2).unwrap(),
        polynomials
    );
    // Exhaust every pair of error positions, including entirely clean prefixes,
    // entirely corrupt prefixes and mixed positions. Coordinate errors vary.
    for left in 0..points.len() {
        for right in left + 1..points.len() {
            let mut changed = word.clone();
            changed[left][left % 3] += F::one();
            changed[right][right % 3] += F::from(2);
            assert_eq!(
                classical_decode::joint(&points, &changed, 4, 2).unwrap(),
                polynomials
            );
        }
    }
    let mut disjoint = word.clone();
    for i in 0..3 {
        disjoint[i][i] += F::one();
    }
    assert!(classical_decode::joint(&points, &disjoint, 4, 2).is_none());
    let mut duplicate = points.clone();
    duplicate[1] = duplicate[0];
    assert!(classical_decode::joint(&duplicate, &word, 4, 2).is_none());
    assert!(classical_decode::joint(&points[..6], &word[..6], 4, 2).is_none());
    assert!(classical_decode::joint(&points, &word, 0, 2).is_none());
}
#[test]
fn interpolation_and_fallback_enforce_joint_radius() {
    exercise::<algebra::BabyBear>();
    exercise::<algebra::Goldilocks>();
}
