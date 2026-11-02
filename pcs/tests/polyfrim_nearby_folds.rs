//! Local nearby-word consistency witnesses, not a PCS/FRI/FS soundness test.
use algebra::{
    matrix_weighted::{Matrix, MatrixPair},
    transformation::AbstractNTT,
    AbstractExtensionField, Field, NTTField,
};
use pcs::packed_polyfrim::fold_symbol;

fn scalar<E: Field>(value: usize) -> E {
    (0..value).fold(E::zero(), |a, _| a + E::one())
}
fn power<E: Field>(x: E, exponent: usize) -> E {
    (0..exponent).fold(E::one(), |a, _| a * x)
}
fn same<E: Field>(a: &[E; 2], b: &[E; 2]) -> bool {
    (0..2).all(|i| a[i].canonicalized() == b[i].canonicalized())
}
fn evaluate<E: Field>(coefficients: &[[E; 2]], x: E) -> [E; 2] {
    coefficients
        .iter()
        .rev()
        .fold([E::zero(); 2], |a, c| [a[0] * x + c[0], a[1] * x + c[1]])
}
fn apply<E: Field>(matrix: &[E], value: [E; 2]) -> [E; 2] {
    [
        matrix[0] * value[0] + matrix[1] * value[1],
        matrix[2] * value[0] + matrix[3] * value[1],
    ]
}
fn plus_inverse<E: Field>(pair: &MatrixPair<E>, beta: E) -> Option<[E; 4]> {
    // Changing only P(beta) changes the fold by (M0 + M1 + beta^-1 M1)/2.
    let half = (E::one() + E::one()).inv();
    let m: Vec<_> = pair
        .zero
        .values()
        .iter()
        .zip(pair.one.values())
        .map(|(&a, &b)| (a + (E::one() + beta.inv()) * b) * half)
        .collect();
    let determinant = (m[0] * m[3] - m[1] * m[2]).canonicalized();
    if determinant == E::zero() {
        return None;
    }
    let scale = determinant.inv();
    Some([m[3] * scale, -m[1] * scale, -m[2] * scale, m[0] * scale])
}
fn folded<E: Field>(pair: &MatrixPair<E>, beta: E, values: &[[E; 2]; 2]) -> [E; 2] {
    fold_symbol(pair, beta, &values[0], &values[1])
        .unwrap()
        .try_into()
        .unwrap()
}

fn exercise<F: NTTField, E: AbstractExtensionField<F>>() {
    let root = power(E::from_base(F::generate_ntt_table(6).unwrap().root()), 4);
    assert_eq!(power(root, 32).canonicalized(), E::one());
    assert_eq!(power(root, 16).canonicalized(), -E::one());
    let unit = E::from_base_fn(|i| if i == 1 { F::one() } else { F::zero() });
    let pair = MatrixPair {
        zero: Matrix::new(2, vec![1, 2, 3, 4].into_iter().map(scalar::<E>).collect()).unwrap(),
        one: Matrix::new(2, vec![2, 0, 1, 1].into_iter().map(scalar::<E>).collect()).unwrap(),
    };
    let probe = [E::one(), unit];
    assert!(!same(
        &apply(pair.zero.values(), apply(pair.one.values(), probe)),
        &apply(pair.one.values(), apply(pair.zero.values(), probe))
    ));
    let coefficients: Vec<_> = (0..8)
        .map(|i| {
            [
                scalar::<E>(i + 1) + unit * scalar::<E>(3 * i + 2),
                scalar::<E>(2 * i + 3) - unit * scalar::<E>(i + 2),
            ]
        })
        .collect();
    let next_coefficients: Vec<_> = coefficients
        .chunks_exact(2)
        .map(|c| {
            let even = apply(pair.zero.values(), c[0]);
            let odd = apply(pair.one.values(), [c[0][0] + c[1][0], c[0][1] + c[1][1]]);
            [even[0] + odd[0], even[1] + odd[1]]
        })
        .collect();
    let betas: Vec<_> = (0..8).map(|i| power(root, 2 * i + 1)).collect();
    let points: Vec<_> = betas.iter().map(|&x| x * x).collect();
    let clean: Vec<_> = betas
        .iter()
        .map(|&b| [evaluate(&coefficients, b), evaluate(&coefficients, -b)])
        .collect();
    let truth: Vec<_> = points
        .iter()
        .map(|&y| evaluate(&next_coefficients, y))
        .collect();
    for i in 0..8 {
        assert!(same(&folded(&pair, betas[i], &clean[i]), &truth[i]));
    }

    // A degree-three discrepancy attains exactly three good next-domain points.
    // Both target and true successor still have degree <4.
    let differences: Vec<_> = points
        .iter()
        .map(|&y| {
            let h = points[..3].iter().fold(E::one(), |a, &z| a * (y - z));
            [h, h * unit]
        })
        .collect();
    let target: Vec<_> = truth
        .iter()
        .zip(&differences)
        .map(|(a, d)| [a[0] + d[0], a[1] + d[1]])
        .collect();
    let bad: Vec<_> = (0..8).filter(|&i| !same(&truth[i], &target[i])).collect();
    assert_eq!(bad.len(), 5); // D_next = 8-4+1.
    let mut source = clean.clone();
    let mut successor = target.clone();
    let mut hidden = Vec::new();
    for &i in &bad {
        if let Some(inverse) = plus_inverse(&pair, betas[i]) {
            let change = apply(&inverse, differences[i]);
            for lane in 0..2 {
                source[i][0][lane] += change[lane];
            }
            assert!(same(&folded(&pair, betas[i], &source[i]), &target[i]));
            hidden.push(i);
            if hidden.len() == 2 {
                break;
            }
        }
    }
    assert_eq!(hidden.len(), 2);
    let last = *bad.iter().find(|i| !hidden.contains(i)).unwrap();
    successor[last] = truth[last];
    let source_errors = source
        .iter()
        .zip(&clean)
        .map(|(a, b)| usize::from(!same(&a[0], &b[0])) + usize::from(!same(&a[1], &b[1])))
        .sum::<usize>();
    let next_errors = successor
        .iter()
        .zip(&target)
        .filter(|(a, b)| !same(a, b))
        .count();
    assert_eq!((source_errors, next_errors), (2, 1));
    let rejections = (0..8)
        .filter(|&i| !same(&folded(&pair, betas[i], &source[i]), &successor[i]))
        .count();
    assert_eq!(rejections, 5 - source_errors - next_errors);
    assert_eq!(rejections, 2);
    // The sampled consistency component now accepts 6/8 pairs, exceeding 1/2.
    // This does not assert that a complete forged proximity proof accepts.
    assert!(8 - rejections > 8 / 2);

    // The final successor is the bound public constant, not a mutable oracle.
    let terminal_pair = MatrixPair {
        zero: Matrix::identity(2).unwrap(),
        one: Matrix::identity(2).unwrap(),
    };
    let terminal_root = power(root, 4); // Exact order eight; predecessor domain size four.
    let terminal_betas = [terminal_root, power(terminal_root, 3)];
    let terminal_coefficients = [[E::one(), unit], [unit, scalar::<E>(3)]];
    let mut terminal_words: Vec<_> = terminal_betas
        .iter()
        .map(|&b| {
            [
                evaluate(&terminal_coefficients, b),
                evaluate(&terminal_coefficients, -b),
            ]
        })
        .collect();
    let correct = folded(&terminal_pair, terminal_betas[0], &terminal_words[0]);
    assert!(same(
        &correct,
        &folded(&terminal_pair, terminal_betas[1], &terminal_words[1])
    ));
    let false_claim = [correct[0] + E::one(), correct[1] + unit];
    let inverse = plus_inverse(&terminal_pair, terminal_betas[0]).unwrap();
    let change = apply(&inverse, [E::one(), unit]);
    for lane in 0..2 {
        terminal_words[0][0][lane] += change[lane];
    }
    let rejects = (0..2)
        .filter(|&i| {
            !same(
                &folded(&terminal_pair, terminal_betas[i], &terminal_words[i]),
                &false_claim,
            )
        })
        .count();
    assert_eq!(rejects, 2 - 1); // D_next - t_current, with t_next=0.
}

#[test]
fn babybear_nearby_antipodal_fold_witness() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks_nearby_antipodal_fold_witness() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}
