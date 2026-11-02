//! Reference bounded-distance decoding for analysis tests, never proof admission.
use algebra::Field;

fn evaluate<F: Field>(coefficients: &[F], point: F) -> F {
    coefficients
        .iter()
        .rev()
        .fold(F::zero(), |v, &c| v * point + c)
}

// Solve an affine system, choosing zero for free variables. Rank deficiency
// when fewer than t errors occur is expected, not a decoding failure.
fn solve<F: Field>(mut rows: Vec<Vec<F>>, variables: usize) -> Option<Vec<F>> {
    let mut pivots = Vec::new();
    let mut next = 0;
    for column in 0..variables {
        let Some(pivot) = (next..rows.len()).find(|&row| rows[row][column] != F::zero()) else {
            continue;
        };
        rows.swap(next, pivot);
        let scale = rows[next][column];
        for c in column..=variables {
            rows[next][c] /= scale;
        }
        let normalized = rows[next].clone();
        for (row, values) in rows.iter_mut().enumerate() {
            if row == next {
                continue;
            }
            let factor = values[column];
            for c in column..=variables {
                values[c] -= factor * normalized[c];
            }
        }
        pivots.push((next, column));
        next += 1;
    }
    if rows
        .iter()
        .any(|row| row[..variables].iter().all(|&v| v == F::zero()) && row[variables] != F::zero())
    {
        return None;
    }
    let mut solution = vec![F::zero(); variables];
    for (row, column) in pivots {
        solution[column] = rows[row][variables];
    }
    Some(solution)
}

fn scalar<F: Field>(
    points: &[F],
    values: &[F],
    degree_bound: usize,
    errors: usize,
) -> Option<Vec<F>> {
    let numerator_len = degree_bound.checked_add(errors)?;
    let unknowns = numerator_len.checked_add(errors)?;
    let mut rows = Vec::with_capacity(points.len());
    for (&x, &value) in points.iter().zip(values) {
        let mut powers = vec![F::one(); numerator_len.max(errors + 1)];
        for i in 1..powers.len() {
            powers[i] = powers[i - 1] * x;
        }
        let mut row = powers[..numerator_len].to_vec();
        row.extend(powers[..errors].iter().map(|&power| -value * power));
        row.push(value * powers[errors]);
        rows.push(row);
    }
    let solution = solve(rows, unknowns)?;
    let mut remainder = solution[..numerator_len].to_vec();
    let mut locator = solution[numerator_len..].to_vec();
    locator.push(F::one());
    let mut quotient = vec![F::zero(); degree_bound];
    for high in (errors..numerator_len).rev() {
        let coefficient = remainder[high];
        quotient[high - errors] = coefficient;
        for j in 0..=errors {
            remainder[high - errors + j] -= coefficient * locator[j];
        }
    }
    if remainder.iter().any(|&v| v != F::zero()) {
        return None;
    }
    Some(quotient)
}

// Try the polynomial interpolating a fixed prefix. Its acceptance still checks
// joint whole-column distance over the complete word. Corrupted prefixes fall
// through to the general bounded-distance decoder below.
fn interpolate_prefix<F: Field>(points: &[F], columns: &[Vec<F>], degree: usize) -> Vec<Vec<F>> {
    let width = columns[0].len();
    let mut differences = columns[..degree].to_vec();
    for order in 1..degree {
        for j in (order..degree).rev() {
            let inverse = F::one() / (points[j] - points[j - order]);
            let (previous, current) = differences.split_at_mut(j);
            for (value, before) in current[0].iter_mut().zip(&previous[j - 1]) {
                *value = (*value - *before) * inverse;
            }
        }
    }
    let mut polynomials = vec![vec![F::zero(); degree]; width];
    let mut basis = vec![F::one()];
    for j in 0..degree {
        for (polynomial, coefficient) in polynomials.iter_mut().zip(&differences[j]) {
            for (value, power) in polynomial.iter_mut().zip(&basis) {
                *value += *coefficient * *power;
            }
        }
        if j + 1 < degree {
            let mut next = vec![F::zero(); basis.len() + 1];
            for (i, coefficient) in basis.iter().enumerate() {
                next[i] -= points[j] * *coefficient;
                next[i + 1] += *coefficient;
            }
            basis = next;
        }
    }
    polynomials
}

fn joint_distance<F: Field>(points: &[F], columns: &[Vec<F>], decoded: &[Vec<F>]) -> usize {
    points
        .iter()
        .zip(columns)
        .filter(|(x, column)| {
            decoded
                .iter()
                .zip(*column)
                .any(|(polynomial, &value)| evaluate(polynomial, **x) != value)
        })
        .count()
}

/// Recover the unique jointly near vector polynomial, counting a differing
/// whole column once. Individual coordinate proximity is insufficient.
pub fn joint<F: Field>(
    points: &[F],
    columns: &[Vec<F>],
    degree_bound: usize,
    errors: usize,
) -> Option<Vec<Vec<F>>> {
    if degree_bound == 0
        || points.len() != columns.len()
        || points.len() < degree_bound.checked_add(errors.checked_mul(2)?)?
    {
        return None;
    }
    let width = columns.first()?.len();
    if width == 0 || columns.iter().any(|column| column.len() != width) {
        return None;
    }
    for i in 0..points.len() {
        if points[..i].contains(&points[i]) {
            return None;
        }
    }
    let interpolated = interpolate_prefix(points, columns, degree_bound);
    if joint_distance(points, columns, &interpolated) <= errors {
        return Some(interpolated);
    }
    let decoded: Vec<_> = (0..width)
        .map(|coordinate| {
            scalar(
                points,
                &columns
                    .iter()
                    .map(|column| column[coordinate])
                    .collect::<Vec<_>>(),
                degree_bound,
                errors,
            )
        })
        .collect::<Option<_>>()?;
    let differences = joint_distance(points, columns, &decoded);
    (differences <= errors).then_some(decoded)
}
