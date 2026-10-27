//! Authenticate extension-field MLEs through canonical base-field packed roots.
//! Matrices represent multiplication in the declared polynomial basis. Scalar
//! source lanes are selected before row weights; their map must stay on the
//! RIGHT of the first remaining pair. No source-view commitment is introduced.
use algebra::{
    AbstractExtensionField, Field,
    matrix_weighted::{BroadcastQuery, Matrix, MatrixPair, PackedTable, ShapeError},
};
/// Canonical query plus a local terminal map for zero-variable sources.
pub type Query<F> = BroadcastQuery<F>;
fn dimensions<F: Field, EF: AbstractExtensionField<F>>(width: usize) -> Result<(), ShapeError> {
    if EF::D == 0 || EF::D > width || width.checked_mul(width).is_none() {
        return Err(ShapeError("extension/packing dimension"));
    }
    Ok(())
}
/// Encode a field element as basis coefficients followed by ignored zero lanes.
pub fn vector<F: Field, EF: AbstractExtensionField<F>>(
    width: usize,
    value: EF,
) -> Result<Vec<F>, ShapeError> {
    dimensions::<F, EF>(width)?;
    let mut out = vec![F::zero(); width];
    let c = value.as_base_slice();
    if c.len() > EF::D {
        return Err(ShapeError("extension coefficient count"));
    }
    out[..c.len()].copy_from_slice(c);
    Ok(out)
}
/// Read the meaningful basis coordinates, requiring the projected padding zero.
pub fn element<F: Field, EF: AbstractExtensionField<F>>(
    width: usize,
    value: &[F],
) -> Result<EF, ShapeError> {
    dimensions::<F, EF>(width)?;
    if value.len() != width || value[EF::D..].iter().any(|&v| v != F::zero()) {
        return Err(ShapeError("extension projection/padding"));
    }
    Ok(EF::from_base_slice(&value[..EF::D]))
}
/// Base matrix for multiplication by an extension element; unused lanes vanish.
pub fn multiplication<F: Field, EF: AbstractExtensionField<F>>(
    width: usize,
    value: EF,
) -> Result<Matrix<F>, ShapeError> {
    dimensions::<F, EF>(width)?;
    let mut out = vec![F::zero(); width * width];
    for column in 0..EF::D {
        let product = value * EF::monomial(column);
        for (row, &c) in product.as_base_slice().iter().enumerate() {
            out[row * width + column] = c;
        }
    }
    Matrix::new(width, out)
}
/// Query a helper whose each Boolean cell stores one extension element's
/// coefficients. Unused helper lanes are ignored rather than assumed committed
/// zero. An empty point uses a checked projection after a constant-vector opening.
pub fn coefficients_query<F: Field, EF: AbstractExtensionField<F>>(
    width: usize,
    point: &[EF],
) -> Result<Query<F>, ShapeError> {
    dimensions::<F, EF>(width)?;
    let query = point
        .iter()
        .map(|&x| {
            Ok(MatrixPair {
                zero: multiplication::<F, EF>(width, EF::one() - x)?,
                one: multiplication::<F, EF>(width, x)?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let post_matrix = if point.is_empty() {
        Some(multiplication::<F, EF>(width, EF::one())?)
    } else {
        None
    };
    Ok(Query { query, post_matrix })
}
/// Query the ordinary extension MLE of a canonical source's flattened scalar
/// entries. Low point bits select lanes; remaining bits select Boolean cells.
pub fn scalar_query<F: Field, EF: AbstractExtensionField<F>>(
    source_vars: usize,
    width: usize,
    point: &[EF],
) -> Result<Query<F>, ShapeError> {
    dimensions::<F, EF>(width)?;
    if !width.is_power_of_two() {
        return Err(ShapeError("scalar source width must be a power of two"));
    }
    let lane_bits = width.ilog2() as usize;
    if source_vars.checked_add(lane_bits) != Some(point.len()) {
        return Err(ShapeError("scalar source point dimension"));
    }
    let mut values = vec![F::zero(); width * width];
    for lane in 0..width {
        let weight = point[..lane_bits]
            .iter()
            .enumerate()
            .fold(EF::one(), |w, (i, &x)| {
                w * if lane >> i & 1 == 1 { x } else { EF::one() - x }
            });
        for (row, &c) in weight.as_base_slice().iter().enumerate() {
            values[row * width + lane] = c;
        }
    }
    let lanes = Matrix::new(width, values)?;
    let mut result = coefficients_query::<F, EF>(width, &point[lane_bits..])?;
    if let Some(first) = result.query.first_mut() {
        first.zero = first.zero.mul(&lanes)?;
        first.one = first.one.mul(&lanes)?;
    } else {
        result.post_matrix = Some(lanes);
    }
    Ok(result)
}
/// Build a base-field helper table from extension Boolean values.
pub fn table<F: Field, EF: AbstractExtensionField<F>>(
    num_vars: usize,
    width: usize,
    values: &[EF],
) -> Result<PackedTable<F>, ShapeError> {
    dimensions::<F, EF>(width)?;
    if 1usize.checked_shl(u32::try_from(num_vars).map_err(|_| ShapeError("helper variables"))?)
        != Some(values.len())
    {
        return Err(ShapeError("helper value count"));
    }
    values
        .len()
        .checked_mul(width)
        .ok_or(ShapeError("helper size overflow"))?;
    let mut out = vec![F::zero(); values.len() * width];
    for (out, &value) in out.chunks_exact_mut(width).zip(values) {
        let c = value.as_base_slice();
        out[..c.len()].copy_from_slice(c);
    }
    PackedTable::new(num_vars, width, out)
}
