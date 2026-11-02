//! Shared analysis-test word assignments, never proof admission.
use super::classical_decode;
use algebra::{
    AbstractExtensionField, NTTField, matrix_weighted::PackedTable, transformation::AbstractNTT,
};
use pcs::utils::code::{BlockReedSolomonCode, RowCode};

pub(crate) fn brakedown_assignment<F: NTTField>(
    word: &[Vec<F>],
    vars: usize,
    width: usize,
    left: usize,
    code: &BlockReedSolomonCode<F>,
) -> (bool, PackedTable<F>) {
    let zero = || PackedTable::new(vars, width, vec![F::zero(); width << vars]).unwrap();
    let count = code.codeword_blocks();
    let mut points = vec![F::zero(); count];
    points[1] = F::one();
    F::get_ntt_table(count.ilog2())
        .unwrap()
        .transform_slice(&mut points);
    let radius = (count - code.message_blocks()) / 3;
    let Some(decoded) = classical_decode::joint(&points, word, code.message_blocks(), radius)
    else {
        return (false, zero());
    };
    let rows = (1 << left) * width;
    let block = code.block_width();
    if decoded.len() != rows * block {
        return (false, zero());
    }
    let right_count = 1 << (vars - left);
    let mut values = vec![F::zero(); width << vars];
    for row in 0..rows {
        for coefficient in 0..code.message_blocks() {
            for lane in 0..block {
                let right = coefficient * block + lane;
                let value = decoded[row * block + lane][coefficient];
                if right >= right_count {
                    if value != F::zero() {
                        return (false, zero());
                    }
                } else {
                    values[(row / width + (right << left)) * width + row % width] = value;
                }
            }
        }
    }
    (true, PackedTable::new(vars, width, values).unwrap())
}

pub(crate) fn polyfrim_assignment<B, E>(
    points: &[E],
    columns: &[Vec<E>],
    vars: usize,
    width: usize,
    radius: usize,
) -> (bool, PackedTable<B>)
where
    B: NTTField,
    E: AbstractExtensionField<B>,
{
    let message = 1 << vars.max(1);
    let zero = || PackedTable::new(vars, width, vec![B::zero(); width << vars]).unwrap();
    let Some(decoded) = classical_decode::joint(points, columns, message, radius) else {
        return (false, zero());
    };
    if decoded.len() != width {
        return (false, zero());
    }
    if vars == 0 {
        return (
            true,
            PackedTable::new(
                0,
                width,
                decoded
                    .iter()
                    .map(|lane| lane[0].as_base_slice()[0])
                    .collect(),
            )
            .unwrap(),
        );
    }
    let mut coefficients = vec![E::zero(); message * width];
    for cell in 0..message {
        for lane in 0..width {
            coefficients[cell * width + lane] = decoded[lane][cell];
        }
    }
    // Invert Boolean-to-monomial Mobius conversion, then project coordinate
    // zero. Higher extension coordinates do not alter this fixed assignment.
    for bit in 0..vars {
        let step = 1 << bit;
        for cell in 0..message {
            if cell & step != 0 {
                for lane in 0..width {
                    let lower = coefficients[(cell - step) * width + lane];
                    coefficients[cell * width + lane] += lower;
                }
            }
        }
    }
    (
        true,
        PackedTable::new(
            vars,
            width,
            coefficients
                .iter()
                .map(|value| value.as_base_slice()[0])
                .collect(),
        )
        .unwrap(),
    )
}

pub(crate) fn fragment_assignment<B, E>(
    points: &[E],
    columns: &[Vec<E>],
    fragment_len: usize,
    vars: usize,
    width: usize,
    radius: usize,
) -> (bool, PackedTable<B>)
where
    B: NTTField,
    E: AbstractExtensionField<B>,
{
    let zero = || PackedTable::new(vars, width, vec![B::zero(); width << vars]).unwrap();
    let Some(decoded) = classical_decode::joint(points, columns, fragment_len, radius) else {
        return (false, zero());
    };
    // Scalar fragments store the input table entries as univariate
    // coefficients directly, even for Boolean-evaluation tensor semantics.
    let mut entries: Vec<E> = decoded.into_iter().flatten().collect();
    if width << vars == 1 {
        if entries.len() != 2 {
            return (false, zero());
        }
        entries.truncate(1);
    }
    let values: Vec<_> = entries
        .iter()
        .map(|value| value.as_base_slice()[0])
        .collect();
    if values.len() != width << vars {
        return (false, zero());
    }
    (true, PackedTable::new(vars, width, values).unwrap())
}

/// Canonical whole-column completion from an already frozen preimage view.
/// Missing, malformed or hash-inconsistent paths have the fixed zero column.
/// The caller owns first-declaration timing; this never uses a later view.

fn frozen_leaf<'a>(
    known: &'a std::collections::HashMap<pcs::utils::hash::Digest512, Vec<u8>>,
    root: pcs::utils::hash::Digest512,
    depth: usize,
    index: usize,
) -> Option<&'a [u8]> {
    use pcs::utils::hash::Digest512;
    use sha2::{Digest, Sha512};
    if index >= 1usize.checked_shl(u32::try_from(depth).ok()?)? {
        return None;
    }
    let mut node = root;
    for level in (0..depth).rev() {
        let input = known.get(&node)?;
        if input.len() != 128 || Digest512(Sha512::digest(input).into()) != node {
            return None;
        }
        let at = ((index >> level) & 1) * 64;
        node = Digest512(input.get(at..at + 64)?.try_into().ok()?);
    }
    let input = known.get(&node)?;
    (Digest512(Sha512::digest(input).into()) == node).then_some(input.as_slice())
}
fn canonical_vector<F>(mut rest: &[u8], cells: usize) -> Option<Vec<F>>
where
    F: serde::Serialize + serde::de::DeserializeOwned,
{
    let config = bincode::config::standard();
    let (length, used): (usize, usize) = bincode::serde::decode_from_slice(rest, config).ok()?;
    if length != cells || rest.get(..used)? != bincode::serde::encode_to_vec(length, config).ok()? {
        return None;
    }
    rest = rest.get(used..)?;
    let mut values = Vec::with_capacity(cells);
    for _ in 0..cells {
        let (value, used): (F, usize) = bincode::serde::decode_from_slice(rest, config).ok()?;
        if rest.get(..used)? != bincode::serde::encode_to_vec(&value, config).ok()? {
            return None;
        }
        rest = rest.get(used..)?;
        values.push(value);
    }
    rest.is_empty().then_some(values)
}
pub(crate) fn frozen_brakedown_columns<F>(
    known: &std::collections::HashMap<pcs::utils::hash::Digest512, Vec<u8>>,
    root: pcs::utils::hash::Digest512,
    depth: usize,
    cells: usize,
) -> Option<Vec<Vec<F>>>
where
    F: NTTField + serde::Serialize + serde::de::DeserializeOwned,
{
    let count = 1usize.checked_shl(u32::try_from(depth).ok()?)?;
    Some(
        (0..count)
            .map(|index| {
                frozen_leaf(known, root, depth, index)
                    .and_then(|input| input.strip_prefix(b"HasteBoots/mw-column/v1"))
                    .and_then(|body| canonical_vector(body, cells))
                    .unwrap_or_else(|| vec![F::zero(); cells])
            })
            .collect(),
    )
}
/// Complete source-layer direct PolyFRIM symbols in the exact +/- pair order.
/// Geometry and parameters come from the trusted profile; view timing belongs
/// to the caller. This fixed completion is not proof admission.
pub(crate) fn frozen_polyfrim_symbols<E>(
    known: &std::collections::HashMap<pcs::utils::hash::Digest512, Vec<u8>>,
    root: pcs::utils::hash::Digest512,
    parameters: &pcs::packed_polyfrim::authenticated::Parameters<E>,
    domain: usize,
    width: usize,
) -> Option<Vec<Vec<E>>>
where
    E: algebra::Field + serde::Serialize + serde::de::DeserializeOwned,
{
    if domain < 2 || !domain.is_power_of_two() || width == 0 {
        return None;
    }
    let pairs = domain / 2;
    let cells = width.checked_mul(2)?;
    let mut symbols = Vec::with_capacity(domain);
    for index in 0..pairs {
        let prefix = bincode::serde::encode_to_vec(
            &(b"packed PolyFRIM pair leaf v2", parameters, 0usize, index),
            bincode::config::standard(),
        )
        .ok()?;
        let values = frozen_leaf(known, root, pairs.ilog2() as usize, index)
            .and_then(|input| input.strip_prefix(prefix.as_slice()))
            .and_then(|body| canonical_vector::<E>(body, cells))
            .unwrap_or_else(|| vec![E::zero(); cells]);
        symbols.push(values[..width].to_vec());
        symbols.push(values[width..].to_vec());
    }
    Some(symbols)
}

/// Complete the actual packed-fragment source word, never a virtual identifier.
/// Each canonical leaf binds the scalar parameter context and pair index.
pub(crate) fn frozen_fragment_symbols<E>(
    known: &std::collections::HashMap<pcs::utils::hash::Digest512, Vec<u8>>,
    root: pcs::utils::hash::Digest512,
    context: pcs::utils::hash::Digest512,
    domain: usize,
    fragments: usize,
) -> Option<Vec<Vec<E>>>
where
    E: algebra::Field + serde::Serialize + serde::de::DeserializeOwned,
{
    if domain < 2 || !domain.is_power_of_two() || fragments == 0 {
        return None;
    }
    let pairs = domain / 2;
    let mut symbols = Vec::with_capacity(domain);
    for index in 0..pairs {
        let prefix = bincode::serde::encode_to_vec(
            &(b"PipFRI packed pair leaf v1", context, index),
            bincode::config::standard(),
        )
        .ok()?;
        let values = frozen_leaf(known, root, pairs.ilog2() as usize, index)
            .and_then(|input| input.strip_prefix(prefix.as_slice()))
            .and_then(|body| canonical_vector::<[E; 2]>(body, fragments))
            .unwrap_or_else(|| vec![[E::zero(); 2]; fragments]);
        symbols.push(values.iter().map(|pair| pair[0]).collect());
        symbols.push(values.iter().map(|pair| pair[1]).collect());
    }
    Some(symbols)
}
