//! Native sample-extraction coordinates, independent of the production tables.
use super::*;
use crate::packed_key_switch::{ExpectedKey, canonical::protocol};

pub(super) fn reference<F: NTTField>(
    n: usize,
    lwe: usize,
    accumulator: &[F],
    a: &[F],
    b: F,
) -> Option<(Vec<F>, Vec<F>)> {
    let size = n.checked_mul(2)?;
    if !n.is_power_of_two()
        || lwe.checked_next_power_of_two()? != n
        || lwe == 0
        || accumulator.len() != size
        || a.len() != lwe
    {
        return None;
    }
    let characteristic: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    let bias = F::from(usize::try_from(characteristic / 8).ok()?);
    let mut mask = vec![F::zero(); size];
    let mut target = mask.clone();
    for coordinate in 0..n {
        let output_index = if coordinate == 0 { 0 } else { n - coordinate };
        if output_index < lwe {
            mask[coordinate] = F::one();
            target[coordinate] = if coordinate == 0 {
                a[output_index]
            } else {
                -a[output_index]
            };
        }
    }
    mask[n] = F::one();
    target[n] = b - accumulator[n] - bias;
    Some((mask, target))
}

fn valid<F: NTTField>(word: &[F], mask: &[F], target: &[F]) -> bool {
    word.len() == mask.len()
        && word.len() == target.len()
        && word
            .iter()
            .zip(mask)
            .zip(target)
            .all(|((&w, &m), &t)| w * m == t)
}

pub(super) fn exercise<F, EF, P>(
    profile: &ClassicalProfile,
    parameters: &P,
    key: &ExpectedKey<Digest512>,
    accumulator: &[F],
    a: &[F],
    b: F,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let cfg = key.config();
    let n = cfg.polynomial_size();
    let lwe = cfg.output_dimension();
    let (mask, target) = reference(n, lwe, accumulator, a, b).unwrap();
    let (actual_mask, actual_target, shape) =
        protocol::audit::extraction::<F, Sha512, P>(parameters, key, accumulator, a, b).unwrap();
    assert_eq!(encoded(&mask), encoded(&actual_mask.values().to_vec()));
    assert_eq!(encoded(&target), encoded(&actual_target.values().to_vec()));
    assert_eq!(shape.num_vars, parameters.num_vars());
    assert_eq!(shape.width, parameters.width());
    assert_eq!(shape.num_factors, 3);
    assert_eq!(
        encoded(&shape.terms),
        encoded(&vec![
            (F::one(), vec![0usize, 1]),
            (-F::one(), vec![2usize])
        ])
    );
    let active = mask.iter().filter(|&&v| v != F::zero()).count();
    assert_eq!(active, lwe + 1);
    let mut word = (0..2 * n)
        .map(|i| {
            if mask[i] == F::one() {
                target[i]
            } else {
                F::from(i + 37)
            }
        })
        .collect::<Vec<_>>();
    assert!(valid(&word, &mask, &target));
    let width = parameters.width();
    for (index, &m) in mask.iter().enumerate() {
        if m == F::zero() {
            continue;
        }
        word[index] += F::one();
        assert_ne!(word[index] * m, target[index]);
        let start = index / width * width;
        let actual = shape
            .evaluate(&[
                word[start..start + width].to_vec(),
                mask[start..start + width].to_vec(),
                target[start..start + width].to_vec(),
            ])
            .unwrap();
        assert_ne!(actual[index % width], F::zero());
        word[index] -= F::one();
    }
    assert!(valid(&word, &mask, &target));
    let inactive = mask.iter().position(|&v| v == F::zero()).unwrap();
    word[inactive] += F::one();
    assert!(valid(&word, &mask, &target));
    let mut padded = a.to_vec();
    padded.resize(n, F::zero());
    assert!(reference(n, lwe, accumulator, &padded, b).is_none());
    assert!(
        protocol::audit::extraction::<F, Sha512, P>(parameters, key, accumulator, &padded, b)
            .is_err()
    );
    assert!(reference(n, lwe, &accumulator[..accumulator.len() - 1], a, b).is_none());
    let (_, changed_target) = reference(n, lwe, accumulator, a, b + F::one()).unwrap();
    assert!(!valid(&word, &mask, &changed_target));
    let mut changed_accumulator = accumulator.to_vec();
    changed_accumulator[n] += F::one();
    let (_, changed_target) = reference(n, lwe, &changed_accumulator, a, b).unwrap();
    assert!(!valid(&word, &mask, &changed_target));
    println!(
        "HB_FINAL_EXTRACTION prime={} degree={} n={} lwe={} version={} backend={:?} changed_active_coordinates={} source_opening_authenticated=false",
        F::MODULUS_VALUE,
        EF::D,
        n,
        lwe,
        profile.version(),
        profile.specification().backend,
        active
    );
}
