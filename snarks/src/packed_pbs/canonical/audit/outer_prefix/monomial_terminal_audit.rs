//! Necessary monomial terminal identity; source authentication is separate.
use super::*;
use sumcheck::packed_zero::{self, ZeroSubclaim};

pub(super) fn terminal_valid<F: NTTField>(
    plan: &crate::packed_monomial::Plan,
    width: usize,
    subclaim: &ZeroSubclaim<F>,
    values: &[Vec<F>],
) -> bool {
    if values.len() != 2
        || values.iter().any(|v| v.len() != width)
        || subclaim.expected.len() != width
        || subclaim.equality.len() != width
    {
        return false;
    }
    let Some(public) = super::monomial_public_audit::public_value(plan, width, &subclaim.query)
    else {
        return false;
    };
    (0..width).all(|lane| {
        (values[0][lane] * public[lane] - values[1][lane]) * subclaim.equality[lane]
            == subclaim.expected[lane]
    })
}

fn exercise<F>()
where
    F: NTTField + Serialize,
{
    let plan = crate::packed_monomial::Plan::new(32, vec![1, 35, 63]).unwrap();
    for width in [2, 8] {
        let public = plan.table::<F>(width).unwrap();
        let variables = public.num_vars();
        let input = PackedTable::new(
            variables,
            width,
            (0..public.values().len()).map(|i| F::from(i + 1)).collect(),
        )
        .unwrap();
        let output = PackedTable::new(
            variables,
            width,
            input
                .values()
                .iter()
                .zip(public.values())
                .map(|(&a, &b)| a * b)
                .collect(),
        )
        .unwrap();
        let shape = sumcheck::packed::PackedShape {
            num_vars: variables,
            width,
            num_factors: 3,
            terms: vec![(F::one(), vec![0, 1]), (-F::one(), vec![2])],
        };
        for version in [4, 5] {
            let transcript = || {
                if version == 4 {
                    Transcript::<F>::new_classical_atomic_zerocheck(&[42; 64])
                } else {
                    Transcript::<F>::new_classical_atomic_columns(&[42; 64])
                }
            };
            let mut prover = transcript();
            let (proof, _, terminals) = packed_zero::prove_with_terminal_values(
                &mut prover,
                &shape,
                &[input.clone(), public.clone(), output.clone()],
            )
            .unwrap();
            let mut verifier = transcript();
            let subclaim = packed_zero::verify(&mut verifier, &shape, &proof).unwrap();
            let values = vec![terminals[0].clone(), terminals[2].clone()];
            assert!(terminal_valid(&plan, width, &subclaim, &values));
            let factors = || {
                vec![
                    values[0].clone(),
                    plan.evaluate(width, &subclaim.query).unwrap(),
                    values[1].clone(),
                ]
            };
            assert!(subclaim.check(&shape, &factors()).is_ok());
            // Every independent necessary check is compared with the actual
            // production terminal check, using its genuine sumcheck subclaim.
            for lane in 0..width {
                let mut changed = subclaim.clone();
                changed.expected[lane] += F::one();
                assert!(!terminal_valid(&plan, width, &changed, &values));
                assert!(changed.check(&shape, &factors()).is_err());
                for source in 0..2 {
                    let mut changed_values = values.clone();
                    changed_values[source][lane] += F::one();
                    let actual = subclaim
                        .check(
                            &shape,
                            &[
                                changed_values[0].clone(),
                                plan.evaluate(width, &subclaim.query).unwrap(),
                                changed_values[1].clone(),
                            ],
                        )
                        .is_ok();
                    assert_eq!(
                        terminal_valid(&plan, width, &subclaim, &changed_values),
                        actual
                    );
                }
            }
            assert!(!terminal_valid(&plan, width, &subclaim, &values[..1]));
            let mut changed = subclaim.clone();
            changed.query.pop();
            assert!(!terminal_valid(&plan, width, &changed, &values));
            let mut changed = subclaim.clone();
            changed.equality.pop();
            assert!(!terminal_valid(&plan, width, &changed, &values));
            println!(
                "HB_MONOMIAL_TERMINAL prime={} width={} version={} source_authentication=false",
                F::MODULUS_VALUE,
                width,
                version
            );
        }
    }
}

#[test]
fn monomial_terminal_independent() {
    exercise::<algebra::BabyBear>();
    exercise::<algebra::Goldilocks>();
}
