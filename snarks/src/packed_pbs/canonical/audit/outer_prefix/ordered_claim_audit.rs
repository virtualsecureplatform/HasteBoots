//! Shape-checked ordered-claim envelopes, not parent-task admissibility.
use super::*;
use algebra::matrix_weighted::{Matrix, MatrixPair};

pub(super) struct Claims<F> {
    pub root: Commitment<Digest512>,
    pub queries: Vec<Vec<MatrixPair<F>>>,
    pub values: Vec<Vec<F>>,
}

pub(super) struct FixedTask {
    pub promised: bool,
    pub claims_match: Vec<bool>,
}
impl FixedTask {
    pub fn is_bad(&self) -> bool {
        !self.promised || self.claims_match.iter().any(|&matches| !matches)
    }
}

/// Classify the decoded task using a caller-supplied immutable first-declaration
/// source view. This does not establish that view's timing or hash availability.
pub(super) fn fixed_task<F, EF, P>(
    role: monomial_word_audit::SourceRole,
    profile: &ClassicalProfile,
    parameters: &P,
    claims: &Claims<F>,
    view: &std::sync::Arc<FrozenWordView>,
) -> Option<FixedTask>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    if claims.queries.is_empty()
        || claims.queries.len() != claims.values.len()
        || claims
            .values
            .iter()
            .any(|row| row.len() != parameters.width())
    {
        return None;
    }
    let context = parameters.context().ok()?;
    let sources = vec![
        (context, claims.root.clone()),
        (context, claims.root.clone()),
    ];
    let (promises, values) = monomial_word_audit::values_many_for_role::<F, EF, P>(
        role,
        profile,
        parameters,
        &sources,
        &claims.queries,
        |_| Some(std::sync::Arc::clone(view)),
    )?;
    let claims_match = values[0]
        .iter()
        .zip(&claims.values)
        .map(|(actual, claimed)| {
            encoded(actual) == encoded(&parameters.normalize_values(claimed.clone()))
        })
        .collect();
    Some(FixedTask {
        promised: promises.iter().all(|&promised| promised),
        claims_match,
    })
}

fn atom<T: Serialize + DeserializeOwned>(input: &mut &[u8]) -> Option<T> {
    let (value, used): (T, usize) =
        bincode::serde::decode_from_slice(input, bincode::config::standard()).ok()?;
    if encoded(&value) != input.get(..used)? {
        return None;
    }
    *input = input.get(used..)?;
    Some(value)
}

fn matrix<F: NTTField + Serialize + DeserializeOwned>(
    input: &mut &[u8],
    width: usize,
) -> Option<Matrix<F>> {
    *input = input.strip_prefix(encoded(&width).as_slice())?;
    Matrix::new(width, vector::<F>(input, width.checked_mul(width)?)?).ok()
}

/// Decode the final claim/fork/seed envelope of a framed parent candidate.
/// `claims` and parameter dimensions are caller-trusted stage shapes, never
/// sizes read from the candidate. This makes no truth/availability assertion.
pub(super) fn decode<F, P>(
    profile: &ClassicalProfile,
    parameters: &P,
    input: &[u8],
    claims: usize,
) -> Option<Claims<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    if claims == 0 || parameters.width() == 0 {
        return None;
    }
    let (binding, child_label, child_context) = pcs_child_labels(profile.specification().backend)?;
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
    let (mut first, mut second, mut third) = (None, None, None);
    while !rest.is_empty() {
        let kind = *take(&mut rest, 1)?.first()?;
        if kind > 8 {
            return None;
        }
        let item = (kind, sized(&mut rest)?, sized(&mut rest)?);
        (first, second, third) = (second, third, Some(item));
    }
    let (kind, label, mut body) = first?;
    if kind != 1
        || label != binding
        || second? != (6, child_label, child_context)
        || third?
            != (
                2,
                b"classical child seed".as_slice(),
                64u64.to_le_bytes().as_slice(),
            )
    {
        return None;
    }
    let context: Digest512 = atom(&mut body)?;
    if context != parameters.context().ok()? {
        return None;
    }
    let root: Commitment<Digest512> = atom(&mut body)?;
    body = body.strip_prefix(encoded(&claims).as_slice())?;
    let mut queries = Vec::with_capacity(claims);
    for _ in 0..claims {
        body = body.strip_prefix(encoded(&parameters.num_vars()).as_slice())?;
        let mut query = Vec::with_capacity(parameters.num_vars());
        for _ in 0..parameters.num_vars() {
            query.push(MatrixPair {
                zero: matrix(&mut body, parameters.width())?,
                one: matrix(&mut body, parameters.width())?,
            });
        }
        queries.push(query);
    }
    let values = rectangular::<F>(&mut body, claims, parameters.width())?;
    if !body.is_empty() {
        return None;
    }
    Some(Claims {
        root,
        queries,
        values,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate<F: NTTField>(profile: &ClassicalProfile, body: &[u8]) -> Vec<u8> {
        let (binding, label, context) = pcs_child_labels(profile.specification().backend).unwrap();
        let mut input = initial_header::<F>(profile).unwrap();
        frame(&mut input, 1, binding, body);
        frame(&mut input, 6, label, context);
        frame(&mut input, 2, b"classical child seed", &64u64.to_le_bytes());
        input
    }

    fn exercise<F, P>(bundle: ProfileParameters<P>)
    where
        F: NTTField + Serialize + DeserializeOwned,
        P: CanonicalPcs<F, Sha512>,
    {
        let profile = bundle.profile();
        let parameters = &bundle.roles()[0];
        let width = parameters.width();
        let context = parameters.context().ok().unwrap();
        let root = Commitment {
            root: Digest512([91; 64]),
        };
        let queries = vec![vec![
            MatrixPair {
                zero: Matrix::<F>::identity(width).unwrap(),
                one: Matrix::<F>::identity(width).unwrap()
            };
            parameters.num_vars()
        ]];
        let values = vec![vec![F::zero(); width]];
        let body = encoded(&(context, &root, &queries, &values));
        let input = candidate::<F>(profile, &body);
        let parsed = decode::<F, P>(profile, parameters, &input, 1).unwrap();
        assert_eq!(
            encoded(&(parsed.root, parsed.queries, parsed.values)),
            encoded(&(&root, &queries, &values))
        );
        let mut foreign = context;
        foreign.0[0] ^= 1;
        let mut bad = vec![encoded(&(foreign, &root, &queries, &values))];
        let prefix = encoded(&(context, &root));
        // Declared lengths are rejected at each nested vector boundary.
        bad.push([prefix.clone(), encoded(&usize::MAX)].concat());
        bad.push([prefix.clone(), encoded(&1usize), encoded(&usize::MAX)].concat());
        bad.push(
            [
                prefix.clone(),
                encoded(&1usize),
                encoded(&parameters.num_vars()),
                encoded(&usize::MAX),
            ]
            .concat(),
        );
        bad.push(
            [
                prefix.clone(),
                encoded(&1usize),
                encoded(&parameters.num_vars()),
                encoded(&width),
                encoded(&usize::MAX),
            ]
            .concat(),
        );
        bad.push(
            [
                prefix.clone(),
                encoded(&queries),
                encoded(&1usize),
                encoded(&usize::MAX),
            ]
            .concat(),
        );
        bad.push([body.clone(), vec![0]].concat());
        bad.push(body[..body.len() - 1].to_vec());
        bad.push([prefix, vec![251, 1, 0]].concat()); // Noncanonical spelling of length one.
        for body in bad {
            assert!(
                decode::<F, P>(profile, parameters, &candidate::<F>(profile, &body), 1).is_none()
            );
        }
        assert!(decode::<F, P>(profile, parameters, &input, 2).is_none());
        assert!(decode::<F, P>(profile, parameters, &input, 0).is_none());
        let mut trailing = input.clone();
        trailing.push(0);
        assert!(decode::<F, P>(profile, parameters, &trailing, 1).is_none());
        let mut wrong_request = input.clone();
        let length = wrong_request.len();
        wrong_request[length - 8..].copy_from_slice(&32u64.to_le_bytes());
        assert!(decode::<F, P>(profile, parameters, &wrong_request, 1).is_none());
        // Different well-shaped values are another task, not a syntax error.
        let mut changed = values;
        changed[0][0] += F::one();
        let alternate = candidate::<F>(profile, &encoded(&(context, &root, &queries, &changed)));
        assert_eq!(
            encoded(
                &decode::<F, P>(profile, parameters, &alternate, 1)
                    .unwrap()
                    .values
            ),
            encoded(&changed)
        );
    }

    fn field<F, EF>(widths: &[usize])
    where
        F: NTTField + Serialize + DeserializeOwned,
        EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    {
        for &width in widths {
            for version in [4, 5] {
                for backend in [
                    Backend::Polyfrim,
                    Backend::PolyfrimDictionary,
                    Backend::FragmentedPipfri,
                    Backend::FragmentedPipfriVirtual,
                ] {
                    let spec = Specification {
                        backend,
                        roles: std::array::from_fn(|_| Role {
                            num_vars: 3,
                            width,
                            queries: 8,
                            left_vars: None,
                            block_width: None,
                        }),
                        blowup: 2,
                        fragment_vars: matches!(
                            backend,
                            Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual
                        )
                        .then_some(4),
                    };
                    let profile = if version == 4 {
                        ClassicalProfile::new_atomic_zerocheck::<F, EF>(spec)
                    } else {
                        ClassicalProfile::new_atomic_columns::<F, EF>(spec)
                    }
                    .unwrap();
                    match backend {
                        Backend::Polyfrim => {
                            exercise::<F, _>(profile.polyfrim_parameters::<F, EF>().unwrap())
                        }
                        Backend::PolyfrimDictionary => exercise::<F, _>(
                            profile.polyfrim_dictionary_parameters::<F, EF>().unwrap(),
                        ),
                        Backend::FragmentedPipfri => {
                            exercise::<F, _>(profile.fragmented_parameters::<F, EF>().unwrap())
                        }
                        Backend::FragmentedPipfriVirtual => exercise::<F, _>(
                            profile.fragmented_virtual_parameters::<F, EF>().unwrap(),
                        ),
                        _ => unreachable!(),
                    }
                }
            }
        }
    }

    #[test]
    fn ordered_claim_envelopes_reject_untrusted_nested_lengths() {
        field::<algebra::BabyBear, algebra::BabyBearExtension6>(&[8, 16]);
        field::<algebra::Goldilocks, algebra::GoldilocksExtension3>(&[4, 8]);
    }
}
