//! Two monomial evaluation words from fixed first-declaration views.
use super::*;
use algebra::matrix_weighted::MatrixPair;
use std::{collections::HashMap, sync::Arc};

#[derive(Clone, Copy)]
#[cfg_attr(not(feature = "transcript-audit"), allow(dead_code))]
pub(super) enum SourceRole {
    Main,
    MainHelper,
    Final,
    FinalHelper,
}
impl SourceRole {
    fn index(self) -> usize {
        match self {
            Self::Main => 0,
            Self::MainHelper => 1,
            Self::Final => 2,
            Self::FinalHelper => 3,
        }
    }
}

pub(super) fn values_many<F, EF, P>(
    profile: &ClassicalProfile,
    parameters: &P,
    sources: &[(Digest512, Commitment<Digest512>)],
    queries: &[Vec<MatrixPair<F>>],
    view: impl FnMut(&(Digest512, Commitment<Digest512>)) -> Option<Arc<FrozenWordView>>,
) -> Option<(Vec<bool>, Vec<Vec<Vec<F>>>)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    values_many_for_role::<F, EF, P>(
        SourceRole::Main,
        profile,
        parameters,
        sources,
        queries,
        view,
    )
}

pub(super) fn values_many_for_role<F, EF, P>(
    role_kind: SourceRole,
    profile: &ClassicalProfile,
    parameters: &P,
    sources: &[(Digest512, Commitment<Digest512>)],
    queries: &[Vec<MatrixPair<F>>],
    mut view: impl FnMut(&(Digest512, Commitment<Digest512>)) -> Option<Arc<FrozenWordView>>,
) -> Option<(Vec<bool>, Vec<Vec<Vec<F>>>)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let role_index = role_kind.index();
    profile.validate_field::<F, EF>().ok()?;
    let role = profile.specification().roles.get(role_index)?;
    let expected_context = match profile.specification().backend {
        Backend::Brakedown => <_ as CanonicalPcs<F, Sha512>>::context(
            &profile.brakedown_parameters::<F, EF>().ok()?.roles()[role_index],
        )
        .ok()?,
        Backend::Polyfrim => <_ as CanonicalPcs<F, Sha512>>::context(
            &profile.polyfrim_parameters::<F, EF>().ok()?.roles()[role_index],
        )
        .ok()?,
        Backend::PolyfrimDictionary => <_ as CanonicalPcs<F, Sha512>>::context(
            &profile
                .polyfrim_dictionary_parameters::<F, EF>()
                .ok()?
                .roles()[role_index],
        )
        .ok()?,
        Backend::FragmentedPipfri => <_ as CanonicalPcs<F, Sha512>>::context(
            &profile.fragmented_parameters::<F, EF>().ok()?.roles()[role_index],
        )
        .ok()?,
        Backend::FragmentedPipfriVirtual => <_ as CanonicalPcs<F, Sha512>>::context(
            &profile
                .fragmented_virtual_parameters::<F, EF>()
                .ok()?
                .roles()[role_index],
        )
        .ok()?,
    };
    if sources.len() != 2
        || parameters.context().ok()? != expected_context
        || parameters.num_vars() != role.num_vars
        || parameters.width() != role.width
        || sources.iter().any(|s| s.0 != expected_context)
        || queries.iter().any(|query| {
            query.len() != role.num_vars || query.iter().any(|q| q.validate(role.width).is_err())
        })
    {
        return None;
    }
    let mut cache = HashMap::<Vec<u8>, (bool, Vec<Vec<F>>)>::new();
    let mut promises = Vec::new();
    let mut result = Vec::new();
    for source in sources {
        let identity = encoded(source);
        if let Some((promise, value)) = cache.get(&identity) {
            promises.push(*promise);
            result.push(value.clone());
            continue;
        }
        let frozen = view(source)?;
        let (promise, table) = match profile.specification().backend {
            Backend::Brakedown => {
                use pcs::utils::code::{BlockReedSolomonCode, RowCode};
                let left = role.left_vars?;
                let right =
                    1usize.checked_shl(u32::try_from(role.num_vars.checked_sub(left)?).ok()?)?;
                let code = BlockReedSolomonCode::<F>::new(
                    right,
                    role.block_width?,
                    profile.specification().blowup,
                )
                .ok()?;
                let cells = 1usize
                    .checked_shl(u32::try_from(left).ok()?)?
                    .checked_mul(role.width)?
                    .checked_mul(code.block_width())?;
                let columns = classical_assignment::frozen_brakedown_columns::<F>(
                    &frozen,
                    source.1.root,
                    code.codeword_blocks().ilog2() as usize,
                    cells,
                )?;
                classical_assignment::brakedown_assignment(
                    &columns,
                    role.num_vars,
                    role.width,
                    left,
                    &code,
                )
            }
            Backend::Polyfrim | Backend::PolyfrimDictionary => {
                let (core, domain) = direct_core_for_role::<F, EF>(profile, role_index)?;
                let points = direct_source_points::<F, EF>(domain)?;
                let message = 1usize.checked_shl(u32::try_from(role.num_vars).ok()?)?;
                let symbols = classical_assignment::frozen_polyfrim_symbols(
                    &frozen,
                    source.1.root,
                    &core,
                    domain,
                    role.width,
                )?;
                classical_assignment::polyfrim_assignment::<F, EF>(
                    &points,
                    &symbols,
                    role.num_vars,
                    role.width,
                    domain.checked_sub(message)? / 4,
                )
            }
            Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual => {
                let (_, retained, fragments, context, _) =
                    scalar_geometry_for_role::<F, EF>(profile, role_index)?;
                let length = 1usize.checked_shl(u32::try_from(retained).ok()?)?;
                let domain = length.checked_mul(profile.specification().blowup)?;
                let points = direct_source_points::<F, EF>(domain)?;
                let symbols = classical_assignment::frozen_fragment_symbols::<EF>(
                    &frozen,
                    source.1.root,
                    context,
                    domain,
                    fragments,
                )?;
                classical_assignment::fragment_assignment::<F, EF>(
                    &points,
                    &symbols,
                    length,
                    role.num_vars,
                    role.width,
                    domain.checked_sub(length)? / 4,
                )
            }
        };
        table.validate().ok()?;
        if table.num_vars() != role.num_vars || table.width() != role.width {
            return None;
        }
        let value = queries
            .iter()
            .map(|query| {
                let value = parameters.normalize_values(table.evaluate(query).ok()?);
                parameters.validate_values(&value).ok()?;
                Some(value)
            })
            .collect::<Option<Vec<_>>>()?;
        cache.insert(identity, (promise, value.clone()));
        promises.push(promise);
        result.push(value);
    }
    Some((promises, result))
}

pub(super) fn values<F, EF, P>(
    profile: &ClassicalProfile,
    parameters: &P,
    sources: &[(Digest512, Commitment<Digest512>)],
    query: &[MatrixPair<F>],
    view: impl FnMut(&(Digest512, Commitment<Digest512>)) -> Option<Arc<FrozenWordView>>,
) -> Option<(Vec<bool>, Vec<Vec<F>>)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (promises, values) =
        values_many::<F, EF, P>(profile, parameters, sources, &[query.to_vec()], view)?;
    Some((
        promises,
        values
            .into_iter()
            .map(|mut group| group.remove(0))
            .collect(),
    ))
}

pub(super) fn exercise<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    task: &AccumulatorTask<F>,
    tables: &[PackedTable<F>],
    history: &classical_history::History,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let query = accumulator_query_maps(task, pp.monomial.width()).unwrap()[0][0].clone();
    for slots in [[0, 3], [0, 0]] {
        let sources = slots.map(|i| task.sources[i].clone());
        let mut seen = std::collections::HashSet::new();
        let (promises, assigned) =
            values::<F, EF, P>(profile, pp.monomial, &sources, &query, |s| {
                assert!(seen.insert(encoded(s)), "aliased word requested twice");
                history.view(s.1.root)
            })
            .unwrap();
        assert_eq!(seen.len(), if slots[0] == slots[1] { 1 } else { 2 });
        assert!(promises.iter().all(|&p| p));
        for (value, slot) in assigned.iter().zip(slots) {
            assert_eq!(
                encoded(value),
                encoded(
                    &pp.monomial
                        .normalize_values(tables[slot].evaluate(&query).unwrap())
                )
            );
        }
        let queries = vec![query.clone(), query.iter().rev().cloned().collect()];
        let mut many_seen = std::collections::HashSet::new();
        let (many_promises, many) =
            values_many::<F, EF, P>(profile, pp.monomial, &sources, &queries, |source| {
                assert!(many_seen.insert(encoded(source)));
                history.view(source.1.root)
            })
            .unwrap();
        assert_eq!(many_promises, promises);
        assert_eq!(many_seen.len(), seen.len());
        for (group, slot) in many.iter().zip(slots) {
            for (value, query) in group.iter().zip(&queries) {
                assert_eq!(
                    encoded(value),
                    encoded(
                        &pp.monomial
                            .normalize_values(tables[slot].evaluate(query).unwrap())
                    )
                );
            }
        }
        let mut malformed = queries.clone();
        malformed[1].pop();
        let mut calls = 0;
        assert!(
            values_many::<F, EF, P>(profile, pp.monomial, &sources, &malformed, |_| {
                calls += 1;
                None
            })
            .is_none()
        );
        assert_eq!(calls, 0);
        // Freeze these roots before any producing graph is visible. Exposing
        // every honest preimage later must retain the first assignment, even
        // after a repeated declaration of the same roots.
        let mut late = classical_history::History::default();
        let declaration: Vec<_> = sources.iter().flat_map(|s| s.1.root.0).collect();
        late.declare_input(&declaration);
        let first = sources
            .iter()
            .map(|s| late.view(s.1.root).unwrap())
            .collect::<Vec<_>>();
        let before = values::<F, EF, P>(profile, pp.monomial, &sources, &query, |s| {
            late.view(s.1.root)
        })
        .unwrap();
        let mut exposed = std::collections::HashSet::new();
        for source in &sources {
            for (&digest, input) in history.view(source.1.root).unwrap().iter() {
                if exposed.insert(digest) {
                    late.expose(digest, input.clone());
                }
            }
        }
        late.declare_input(&declaration);
        let after = values::<F, EF, P>(profile, pp.monomial, &sources, &query, |s| {
            late.view(s.1.root)
        })
        .unwrap();
        assert_eq!(encoded(&before), encoded(&after));
        if slots[0] != slots[1] {
            assert_ne!(encoded(&assigned), encoded(&after.1));
        }
        for (source, frozen) in sources.iter().zip(first) {
            assert!(Arc::ptr_eq(&frozen, &late.view(source.1.root).unwrap()));
        }
        assert!(values::<F, EF, P>(profile, pp.monomial, &sources, &query, |_| None).is_none());
        for mutation in 0..3 {
            let mut changed_sources = sources.clone();
            let mut changed_query = query.clone();
            match mutation {
                0 => changed_sources[1].0.0[0] ^= 1,
                1 => {
                    changed_query.pop();
                }
                _ => {
                    changed_sources = [sources[0].clone(), sources[1].clone()];
                }
            }
            let supplied = if mutation == 2 {
                &changed_sources[..1]
            } else {
                &changed_sources[..]
            };
            let mut calls = 0;
            assert!(
                values::<F, EF, P>(profile, pp.monomial, supplied, &changed_query, |_| {
                    calls += 1;
                    None
                })
                .is_none()
            );
            assert_eq!(calls, 0);
        }
    }
    println!(
        "HB_MONOMIAL_FROZEN_WORD prime={} degree={} version={} backend={:?} source_opening_acceptance=false",
        F::MODULUS_VALUE,
        EF::D,
        profile.version(),
        profile.specification().backend
    );
}
