//! Trusted-parameter feasibility inventory, not security-qualified selection.
use algebra::{AbstractExtensionField, NTTField};
use pcs::classical_profile::{Backend, ClassicalProfile, Role, Specification};
use serde::{Serialize, de::DeserializeOwned};
use snarks::packed_pbs::Config;

fn inventory<F, E>(
    widths: [usize; 2],
    helper_basis: bool,
    schedule: u32,
    role_queries: [usize; 4],
    emit_descriptors: bool,
) where
    F: NTTField + Serialize,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let version = schedule;
    let query_metadata = if role_queries.iter().all(|&q| q == role_queries[0]) {
        format!("\"queries\":{}", role_queries[0])
    } else {
        format!("\"queries\":null,\"role_queries\":{role_queries:?}")
    };
    let cfg = Config::new::<F>(1024, 728, 8, 5, 1, 1).unwrap();
    for width in widths {
        let variables = cfg.variables(width).unwrap();
        for blowup in [2, 4, 8] {
            for backend in [
                Backend::Brakedown,
                Backend::Polyfrim,
                Backend::PolyfrimDictionary,
                Backend::FragmentedPipfri,
                Backend::FragmentedPipfriVirtual,
            ] {
                let fragmented = matches!(
                    backend,
                    Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual
                );
                if helper_basis && fragmented {
                    continue;
                }
                let helper_width = if helper_basis { E::D } else { width };
                let caps: &[usize] = if fragmented {
                    &[8, 10, 12, 14, 16]
                } else {
                    &[0]
                };
                for &cap in caps {
                    let specification = Specification {
                        backend,
                        roles: std::array::from_fn(|index| Role {
                            num_vars: variables[index],
                            width: if index % 2 == 1 { helper_width } else { width },
                            queries: role_queries[index],
                            left_vars: (backend == Backend::Brakedown)
                                .then_some(variables[index] / 2),
                            block_width: (backend == Backend::Brakedown).then_some(width),
                        }),
                        blowup,
                        fragment_vars: fragmented.then_some(cap),
                    };
                    let profile = match schedule {
                        1 => ClassicalProfile::new::<F, E>(specification),
                        3 => ClassicalProfile::new_atomic_phases::<F, E>(specification),
                        4 => ClassicalProfile::new_atomic_zerocheck::<F, E>(specification),
                        5 => ClassicalProfile::new_atomic_columns::<F, E>(specification),
                        _ => panic!("unsupported grid schedule"),
                    };
                    let result = profile.and_then(|profile| {
                        // Exercise all four actual parameter constructors, not just descriptor validation.
                        match backend {
                            Backend::Brakedown => {
                                profile.brakedown_parameters::<F, E>().map(|_| ())
                            }
                            Backend::Polyfrim => profile.polyfrim_parameters::<F, E>().map(|_| ()),
                            Backend::PolyfrimDictionary => {
                                profile.polyfrim_dictionary_parameters::<F, E>().map(|_| ())
                            }
                            Backend::FragmentedPipfri => {
                                profile.fragmented_parameters::<F, E>().map(|_| ())
                            }
                            Backend::FragmentedPipfriVirtual => {
                                profile.fragmented_virtual_parameters::<F, E>().map(|_| ())
                            }
                        }?;
                        let descriptor = if emit_descriptors {
                            let bytes = bincode::serde::encode_to_vec(
                                &profile,
                                bincode::config::standard(),
                            )
                            .map_err(|_| "profile descriptor encoding")?;
                            Some(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
                        } else {
                            None
                        };
                        Ok((
                            profile
                                .id()
                                .0
                                .iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<String>(),
                            descriptor,
                        ))
                    });
                    let (admitted, id, error, descriptor) = match result {
                        Ok((id, descriptor)) => {
                            (true, format!("{id:?}"), "null".to_owned(), descriptor)
                        }
                        Err(error) => (false, "null".to_owned(), format!("{error:?}"), None),
                    };
                    let descriptor_metadata = if emit_descriptors {
                        format!(
                            ",\"descriptor_bincode_hex\":{}",
                            descriptor.map_or("null".to_owned(), |d| format!("{d:?}"))
                        )
                    } else {
                        String::new()
                    };
                    let fragment = if fragmented {
                        cap.to_string()
                    } else {
                        "null".to_owned()
                    };
                    println!(
                        "HB_CLASSICAL_PROFILE_GRID {{\"prime\":\"{}\",\"extension_degree\":{},\"descriptor_version\":{version},\"backend\":\"{backend:?}\",\"width\":{width},\"helper_width\":{helper_width},\"role_variables\":{variables:?},{query_metadata},\"blowup\":{blowup},\"fragment_vars\":{fragment},\"profile_id_sha512\":{id}{descriptor_metadata},\"parameters_constructed\":{admitted},\"error\":{error},\"security_qualified\":false,\"performance_gate\":false}}",
                        F::MODULUS_VALUE,
                        E::D
                    );
                }
            }
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    let mut selected_queries = None;
    let mut index = 0;
    while index < args.len() {
        if matches!(args[index].as_str(), "--queries" | "--role-queries") {
            assert!(selected_queries.is_none(), "choose one query-count option");
            let flag = args.remove(index);
            assert!(index < args.len(), "missing query counts");
            let value = args.remove(index);
            let counts = if flag == "--queries" {
                [value.parse::<usize>().expect("positive query count"); 4]
            } else {
                value
                    .split(',')
                    .map(|q| q.parse::<usize>().expect("positive role query count"))
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("four role query counts required")
            };
            assert!(
                counts.iter().all(|&q| q > 0),
                "query counts must be positive"
            );
            selected_queries = Some(counts);
        } else {
            index += 1;
        }
    }
    let role_queries = selected_queries.unwrap_or([1; 4]);
    let helper_basis = args.iter().any(|a| a == "--helper-basis");
    let atomic_phases = args.iter().any(|a| a == "--atomic-phases");
    let atomic_zero = args.iter().any(|a| a == "--atomic-zerocheck");
    let atomic_columns = args.iter().any(|a| a == "--atomic-columns");
    let emit_descriptors = args.iter().any(|a| a == "--emit-descriptors");
    assert!(
        args.iter().all(|a| matches!(
            a.as_str(),
            "--helper-basis"
                | "--atomic-phases"
                | "--atomic-zerocheck"
                | "--atomic-columns"
                | "--emit-descriptors"
        )) && usize::from(atomic_phases) + usize::from(atomic_zero) + usize::from(atomic_columns)
            <= 1
            && args.len()
                == usize::from(helper_basis)
                    + usize::from(atomic_phases)
                    + usize::from(atomic_zero)
                    + usize::from(atomic_columns)
                    + usize::from(emit_descriptors),
        "usage: classical_profile_grid [--helper-basis] [--atomic-phases | --atomic-zerocheck | --atomic-columns] [--queries Q | --role-queries A,B,C,D] [--emit-descriptors]"
    );
    let schedule = if atomic_columns {
        5
    } else if atomic_zero {
        4
    } else if atomic_phases {
        3
    } else {
        1
    };
    inventory::<algebra::BabyBear, algebra::BabyBearExetension>(
        [8, 16],
        helper_basis,
        schedule,
        role_queries,
        emit_descriptors,
    );
    inventory::<algebra::BabyBear, algebra::BabyBearExtension5>(
        [8, 16],
        helper_basis,
        schedule,
        role_queries,
        emit_descriptors,
    );
    inventory::<algebra::BabyBear, algebra::BabyBearExtension6>(
        [8, 16],
        helper_basis,
        schedule,
        role_queries,
        emit_descriptors,
    );
    inventory::<algebra::BabyBear, algebra::BabyBearExtension8>(
        [8, 16],
        helper_basis,
        schedule,
        role_queries,
        emit_descriptors,
    );
    inventory::<algebra::Goldilocks, algebra::GoldilocksExtension>(
        [4, 8],
        helper_basis,
        schedule,
        role_queries,
        emit_descriptors,
    );
    inventory::<algebra::Goldilocks, algebra::GoldilocksExtension3>(
        [4, 8],
        helper_basis,
        schedule,
        role_queries,
        emit_descriptors,
    );
    inventory::<algebra::Goldilocks, algebra::GoldilocksExtension4>(
        [4, 8],
        helper_basis,
        schedule,
        role_queries,
        emit_descriptors,
    );
    inventory::<algebra::Goldilocks, algebra::GoldilocksExtension5>(
        [4, 8],
        helper_basis,
        schedule,
        role_queries,
        emit_descriptors,
    );
}
