// Select the Hadamard certificate while leaving key-switch product proofs on
// their original backend. These helpers exist only in adversarial test modules.
macro_rules! audit_decomposition_type {
    () => { decomp::LaneProof<F,[u8;32]> };
    ($extension:ty) => { decomp::ExtensionProof<F,$extension,[u8;32]> };
}
macro_rules! audit_hadamard_helpers {
    (Independent $(,$extension:ty)?) => {
        type HadamardProof=relation::RelationProof<F,[u8;32]>;
        fn hadamard_with_declared_roots(prover:&mut Transcript<F>,reference:&mut Transcript<F>,
            pp:&Parameters<C>,shape:&PackedShape<F>,factors:&[PackedTable<F>],
            actual:&[Commitment<[u8;32]>],states:&[&State<F,Sha256>],declared:&[Commitment<[u8;32]>]) -> HadamardProof {
            relation_with_declared_roots(prover,reference,pp,shape,factors,actual,states,declared)
        }
    };
    (Aggregated,$extension:ty) => {
        type HadamardProof=relation::aggregate::Proof<F,$extension,[u8;32]>;
        fn hadamard_with_declared_roots(prover:&mut Transcript<F>,reference:&mut Transcript<F>,
            pp:&Parameters<C>,shape:&PackedShape<F>,factors:&[PackedTable<F>],
            actual:&[Commitment<[u8;32]>],states:&[&State<F,Sha256>],declared:&[Commitment<[u8;32]>]) -> HadamardProof {
            let degree=<$extension as algebra::AbstractExtensionField<F>>::D;
            let context=pp.context_digest::<F,Sha256>().unwrap();
            prover.append_message(b"HasteBoots packed aggregated relation v1",&(shape,context,degree,declared));
            reference.append_message(b"HasteBoots packed aggregated relation v1",&(shape,context,degree,declared));
            let (zero,claim,values)=packed_zero::prove_with_terminal_values(prover,shape,factors).unwrap();
            claim.check(shape,&values).unwrap();
            let verified=packed_zero::verify(reference,shape,&zero).unwrap();
            verified.check(shape,&values).unwrap();
            prover.append_message(b"packed aggregated relation terminal values",&values);
            reference.append_message(b"packed aggregated relation terminal values",&values);
            let opening=pcs::matrix_weighted::aggregate::prove::<F,$extension,Sha256,_>(
                pp,prover,actual,states,&claim.query,&values).unwrap();
            pcs::matrix_weighted::aggregate::verify::<F,$extension,Sha256,_>(
                pp,reference,actual,&verified.query,&values,&opening).unwrap();
            relation::aggregate::Proof {zero,values,opening}
        }
    };
}
// This fixture deliberately reconstructs the public protocol from component
// APIs. It is a malicious prover, not a call to pbs::prove with altered input.
macro_rules! complete_foreign_trace_case {
    ($module:ident, $field:ty, $prove:ident, $verify:ident, $pbs_prove:ident, $pbs_verify:ident, $version:expr, $domain:literal, $width:expr, $repetitions:expr $(, $extension:ty)?) => {
        complete_foreign_trace_case!(@backend Independent,$module,$field,$prove,$verify,$pbs_prove,$pbs_verify,$version,$domain,$width,$repetitions $(,$extension)?);
    };
    (@aggregated $module:ident, $field:ty, $prove:ident, $verify:ident, $pbs_prove:ident, $pbs_verify:ident, $version:expr, $domain:literal, $width:expr, $repetitions:expr, $extension:ty) => {
        complete_foreign_trace_case!(@backend Aggregated,$module,$field,$prove,$verify,$pbs_prove,$pbs_verify,$version,$domain,$width,$repetitions,$extension);
    };
    (@backend $kind:ident,$module:ident, $field:ty, $prove:ident, $verify:ident, $pbs_prove:ident, $pbs_verify:ident, $version:expr, $domain:literal, $width:expr, $repetitions:expr $(, $extension:ty)?) => {
        mod $module {
            use super::{params, secret};
            use algebra::{
                Field, NTTField,
                matrix_weighted::{Matrix, MatrixPair, PackedTable},
                transformation::AbstractNTT,
            };
            use helper::{FiatShamirTranscript, Transcript};
            use pcs::{
                matrix_weighted::{Commitment, Parameters, State},
                utils::code::BlockReedSolomonCode,
            };
            use sha2::Sha256;
            use snarks::{
                packed_accumulator as acc, packed_bootstrap_key as bk, packed_decomposition as decomp,
                packed_key_switch as ks, packed_monomial as mono, packed_ntt as ntt,
                packed_oracle::ProverOracle, packed_pbs as pbs, packed_relation as relation,
            };
            use sumcheck::{packed::PackedShape, packed_zero};
            use vfhe::{Encryptor, bfhe::Evaluator};
            type F = $field;
            type C = BlockReedSolomonCode<F>;
            audit_hadamard_helpers!($kind $(,$extension)?);
            type FullProof=pbs::Proof<F,[u8;32],audit_decomposition_type!($($extension)?),HadamardProof>;
            struct Sources {
                tables: Vec<PackedTable<F>>,
                roots: Vec<Commitment<[u8; 32]>>,
                states: Vec<State<F, Sha256>>,
            }
            impl Sources {
                fn new(pp: &Parameters<C>, tables: Vec<PackedTable<F>>) -> Self {
                    let (roots, states) = tables
                        .iter()
                        .map(|t| pp.commit::<F, Sha256>(t).unwrap())
                        .unzip();
                    Self {
                        tables,
                        roots,
                        states,
                    }
                }
                fn oracles<'a>(&'a self, pp: &'a Parameters<C>) -> Vec<ProverOracle<'a, F, Sha256, C>> {
                    self.tables
                        .iter()
                        .zip(&self.roots)
                        .zip(&self.states)
                        .map(|((table, commitment), state)| ProverOracle {
                            parameters: pp,
                            table,
                            commitment,
                            state,
                        })
                        .collect()
                }
            }
            fn transforms(tables: &[PackedTable<F>], n: usize) -> Vec<PackedTable<F>> {
                let native = F::get_ntt_table(n.ilog2()).unwrap();
                tables
                    .iter()
                    .map(|t| {
                        let mut values = t.values().to_vec();
                        for p in values.chunks_exact_mut(n) {
                            native.transform_slice(p);
                        }
                        PackedTable::new(t.num_vars(), t.width(), values).unwrap()
                    })
                    .collect()
            }
            fn assert_roots(a: &[Commitment<[u8; 32]>], b: &[Commitment<[u8; 32]>]) {
                assert_eq!(a.len(), b.len());
                for (a, b) in a.iter().zip(b) {
                    assert_eq!(a.root, b.root);
                }
            }
            fn product_shape(pp: &Parameters<C>, count: usize) -> PackedShape<F> {
                let mut terms = (0..count)
                    .map(|i| (F::from(1usize), vec![2 * i, 2 * i + 1]))
                    .collect::<Vec<_>>();
                terms.push((-F::from(1usize), vec![2 * count]));
                PackedShape {
                    num_vars: pp.num_vars(),
                    width: pp.width(),
                    num_factors: 2 * count + 1,
                    terms,
                }
            }
            // Declare trusted roots in the child domain, then authenticate the
            // actual witness roots. A different-key attack is rejected precisely
            // when production substitutes its trusted root for an actual opening.
            fn relation_with_declared_roots(
                prover: &mut Transcript<F>,
                reference: &mut Transcript<F>,
                pp: &Parameters<C>,
                shape: &PackedShape<F>,
                factors: &[PackedTable<F>],
                actual: &[Commitment<[u8; 32]>],
                states: &[&State<F, Sha256>],
                declared: &[Commitment<[u8; 32]>],
            ) -> relation::RelationProof<F, [u8; 32]> {
                prover.append_message(b"HasteBoots packed relation v1", &(shape, declared));
                reference.append_message(b"HasteBoots packed relation v1", &(shape, declared));
                let (zero, claim, values) =
                    packed_zero::prove_with_terminal_values(prover, shape, factors).unwrap();
                claim.check(shape, &values).unwrap();
                let verified = packed_zero::verify(reference, shape, &zero).unwrap();
                verified.check(shape, &values).unwrap();
                prover.append_message(b"packed relation terminal values", &values);
                reference.append_message(b"packed relation terminal values", &values);
                let openings = actual
                    .iter()
                    .zip(states)
                    .zip(&values)
                    .map(|((root, state), value)| {
                        let proof = pp
                            .open::<F, Sha256>(prover, root, state, &claim.query, value)
                            .unwrap();
                        pp.verify::<F, Sha256>(reference, root, &verified.query, value, &proof)
                            .unwrap();
                        proof
                    })
                    .collect();
                relation::RelationProof {
                    zero,
                    values,
                    openings,
                }
            }

            // Independent reconstruction of the accumulator's ordered query
            // maps. Control cases below cross-check this replay against the
            // production verifier; no production verifier bypass is exported.
            fn accumulator_certificate(
                prover: &mut Transcript<F>,
                reference: &mut Transcript<F>,
                shape: &acc::Shape,
                initial: &[F],
                final_acc: &[F],
                sources: &[&ProverOracle<'_, F, Sha256, C>],
            ) -> acc::Proof<F, [u8; 32]> {
                let pp = sources[0].parameters;
                let k = pp.width();
                let n = shape.polynomial_size();
                let c = (n / k).ilog2() as usize;
                let r = shape.padded_rounds().ilog2() as usize;
                let contexts = sources
                    .iter()
                    .map(|o| (pp.context_digest::<F, Sha256>().unwrap(), o.commitment))
                    .collect::<Vec<_>>();
                let bind = |t: &mut Transcript<F>| {
                    t.append_message(
                        b"packed accumulator canonical linkage v1",
                        &(shape, initial, final_acc, &contexts),
                    );
                    (0..pp.num_vars())
                        .map(|_| {
                            sumcheck::packed::challenge_pair(
                                &t.get_vec_challenge(b"accumulator independent lane challenges", k),
                            )
                            .unwrap()
                        })
                        .collect::<Vec<_>>()
                };
                let base = bind(prover);
                assert_eq!(base, bind(reference));
                let identity = || Matrix::identity(k).unwrap();
                let zero = || Matrix::new(k, vec![F::from(0usize); k * k]).unwrap();
                let select = |bit: usize, m: Matrix<F>| {
                    if bit == 0 {
                        MatrixPair {
                            zero: m,
                            one: zero(),
                        }
                    } else {
                        MatrixPair {
                            zero: zero(),
                            one: m,
                        }
                    }
                };
                let row_query = |row: usize| {
                    let mut q = base.clone();
                    for bit in 0..r {
                        q[c + bit] = select((row >> bit) & 1, identity());
                    }
                    q
                };
                let mut queries = vec![vec![base.clone()]; 7];
                queries[acc::INPUT_ACC].push(row_query(0));
                if r == 0 {
                    queries[acc::INPUT_ACC].push(base.clone());
                } else {
                    let mut low = identity();
                    for bit in 0..r {
                        let mut q = base.clone();
                        for j in 0..bit {
                            q[c + j] = select(0, identity());
                        }
                        q[c + bit] = select(1, base[c + bit].zero.mul(&low).unwrap());
                        queries[acc::INPUT_ACC].push(q);
                        low = base[c + bit].one.mul(&low).unwrap();
                    }
                    let mut q = base.clone();
                    q[c] = select(0, low);
                    for bit in 1..r {
                        q[c + bit] = select(0, identity());
                    }
                    queries[acc::INPUT_ACC].push(q);
                }
                queries[acc::OUTPUT_ACC].push(row_query(shape.rounds() - 1));
                let half = base.last().unwrap();
                let summed = Matrix::new(
                    k,
                    half.zero
                        .values()
                        .iter()
                        .zip(half.one.values())
                        .map(|(&a, &b)| a + b)
                        .collect(),
                )
                .unwrap();
                for h in 0..2 {
                    let mut q = base.clone();
                    *q.last_mut().unwrap() = select(h, summed.clone());
                    queries[acc::EXTERNAL_INPUT].push(q);
                }
                let values = sources
                    .iter()
                    .zip(&queries)
                    .map(|(o, q)| {
                        q.iter()
                            .map(|q| o.table.evaluate(q).unwrap())
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                let openings = sources
                    .iter()
                    .zip(&queries)
                    .zip(&values)
                    .map(|((o, q), v)| {
                        let proof = pp
                            .open_many::<F, Sha256>(prover, o.commitment, o.state, q, v)
                            .unwrap();
                        pp.verify_many::<F, Sha256>(reference, o.commitment, q, v, &proof)
                            .unwrap();
                        proof
                    })
                    .collect();
                acc::Proof { values, openings }
            }
            fn splice(
                pp: &Parameters<C>,
                left: &Sources,
                right: &Sources,
                n: usize,
                split: usize,
            ) -> Sources {
                let rows = left.tables[0].values().len() / (2 * n);
                Sources::new(
                    pp,
                    left.tables
                        .iter()
                        .zip(&right.tables)
                        .map(|(a, b)| {
                            let values = a
                                .values()
                                .iter()
                                .zip(b.values())
                                .enumerate()
                                .map(|(i, (&a, &b))| if (i / n) % rows < split { a } else { b })
                                .collect();
                            PackedTable::new(pp.num_vars(), pp.width(), values).unwrap()
                        })
                        .collect(),
                )
            }

            // Bind the requested output, but build the final extraction with
            // the actual native target. All other key-switch children are genuine.
            fn key_switch_with_actual_target(
                prover: &mut Transcript<F>,
                reference: &mut Transcript<F>,
                pp: &pbs::Parameters<'_, C>,
                expected: &ks::ExpectedKey<[u8; 32]>,
                co: &Sources,
                ev: &Sources,
                keys: &Sources,
                input: &Sources,
                final_acc: &[F],
                requested: &pbs::Statement<'_, F>,
                actual: &pbs::Statement<'_, F>,
            ) -> ks::Proof<F, [u8; 32] $(, decomp::ExtensionProof<F, $extension, [u8; 32]>)?> {
                let n = final_acc.len() / 2;
                let width = pp.final_source.width();
                let d = expected.roots().len();
                let bind = |t: &mut Transcript<F>| {
                    t.append_message(
                        b"packed original RLWE key switch v1",
                        &(
                            expected,
                            pp.final_helper.context_digest::<F, Sha256>().unwrap(),
                            final_acc,
                            requested.output_a,
                            requested.output_b,
                            &co.roots,
                            &ev.roots,
                        ),
                    )
                };
                bind(prover);
                bind(reference);
                let co_o = co.oracles(pp.final_source);
                let ev_o = ev.oracles(pp.final_source);
                let key_o = keys.oracles(pp.final_source);
                let in_o = input.oracles(pp.final_source);
                let shape = ntt::Shape::new::<F, _>(pp.final_source, n).unwrap();
                let mut ntt_proofs = Vec::new();
                for i in 0..d + 1 {
                    let proof = ntt::prove::<F, Sha256, _>(prover, &shape, &co_o[i], &ev_o[i]).unwrap();
                    ntt::verify::<F, Sha256, _>(
                        reference,
                        &shape,
                        &co_o[i].verifier(),
                        &ev_o[i].verifier(),
                        &proof,
                    )
                    .unwrap();
                    ntt_proofs.push(proof);
                }
                let mut factors = Vec::new();
                let mut roots = Vec::new();
                let mut states = Vec::new();
                for i in 0..d {
                    for o in [&ev_o[i], &key_o[i]] {
                        factors.push(o.table.clone());
                        roots.push(o.commitment.clone());
                        states.push(o.state);
                    }
                }
                factors.push(ev.tables[d].clone());
                roots.push(ev.roots[d].clone());
                states.push(&ev.states[d]);
                let mut declared = roots.clone();
                for i in 0..d {
                    declared[2 * i + 1] = expected.roots()[i].clone();
                }
                let product = relation_with_declared_roots(
                    prover,
                    reference,
                    pp.final_source,
                    &product_shape(pp.final_source, d),
                    &factors,
                    &roots,
                    &states,
                    &declared,
                );
                let config = decomp::Config::new::<F>(5, 2 * n, $repetitions).unwrap();
                let digits = co_o[..d].iter().collect::<Vec<_>>();
                let decomposition = decomp::$prove::<F, $($extension,)? Sha256, _>(
                    prover,
                    &config,
                    &in_o[0],
                    pp.final_helper,
                    &digits,
                )
                .unwrap();
                decomp::$verify::<F, $($extension,)? Sha256, _>(
                    reference,
                    &config,
                    &in_o[0].verifier(),
                    pp.final_helper,
                    &digits.iter().map(|s| s.verifier()).collect::<Vec<_>>(),
                    &decomposition,
                )
                .unwrap();
                let mut mask = vec![F::from(0usize); 2 * n];
                let mut target = mask.clone();
                mask[0] = F::from(1usize);
                target[0] = actual.output_a[0];
                for i in 1..actual.output_a.len() {
                    mask[n - i] = F::from(1usize);
                    target[n - i] = -actual.output_a[i];
                }
                mask[n] = F::from(1usize);
                let bias = mono::nand_lut::<F>(n, 1).unwrap()[0];
                target[n] = actual.output_b - final_acc[n] - bias;
                let mut requested_target = target.clone();
                requested_target[0] = requested.output_a[0];
                for i in 1..requested.output_a.len() {
                    requested_target[n - i] = -requested.output_a[i];
                }
                requested_target[n] = requested.output_b - final_acc[n] - bias;
                let make = |v| PackedTable::new(pp.final_source.num_vars(), width, v).unwrap();
                let mask = make(mask);
                let target = make(target);
                let requested_target = make(requested_target);
                let shape = PackedShape {
                    num_vars: pp.final_source.num_vars(),
                    width,
                    num_factors: 3,
                    terms: vec![(F::from(1usize), vec![0, 1]), (-F::from(1usize), vec![2])],
                };
                let (zero, claim, terminal) = packed_zero::prove_with_terminal_values(
                    prover,
                    &shape,
                    &[co.tables[d].clone(), mask.clone(), target.clone()],
                )
                .unwrap();
                let value = terminal[0].clone();
                let verified = packed_zero::verify(reference, &shape, &zero).unwrap();
                let mask_value = mask.evaluate(&verified.query).unwrap();
                verified
                    .check(
                        &shape,
                        &[
                            value.clone(),
                            mask_value.clone(),
                            target.evaluate(&verified.query).unwrap(),
                        ],
                    )
                    .unwrap();
                let wrong = requested.output_a != actual.output_a || requested.output_b != actual.output_b;
                assert_eq!(
                    verified
                        .check(
                            &shape,
                            &[
                                value.clone(),
                                mask_value,
                                requested_target.evaluate(&verified.query).unwrap()
                            ]
                        )
                        .is_err(),
                    wrong
                );
                let opening = pp
                    .final_source
                    .open::<F, Sha256>(prover, &co.roots[d], &co.states[d], &claim.query, &value)
                    .unwrap();
                pp.final_source
                    .verify::<F, Sha256>(reference, &co.roots[d], &verified.query, &value, &opening)
                    .unwrap();
                ks::Proof {
                    coefficients: co.roots.clone(),
                    evaluations: ev.roots.clone(),
                    ntt: ntt_proofs,
                    product,
                    decomposition,
                    extraction: ks::ExtractionProof {
                        zero,
                        value,
                        opening,
                    },
                }
            }
            #[test]
            fn genuine_full_children_under_requested_statement_fail_public_equations() {
                let native_params = params::<F>();
                let n = native_params.ring_dimension();
                let lwe = native_params.lwe_dimension();
                let width = $width;
                let cfg = pbs::Config::new::<F>(n, lwe, 8, 5, 1, $repetitions).unwrap();
                let codes = cfg
                    .variables(width)
                    .unwrap()
                    .map(|n| Parameters::<C>::balanced_block_rs(n, width, 32, 2).unwrap());
                let pp = pbs::Parameters {
                    source: &codes[0],
                    helper: &codes[1],
                    final_source: &codes[2],
                    final_helper: &codes[3],
                };
                let sk = secret::<F>(42);
                let enc = Encryptor::new(sk.clone());
                let evaluator = Evaluator::new(&sk);
                let setup = pbs::preprocess::<F, Sha256, _>(
                    &pp,
                    cfg.clone(),
                    evaluator.binary_bootstrap_key().unwrap(),
                    evaluator.rlwe_key_switching_key().unwrap().as_slice(),
                )
                .unwrap();
                let expected = setup.verifier();
                let x = enc.encrypt(1);
                let y = enc.encrypt(1);
                let (out, mut trace) = evaluator.nand(&x, &y);
                let actual = pbs::Statement {
                    left_a: x.a(),
                    left_b: x.b(),
                    right_a: y.a(),
                    right_b: y.b(),
                    output_a: out.a(),
                    output_b: out.b(),
                };
                let honest = pbs::$pbs_prove::<F, $($extension,)? Sha256, _>(
                    &pp, &setup, &actual, &trace,
                )
                .unwrap();
                pbs::$pbs_verify::<F, $($extension,)? Sha256, _>(
                    &pp, &expected, &actual, &honest,
                )
                .unwrap();
                trace.blind_rotation_trace.finalize(lwe);
                let columns = relation::coefficients_from_sum_hadamard(
                    width,
                    &trace.blind_rotation_trace.hadamard_trace,
                )
                .unwrap();
                let co = Sources::new(pp.source, columns.into_iter().step_by(2).collect());
                let ev = Sources::new(pp.source, transforms(&co.tables, n));
                let ac = Sources::new(
                    pp.source,
                    acc::from_native(width, &trace.blind_rotation_trace).unwrap(),
                );
                let input = Sources::new(
                    pp.source,
                    decomp::sources_from_blind_rotation(width, &trace.blind_rotation_trace).unwrap(),
                );
                let mono_ev = Sources::new(pp.source, transforms(&ac.tables[..2], n));
                let final_acc = &honest.final_accumulator;
                assert_roots(&co.roots, &honest.coefficients);
                assert_roots(&ev.roots, &honest.evaluations);
                assert_roots(&ac.roots, &honest.accumulators);
                assert_roots(&input.roots, &honest.decomposition_inputs);
                assert_roots(&mono_ev.roots, &honest.monomial.evaluations);
                let br =
                    bk::prepare::<F, Sha256, _>(pp.source, n, evaluator.binary_bootstrap_key().unwrap())
                        .unwrap();
                let key = ks::preprocess::<F, Sha256, _>(
                    pp.final_source,
                    ks::Config::new::<F>(n, lwe, 5, $repetitions).unwrap(),
                    evaluator.rlwe_key_switching_key().unwrap().as_slice(),
                )
                .unwrap();
                let ks_columns = ks::from_native(width, &trace.key_switching_trace).unwrap();
                let ks_co = Sources::new(pp.final_source, ks_columns);
                let ks_ev = Sources::new(pp.final_source, transforms(&ks_co.tables, n));
                let ks_keys = Sources::new(
                    pp.final_source,
                    evaluator.rlwe_key_switching_key().unwrap().as_slice()[0]
                        .iter()
                        .map(|p| {
                            PackedTable::new(
                                pp.final_source.num_vars(),
                                width,
                                p.a_slice().iter().chain(p.b_slice()).copied().collect(),
                            )
                            .unwrap()
                        })
                        .collect(),
                );
                let ks_input = Sources::new(
                    pp.final_source,
                    vec![
                        PackedTable::new(
                            pp.final_source.num_vars(),
                            width,
                            final_acc[..n]
                                .iter()
                                .chain(&final_acc[..n])
                                .map(|&v| -v)
                                .collect(),
                        )
                        .unwrap(),
                    ],
                );
                assert_roots(&ks_co.roots, &honest.key_switch.coefficients);
                assert_roots(&ks_ev.roots, &honest.key_switch.evaluations);
                assert_roots(&ks_keys.roots, key.expected().roots());

                let key_o = br.oracles(pp.source).unwrap();
                let d = key_o.len() / 2;
                let mask = x
                    .a()
                    .iter()
                    .zip(y.a())
                    .map(|(&a, &b)| a + b)
                    .collect::<Vec<_>>();
                let actual_plan = mono::Plan::from_field_mask(n, &mask).unwrap();
                let lut = mono::nand_lut::<F>(n, 1).unwrap();
                let contexts = [pp.source, pp.helper, pp.final_source, pp.final_helper]
                    .iter()
                    .map(|p| p.context_digest::<F, Sha256>().unwrap())
                    .collect::<Vec<_>>();
                let mut changed = x.a().to_vec();
                let step: <F as Field>::Value = (F::MODULUS_VALUE as u128 / (2 * n) as u128 + 1)
                    .try_into()
                    .unwrap();
                changed[0] += F::new(step);
                let requested = pbs::Statement {
                    left_a: &changed,
                    left_b: x.b(),
                    right_a: y.a(),
                    right_b: y.b(),
                    output_a: out.a(),
                    output_b: out.b(),
                };
                let requested_cipher = fhe_core::LWECiphertext::new(changed.clone(), x.b());
                let (correct_requested_output, _) = evaluator.nand(&requested_cipher, &y);
                assert!(
                    out.a() != correct_requested_output.a() || out.b() != correct_requested_output.b(),
                    "the forged statement must have a genuinely wrong native output"
                );
                // The control validates this independently framed protocol against the
                // production API; changes to framing or stage order cannot silently
                // turn the attack into an unrelated transcript-replay rejection.
                let mut requested_output = actual.clone();
                requested_output.output_b += F::from(1usize);
                let mut changed_output_a = out.a().to_vec();
                changed_output_a[lwe - 1] += F::from(1usize);
                let mut requested_a = actual.clone();
                requested_a.output_a = &changed_output_a;
                let foreign_sk = secret::<F>(99);
                let foreign_evaluator = Evaluator::new(&foreign_sk);
                let wrong_br_setup = pbs::preprocess::<F, Sha256, _>(
                    &pp,
                    cfg.clone(),
                    foreign_evaluator.binary_bootstrap_key().unwrap(),
                    evaluator.rlwe_key_switching_key().unwrap().as_slice(),
                )
                .unwrap()
                .verifier();
                let wrong_ks_setup = pbs::preprocess::<F, Sha256, _>(
                    &pp,
                    cfg.clone(),
                    evaluator.binary_bootstrap_key().unwrap(),
                    foreign_evaluator
                        .rlwe_key_switching_key()
                        .unwrap()
                        .as_slice(),
                )
                .unwrap()
                .verifier();
                let foreign_br = bk::prepare::<F, Sha256, _>(
                    pp.source,
                    n,
                    foreign_evaluator.binary_bootstrap_key().unwrap(),
                )
                .unwrap();
                let foreign_ks = ks::preprocess::<F, Sha256, _>(
                    pp.final_source,
                    ks::Config::new::<F>(n, lwe, 5, $repetitions).unwrap(),
                    foreign_evaluator
                        .rlwe_key_switching_key()
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
                assert!(
                    foreign_br
                        .expected()
                        .roots()
                        .iter()
                        .zip(br.expected().roots())
                        .any(|(a, b)| a.root != b.root)
                );
                assert!(
                    foreign_ks
                        .expected()
                        .roots()
                        .iter()
                        .zip(key.expected().roots())
                        .any(|(a, b)| a.root != b.root)
                );

                // Two valid traces with the same mask/key but different public
                // initial bodies. Splicing whole rounds keeps every local
                // equation true while breaking only their continuity.
                let alternate_cipher = fhe_core::LWECiphertext::new(x.a().to_vec(), x.b() + F::new(step));
                let (alternate_output, mut alternate_trace) = evaluator.nand(&alternate_cipher, &y);
                assert!(out.a() != alternate_output.a() || out.b() != alternate_output.b());
                let alternate_statement = pbs::Statement {
                    left_a: alternate_cipher.a(),
                    left_b: alternate_cipher.b(),
                    right_a: y.a(),
                    right_b: y.b(),
                    output_a: alternate_output.a(),
                    output_b: alternate_output.b(),
                };
                let alternate_honest = pbs::$pbs_prove::<F, $($extension,)? Sha256, _>(
                    &pp,
                    &setup,
                    &alternate_statement,
                    &alternate_trace,
                )
                .unwrap();
                pbs::$pbs_verify::<F, $($extension,)? Sha256, _>(
                    &pp,
                    &expected,
                    &alternate_statement,
                    &alternate_honest,
                )
                .unwrap();
                alternate_trace.blind_rotation_trace.finalize(lwe);
                let alternate_co = Sources::new(
                    pp.source,
                    relation::coefficients_from_sum_hadamard(
                        width,
                        &alternate_trace.blind_rotation_trace.hadamard_trace,
                    )
                    .unwrap()
                    .into_iter()
                    .step_by(2)
                    .collect(),
                );
                let alternate_ev = Sources::new(pp.source, transforms(&alternate_co.tables, n));
                let alternate_ac = Sources::new(
                    pp.source,
                    acc::from_native(width, &alternate_trace.blind_rotation_trace).unwrap(),
                );
                let alternate_input = Sources::new(
                    pp.source,
                    decomp::sources_from_blind_rotation(width, &alternate_trace.blind_rotation_trace)
                        .unwrap(),
                );
                let alternate_ks_co = Sources::new(
                    pp.final_source,
                    ks::from_native(width, &alternate_trace.key_switching_trace).unwrap(),
                );
                let alternate_ks_ev = Sources::new(pp.final_source, transforms(&alternate_ks_co.tables, n));
                let alternate_ks_input = Sources::new(
                    pp.final_source,
                    vec![
                        PackedTable::new(
                            pp.final_source.num_vars(),
                            width,
                            alternate_honest.final_accumulator[..n]
                                .iter()
                                .chain(&alternate_honest.final_accumulator[..n])
                                .map(|&v| -v)
                                .collect(),
                        )
                        .unwrap(),
                    ],
                );
                let split = lwe / 2;
                assert!(split > 0 && split < lwe);
                let spliced_co = splice(pp.source, &co, &alternate_co, n, split);
                let spliced_ev = Sources::new(pp.source, transforms(&spliced_co.tables, n));
                let spliced_ac = splice(pp.source, &ac, &alternate_ac, n, split);
                let spliced_input = splice(pp.source, &input, &alternate_input, n, split);
                let spliced_mono = Sources::new(pp.source, transforms(&spliced_ac.tables[..2], n));
                let rows = lwe.next_power_of_two();
                assert!((0..2).any(
                    |h| (0..n).any(|j| spliced_ac.tables[acc::INPUT_ACC].values()
                        [(h * rows + split) * n + j]
                        != spliced_ac.tables[acc::OUTPUT_ACC].values()[(h * rows + split - 1) * n + j])
                ));
                let mut wrong_initial = actual.clone();
                wrong_initial.left_b = alternate_cipher.b();
                let mut wrong_final = final_acc.clone();
                wrong_final[n] += F::from(1usize);
                let mut chain_statement = actual.clone();
                chain_statement.output_a = alternate_output.a();
                chain_statement.output_b = alternate_output.b();
                #[derive(Clone, Copy, Debug, PartialEq)]
                enum Attack {
                    Control,
                    InputMask,
                    OutputBody,
                    OutputA,
                    BlindKey,
                    SwitchKey,
                    InitialEndpoint,
                    FinalEndpoint,
                    Chain,
                    DuplicateView,
                }
                for attack in [
                    Attack::Control,
                    Attack::InputMask,
                    Attack::OutputBody,
                    Attack::OutputA,
                    Attack::BlindKey,
                    Attack::SwitchKey,
                    Attack::InitialEndpoint,
                    Attack::FinalEndpoint,
                    Attack::Chain,
                    Attack::DuplicateView,
                ] {
                    let statement = match attack {
                        Attack::InputMask => &requested,
                        Attack::OutputBody | Attack::FinalEndpoint => &requested_output,
                        Attack::OutputA => &requested_a,
                        Attack::InitialEndpoint => &wrong_initial,
                        Attack::Chain => &chain_statement,
                        _ => &actual,
                    };
                    let expected = match attack {
                        Attack::BlindKey => &wrong_br_setup,
                        Attack::SwitchKey => &wrong_ks_setup,
                        _ => &expected,
                    };
                    let declared_br = if attack == Attack::BlindKey {
                        foreign_br.expected()
                    } else {
                        br.expected()
                    };
                    let key = if attack == Attack::SwitchKey {
                        &foreign_ks
                    } else {
                        &key
                    };
                    let co = match attack {
                        Attack::Chain => &spliced_co,
                        Attack::DuplicateView => &alternate_co,
                        _ => &co,
                    };
                    let ev = match attack {
                        Attack::Chain => &spliced_ev,
                        Attack::DuplicateView => &alternate_ev,
                        _ => &ev,
                    };
                    let input = match attack {
                        Attack::Chain => &spliced_input,
                        Attack::DuplicateView => &alternate_input,
                        _ => &input,
                    };
                    let ac = if attack == Attack::Chain {
                        &spliced_ac
                    } else {
                        &ac
                    };
                    let mono_ev = if attack == Attack::Chain {
                        &spliced_mono
                    } else {
                        &mono_ev
                    };
                    let final_acc = match attack {
                        Attack::FinalEndpoint => &wrong_final,
                        Attack::Chain => &alternate_honest.final_accumulator,
                        _ => final_acc,
                    };
                    let initial =
                        mono::initial_accumulator(&lut, statement.left_b + statement.right_b).unwrap();
                    let ks_co = if attack == Attack::Chain {
                        &alternate_ks_co
                    } else {
                        &ks_co
                    };
                    let ks_ev = if attack == Attack::Chain {
                        &alternate_ks_ev
                    } else {
                        &ks_ev
                    };
                    let ks_input = if attack == Attack::Chain {
                        &alternate_ks_input
                    } else {
                        &ks_input
                    };
                    if attack == Attack::DuplicateView {
                        let half = ac.tables[acc::EXTERNAL_INPUT].values().len() / 2;
                        assert!(input.tables.iter().enumerate().any(|(h, table)| {
                            table.values().iter().enumerate().any(|(i, &v)| {
                                v != ac.tables[acc::EXTERNAL_INPUT].values()[h * half + i % half]
                            })
                        }));
                    }
                    let actual_target = if matches!(attack, Attack::FinalEndpoint | Attack::Chain) {
                        statement
                    } else {
                        &actual
                    };
                    let co_o = co.oracles(pp.source);
                    let ev_o = ev.oracles(pp.source);
                    let ac_o = ac.oracles(pp.source);
                    let in_o = input.oracles(pp.source);
                    let mono_o = mono_ev.oracles(pp.source);

                    let request_mask = statement
                        .left_a
                        .iter()
                        .zip(statement.right_a)
                        .map(|(&a, &b)| a + b)
                        .collect::<Vec<_>>();
                    let requested_plan = mono::Plan::from_field_mask(n, &request_mask).unwrap();
                    let bad = actual_plan.rotations() != requested_plan.rotations();
                    if std::ptr::eq(statement, &requested) {
                        assert!(bad);
                    } else {
                        assert!(!bad);
                    }
                    let start = || {
                        let mut t = Transcript::new_direct();
                        t.append_message(
                            $domain,
                            &(
                                $version,
                                &expected,
                                &contexts,
                                statement,
                                &co.roots,
                                &ev.roots,
                                &input.roots,
                                &ac.roots,
                                final_acc,
                            ),
                        );
                        t
                    };
                    let mut prover = start();
                    let mut reference = start();
                    let mut factors = Vec::new();
                    let mut roots = Vec::new();
                    let mut states = Vec::new();
                    for i in 0..2 * d {
                        for o in [&ev_o[i], &key_o[i]] {
                            factors.push(o.table.clone());
                            roots.push(o.commitment.clone());
                            states.push(o.state);
                        }
                    }
                    factors.push(ev.tables[2 * d].clone());
                    roots.push(ev.roots[2 * d].clone());
                    states.push(&ev.states[2 * d]);
                    let declared =
                        bk::commitments::<F, Sha256, _>(pp.source, declared_br, &ev.roots).unwrap();
                    let hadamard = hadamard_with_declared_roots(
                        &mut prover,
                        &mut reference,
                        pp.source,
                        &product_shape(pp.source, 2 * d),
                        &factors,
                        &roots,
                        &states,
                        &declared,
                    );
                    let ntt_shape = ntt::Shape::new::<F, _>(pp.source, n).unwrap();
                    let mut ntt_proofs = Vec::new();
                    for i in 0..2 * d + 1 {
                        let proof = ntt::prove::<F, Sha256, _>(&mut prover, &ntt_shape, &co_o[i], &ev_o[i])
                            .unwrap();
                        ntt::verify::<F, Sha256, _>(
                            &mut reference,
                            &ntt_shape,
                            &co_o[i].verifier(),
                            &ev_o[i].verifier(),
                            &proof,
                        )
                        .unwrap();
                        ntt_proofs.push(proof);
                    }
                    let config =
                        decomp::Config::new::<F>(8, input.tables[0].values().len(), $repetitions)
                            .unwrap();
                    let mut decomposition = Vec::new();
                    for half in 0..2 {
                        let digits = co_o[half * d..(half + 1) * d].iter().collect::<Vec<_>>();
                        let proof = decomp::$prove::<F, $($extension,)? Sha256, _>(
                            &mut prover,
                            &config,
                            &in_o[half],
                            pp.helper,
                            &digits,
                        )
                        .unwrap();
                        decomp::$verify::<F, $($extension,)? Sha256, _>(
                            &mut reference,
                            &config,
                            &in_o[half].verifier(),
                            pp.helper,
                            &digits.iter().map(|d| d.verifier()).collect::<Vec<_>>(),
                            &proof,
                        )
                        .unwrap();
                        decomposition.push(proof);
                    }
                    let acc_shape = acc::Shape::new(n, lwe).unwrap();
                    let sources = [
                        &ac_o[0],
                        &ac_o[1],
                        &ac_o[2],
                        &ac_o[3],
                        &co_o[2 * d],
                        &in_o[0],
                        &in_o[1],
                    ];
                    let accumulator = accumulator_certificate(
                        &mut prover,
                        &mut reference,
                        &acc_shape,
                        &initial,
                        final_acc,
                        &sources,
                    );
                    // Bind the REQUESTED plan in both complete and child domains. Only
                    // the public monomial polynomial used in ZeroCheck is dishonest.
                    let bind_mono = |t: &mut Transcript<F>| {
                        let contexts = ac_o[..2]
                            .iter()
                            .map(|s| {
                                (
                                    pp.source.context_digest::<F, Sha256>().unwrap(),
                                    s.commitment,
                                )
                            })
                            .collect::<Vec<_>>();
                        t.append_message(
                            b"packed expected monomial product v1",
                            &(
                                &requested_plan,
                                F::get_ntt_table(n.ilog2()).unwrap().root(),
                                contexts,
                            ),
                        );
                        t.append_message(b"public monomial NTT roots", &mono_ev.roots);
                    };
                    bind_mono(&mut prover);
                    bind_mono(&mut reference);
                    let mut mono_ntt = Vec::new();
                    for i in 0..2 {
                        let proof =
                            ntt::prove::<F, Sha256, _>(&mut prover, &ntt_shape, &ac_o[i], &mono_o[i])
                                .unwrap();
                        ntt::verify::<F, Sha256, _>(
                            &mut reference,
                            &ntt_shape,
                            &ac_o[i].verifier(),
                            &mono_o[i].verifier(),
                            &proof,
                        )
                        .unwrap();
                        mono_ntt.push(proof);
                    }
                    let product_shape = PackedShape {
                        num_vars: pp.source.num_vars(),
                        width,
                        num_factors: 3,
                        terms: vec![(F::from(1usize), vec![0, 1]), (-F::from(1usize), vec![2])],
                    };
                    let factors = [
                        mono_ev.tables[0].clone(),
                        actual_plan.table::<F>(width).unwrap(),
                        mono_ev.tables[1].clone(),
                    ];
                    let (product, subclaim, terminal) =
                        packed_zero::prove_with_terminal_values(&mut prover, &product_shape, &factors)
                            .unwrap();
                    let values = vec![terminal[0].clone(), terminal[2].clone()];
                    let verified = packed_zero::verify(&mut reference, &product_shape, &product).unwrap();
                    verified
                        .check(
                            &product_shape,
                            &[
                                values[0].clone(),
                                actual_plan.evaluate(width, &verified.query).unwrap(),
                                values[1].clone(),
                            ],
                        )
                        .unwrap();
                    let requested_check = verified.check(
                        &product_shape,
                        &[
                            values[0].clone(),
                            requested_plan.evaluate(width, &verified.query).unwrap(),
                            values[1].clone(),
                        ],
                    );
                    assert_eq!(requested_check.is_err(), bad);
                    let mut openings = Vec::new();
                    for i in 0..2 {
                        let opening = pp
                            .source
                            .open::<F, Sha256>(
                                &mut prover,
                                &mono_ev.roots[i],
                                &mono_ev.states[i],
                                &subclaim.query,
                                &values[i],
                            )
                            .unwrap();
                        pp.source
                            .verify::<F, Sha256>(
                                &mut reference,
                                &mono_ev.roots[i],
                                &verified.query,
                                &values[i],
                                &opening,
                            )
                            .unwrap();
                        openings.push(opening);
                    }
                    let monomial = mono::Proof {
                        evaluations: mono_ev.roots.clone(),
                        ntt: mono_ntt,
                        product,
                        values,
                        openings,
                    };
                    let key_switch = key_switch_with_actual_target(
                        &mut prover,
                        &mut reference,
                        &pp,
                        key.expected(),
                        &ks_co,
                        &ks_ev,
                        &ks_keys,
                        &ks_input,
                        final_acc,
                        statement,
                        actual_target,
                    );
                    assert_eq!(
                        prover.get_challenge(b"after complete forgery"),
                        reference.get_challenge(b"after complete forgery")
                    );
                    let forged = pbs::Proof {
                        protocol_version: $version,
                        coefficients: co.roots.clone(),
                        evaluations: ev.roots.clone(),
                        decomposition_inputs: input.roots.clone(),
                        accumulators: ac.roots.clone(),
                        final_accumulator: final_acc.clone(),
                        hadamard,
                        ntt: ntt_proofs,
                        decomposition,
                        accumulator,
                        monomial,
                        key_switch,
                    };
                    let bytes =
                        bincode::serde::encode_to_vec(&forged, bincode::config::standard()).unwrap();
                    let (forged, used): (FullProof, _) =
                        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
                    assert_eq!(used, bytes.len());
                    let result = pbs::$pbs_verify::<F, $($extension,)? Sha256, _>(
                        &pp, &expected, statement, &forged,
                    );
                    let production_accepted = result.is_ok();
                    match attack {
                        Attack::Control => result.unwrap(),
                        Attack::BlindKey | Attack::SwitchKey => {
                            let error = result.unwrap_err().to_string();
                            assert!(error.contains("matrix-weighted PCS"), "{attack:?}: {error}");
                            if attack == Attack::SwitchKey {
                                assert!(error.contains("packed key switch"), "{error}");
                            }
                        }
                        Attack::InitialEndpoint | Attack::FinalEndpoint | Attack::DuplicateView => {
                            let error = result.unwrap_err().to_string();
                            assert!(error.contains("packed accumulator linkage: false arithmetic, duplicated-half or endpoint identity"),"{attack:?}: {error}");
                        }
                        Attack::Chain => {
                            let error = result.unwrap_err().to_string();
                            assert!(
                                error.contains(
                                    "packed accumulator linkage: false accumulator round continuity"
                                ),
                                "{attack:?}: {error}"
                            );
                        }
                        Attack::InputMask | Attack::OutputBody | Attack::OutputA => {
                            let error = result.unwrap_err().to_string();
                            if attack != Attack::InputMask {
                                assert!(error.contains("packed key switch"), "{error}");
                            }
                            assert!(
                                error.contains("packed ZeroCheck terminal identity failed"),
                                "{attack:?}: {error}"
                            );
                        }
                    }
                    eprintln!(
                        "HB_BINDING_CASE {{\"protocol_version\":{},\"prime\":{},\"attack\":\"{:?}\",\"reference_scope\":\"local-algebra-and-actual-root-openings\",\"production_accepted\":{}}}",
                        $version,
                        F::MODULUS_VALUE,
                        attack,
                        production_accepted
                    );
                }
            }
        }
    };
}
