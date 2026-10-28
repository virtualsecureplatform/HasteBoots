// Complete experimental binary NAND PBS proof and independent verification.
use algebra::{
    AbstractExtensionField, AsInto, Field,
    utils::{Block, Prg},
};
use fhe_core::{
    ConstParameters, LWESecretKeyType, Parameters as FheParameters, RingSecretKeyType,
    SecretKeyPack,
};
use pcs::{
    matrix_weighted::Parameters,
    utils::code::{BlockReedSolomonCode, RowCode},
};
use rand::SeedableRng;
use sha2::{Digest, Sha256};
use snarks::packed_pbs as pbs;
use std::time::Instant;
use vfhe::{Decryptor, Encryptor, bfhe::Evaluator};
fn lookup_statistics(s: &snarks::packed_lane_lookup::ProverStatistics) -> String {
    format!("{{\"preparation_ns\":{},\"commitment_ns\":{},\"sumcheck_ns\":{},\"zero_check_ns\":{},\"terminal_evaluation_ns\":{},\"openings_ns\":{}}}",
        s.preparation.as_nanos(),s.commitment.as_nanos(),s.sumcheck.as_nanos(),
        s.zero_check.as_nanos(),s.terminal_evaluation.as_nanos(),s.openings.as_nanos())
}
fn emit_statistics(version: u32, count: usize, digest: &str, prove_ns: u128,
    s: &pbs::batch::shared::Statistics) {
    let m=&s.members;
    let members_total=if version==5 {prove_ns} else {s.members_total.as_nanos()};
    let blind_rotation=lookup_statistics(&s.blind_rotation);
    let key_switch=lookup_statistics(&s.key_switch);
    println!("HB_BATCH_PHASES {{\"scope\":\"complete-prover-wall-clock-phases\",\"protocol_version\":{version},\"proof_sha256\":\"{digest}\",\"batch_size\":{count},\"prove_ns\":{prove_ns},\"outer\":{{\"members_total_ns\":{members_total},\"binding_ns\":{},\"hadamard_ns\":{},\"release_evaluations_ns\":{},\"blind_rotation_total_ns\":{},\"key_switch_total_ns\":{}}},\"members\":{{\"preparation_ns\":{},\"hadamard_ns\":{},\"ntt_ns\":{},\"decomposition_ns\":{},\"accumulator_ns\":{},\"monomial_ns\":{},\"key_switch_ns\":{}}},\"blind_rotation\":{blind_rotation},\"key_switch\":{key_switch}}}",
        s.binding.as_nanos(),s.hadamard.as_nanos(),s.release_evaluations.as_nanos(),
        s.blind_rotation_total.as_nanos(),s.key_switch_total.as_nanos(),
        m.preparation.as_nanos(),m.hadamard.as_nanos(),m.ntt.as_nanos(),
        m.decomposition.as_nanos(),m.accumulator.as_nanos(),m.monomial.as_nanos(),m.key_switch.as_nanos());
}
fn main() {
    let args:Vec<_>=std::env::args().collect();
    let full=args.iter().any(|s|s=="--full");
    let separate=args.iter().any(|s|s=="--separate");
    let canonical=args.iter().any(|s|s=="--canonical-sources");
    let comparisons=args.iter().any(|s|s=="--joint-comparisons");
    assert!([separate,canonical,comparisons].into_iter().filter(|x|*x).count()<=1,
        "select one of --separate, --canonical-sources, --joint-comparisons");
    let validation=args.iter().any(|s|s=="--validation-batches");
    let count=args.iter().position(|s|s=="--batch-size").map(|i|args[i+1].parse::<usize>().unwrap()).unwrap_or(1);
    assert!(count>0 && !(validation && args.iter().any(|s|s=="--batch-size")));
    let repeated=args.iter().any(|s|s=="--iterations");
    let iterations=args.iter().position(|s|s=="--iterations").map(|i|args[i+1].parse::<usize>().unwrap()).unwrap_or(1);
    assert!(iterations>0 && !(validation && repeated),"--iterations requires a non-validation run");
    let width=WIDTH;let helper_left_extra=HELPER_EXTRA;let repetitions=1;
    let params = if full {
        *PARAMETERS
    } else {
        FheParameters::<F>::new(ConstParameters {
            lwe_dimension: 32,
            lwe_plain_modulus: 4usize.as_into(),
            lwe_noise_standard_deviation: 1.0,
            lwe_secret_key_type: LWESecretKeyType::Binary,
            ring_dimension: 32,
            ring_modulus: F::MODULUS_VALUE,
            ring_noise_standard_deviation: 1.0,
            ring_secret_key_type: RingSecretKeyType::Ternary,
            blind_rotation_basis_bits: 8,
            key_switching_basis_bits: 5,
            key_switching_standard_deviation: 1.0,
        })
        .unwrap()
    };
    let mut seed = [0u8; 16];
    seed[..8].copy_from_slice(&42u64.to_le_bytes());
    let sk = SecretKeyPack::with_rng(params, Prg::from_seed(Block::from(seed)));
    let enc = Encryptor::new(sk.clone());
    let evaluator = Evaluator::new(&sk);
    let dec = Decryptor::new(sk);
    let fhe_parameters_sha256 = format!("{:x}", Sha256::digest(format!("{params:?}").as_bytes()));
    let br_data: Vec<_> = evaluator
        .binary_bootstrap_key()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r.basis().bits(),
                [r.c_neg_s_m(), r.c_m()]
                    .map(|g| g.data().iter().map(|p| p.a_b_slice()).collect::<Vec<_>>()),
            )
        })
        .collect();
    let ks_data: Vec<_> = evaluator
        .rlwe_key_switching_key()
        .unwrap()
        .as_slice()
        .iter()
        .map(|g| {
            (
                g.basis().bits(),
                g.data().iter().map(|p| p.a_b_slice()).collect::<Vec<_>>(),
            )
        })
        .collect();
    let native_keys_sha256 = format!(
        "{:x}",
        Sha256::digest(
            bincode::serde::encode_to_vec(&(br_data, ks_data), bincode::config::standard())
                .unwrap()
        )
    );
    let cfg = pbs::Config::new::<F>(
        params.ring_dimension(),
        params.lwe_dimension(),
        params.blind_rotation_basis().bits(),
        params.key_switching_basis_bits(),
        params.lut_step(),
        repetitions,
    )
    .unwrap();
    let dims = cfg.variables(width).unwrap();
    let codes: [_; 4] = std::array::from_fn(|role| {
        let n = dims[role];
        let balanced = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(n, width, 544, 2).unwrap();
        if role % 2 == 0 || helper_left_extra == 0 {
            balanced
        } else {
            let left = balanced.left_vars().checked_add(helper_left_extra).unwrap();
            assert!(left <= n, "helper split exceeds dimension");
            let code = BlockReedSolomonCode::<F>::new(1usize << (n - left), width, 2).unwrap();
            Parameters::new_encoded::<F>(n, width, left, 544, code).unwrap()
        }
    });
    for (role, p) in ["source", "helper", "final_source", "final_helper"]
        .iter()
        .zip(&codes)
    {
        println!(
            "HB_FULL_PCS {{\"role\":\"{role}\",\"row_code\":\"block-rs\",\"prime\":{},\"width\":{},\"variables\":{},\"left_vars\":{},\"row_message_scalars\":{},\"row_message_blocks\":{},\"row_encoded_blocks\":{},\"block_width\":{},\"queries\":{}}}",
            F::MODULUS_VALUE,
            p.width(),
            p.num_vars(),
            p.left_vars(),
            p.code().message_len(),
            p.code().message_blocks(),
            p.code().codeword_blocks(),
            p.code().block_width(),
            p.queries()
        );
    }
    let pp = pbs::Parameters {
        source: &codes[0],
        helper: &codes[1],
        final_source: &codes[2],
        final_helper: &codes[3],
    };
    let timer = Instant::now();
    let setup = pbs::preprocess::<F, Sha256, _>(
        &pp,
        cfg,
        evaluator.binary_bootstrap_key().unwrap(),
        evaluator.rlwe_key_switching_key().unwrap().as_slice(),
    )
    .unwrap();
    let setup_ns = timer.elapsed().as_nanos();
    let verifier = setup.verifier();
    // Preserve the established fresh-input fixture's initial random stream.
    let _initial_x=enc.encrypt(1usize.as_into());let _initial_y=enc.encrypt(1usize.as_into());
    let sizes=if validation {vec![1,4,16]} else {vec![count;iterations]};
    for (iteration,count) in sizes.into_iter().enumerate() {
        let inputs:Vec<_>=(0..count).map(|i| {
            let left=i&1;let right=(i>>1)&1;
            (enc.encrypt(left.as_into()),enc.encrypt(right.as_into()),left,right)
        }).collect();
        let complete=Instant::now();
        let (outputs,traces):(Vec<_>,Vec<_>)=inputs.iter().map(|(x,y,_,_)|evaluator.nand(x,y)).unzip();
        let trace_ns=complete.elapsed().as_nanos();
        for ((_,_,left,right),out) in inputs.iter().zip(&outputs) {
            assert_eq!(dec.decrypt_with_noise(out).0,(1-left*right).as_into());
        }
        let statements:Vec<_>=inputs.iter().zip(&outputs).map(|((x,y,_,_),out)|pbs::Statement {
            left_a:x.a(),left_b:x.b(),right_a:y.a(),right_b:y.b(),output_a:out.a(),output_b:out.b(),
        }).collect();
        let member_digests:Vec<_>=statements.iter().map(|s|format!("{:x}",Sha256::digest(
            bincode::serde::encode_to_vec(s,bincode::config::standard()).unwrap()))).collect();
        let statements_sha256=format!("{:x}",Sha256::digest(
            bincode::serde::encode_to_vec(&statements,bincode::config::standard()).unwrap()));
        macro_rules! certificate {($prove:expr,$ty:ty,$verify:expr,$inventory:expr)=>{{
            let timer=Instant::now();let proof=$prove;let prove_ns=timer.elapsed().as_nanos();
            drop(traces);
            let timer=Instant::now();let bytes=bincode::serde::encode_to_vec(&proof,bincode::config::standard()).unwrap();
            let serialization_ns=timer.elapsed().as_nanos();let complete_ns=complete.elapsed().as_nanos();
            let proof_bytes=bytes.len();let proof_sha256=format!("{:x}",Sha256::digest(&bytes));drop(proof);
            let timer=Instant::now();let (proof,used):($ty,_)=bincode::serde::decode_from_slice(&bytes,bincode::config::standard()).unwrap();
            assert_eq!(used,proof_bytes);let deserialize_ns=timer.elapsed().as_nanos();drop(bytes);
            let timer=Instant::now();($verify)(&proof);let verify_ns=timer.elapsed().as_nanos();
            let (root_counts,outer):(Vec<usize>,(usize,usize))=($inventory)(&proof);
            let total:usize=root_counts.iter().sum::<usize>()+outer.0+outer.1;
            let outer_metadata=if comparisons {format!(",\"blind_rotation_reciprocals\":{},\"key_switch_reciprocals\":{}",outer.0,outer.1)} else {String::new()};
            println!("HB_BATCH_ROOTS {{\"scope\":\"verified-proof-root-slots\",\"proof_sha256\":\"{proof_sha256}\",\"batch_size\":{count},\"total\":{total},\"per_member\":{root_counts:?},\"trusted_key_roots_included\":false,\"whole_proof_security_certified\":false{outer_metadata}}}");
            (prove_ns,serialization_ns,complete_ns,proof_bytes,proof_sha256,deserialize_ns,verify_ns)
        }};}
        let mut statistics=pbs::batch::shared::Statistics::default();
        let (prove_ns,serialization_ns,complete_ns,proof_bytes,proof_sha256,deserialize_ns,verify_ns)=if separate {
            certificate!((0..count).map(|i|pbs::prove_deferred_with_statistics::<F,EF,Sha256,_>(&pp,&setup,&statements[i],&traces[i],&mut statistics.members).unwrap()).collect::<Vec<_>>(),
                Vec<pbs::DeferredProof<F,EF,[u8;32]>>,
                |proof:&Vec<pbs::DeferredProof<F,EF,[u8;32]>>| {assert_eq!(proof.len(),count);for i in 0..count {
                    pbs::verify_deferred::<F,EF,Sha256,_>(&pp,&verifier,&statements[i],&proof[i]).unwrap();
                }},|proof:&Vec<pbs::DeferredProof<F,EF,[u8;32]>>|(proof.iter().map(|m|snarks::packed_root_inventory::inventory(m).total()).collect::<Vec<_>>(),(0,0)))
        } else if comparisons {
            certificate!(pbs::batch::shared::prove_with_statistics::<F,EF,Sha256,_>(&pp,&setup,&statements,&traces.iter().collect::<Vec<_>>(),&mut statistics).unwrap(),
                pbs::batch::shared::Proof<F,EF,[u8;32]>,
                |proof|pbs::batch::shared::verify::<F,EF,Sha256,_>(&pp,&verifier,&statements,proof).unwrap(),
                |proof:&pbs::batch::shared::Proof<F,EF,[u8;32]>| {
                    let inventory=snarks::packed_root_inventory::comparison_batch_inventory(proof);
                    (inventory.members.iter().map(|m|m.total()).collect::<Vec<_>>(),
                        (inventory.blind_rotation_reciprocals,inventory.key_switch_reciprocals))
                })
        } else if canonical {
            certificate!(pbs::batch::canonical::prove::<F,EF,Sha256,_>(&pp,&setup,&statements,&traces.iter().collect::<Vec<_>>()).unwrap(),
                pbs::batch::canonical::Proof<F,EF,[u8;32]>,
                |proof|pbs::batch::canonical::verify::<F,EF,Sha256,_>(&pp,&verifier,&statements,proof).unwrap(),
                |proof:&pbs::batch::canonical::Proof<F,EF,[u8;32]>|(proof.members.iter().map(|m|snarks::packed_root_inventory::inventory(m).total()).collect::<Vec<_>>(),(0,0)))
        } else {
            certificate!(pbs::batch::prove::<F,EF,Sha256,_>(&pp,&setup,&statements,&traces.iter().collect::<Vec<_>>()).unwrap(),
                pbs::batch::Proof<F,EF,[u8;32]>,
                |proof|pbs::batch::verify::<F,EF,Sha256,_>(&pp,&verifier,&statements,proof).unwrap(),
                |proof:&pbs::batch::Proof<F,EF,[u8;32]>|(proof.members.iter().map(|m|snarks::packed_root_inventory::inventory(m).total()).collect::<Vec<_>>(),(0,0)))
        };
        let protocol_version=if comparisons {9} else if separate {5} else if canonical {7} else {6};
        if comparisons || separate {emit_statistics(protocol_version,count,&proof_sha256,prove_ns,&statistics);}
        let mode=if comparisons {"joint-comparisons"} else if separate {"separate-v5"} else if canonical {"canonical-sources"} else {"joint-hadamard"};
        let transcript=if comparisons {pbs::batch::shared::TRANSCRIPT_ID} else if separate {pbs::DEFERRED_TRANSCRIPT_ID} else if canonical {pbs::batch::canonical::TRANSCRIPT_ID} else {pbs::batch::TRANSCRIPT_ID};
        let group_metadata=if comparisons {format!(",\"comparison_group_size\":4,\"blind_rotation_groups\":{},\"key_switch_groups\":{}",(2*count).div_ceil(4),count.div_ceil(4))} else {String::new()};
        let iteration_metadata=if repeated {format!(",\"timing_iteration\":{iteration}")} else {String::new()};
        let scope=if separate {"complete-serialized-independent-public-verifiers"} else {"complete-serialized-public-batch-verifier"};
        println!("HB_FULL_BATCH_PBS {{\"kind\":\"complete-binary-nand-pbs-batch\",\"field\":\"{FIELD}\",\"mode\":\"{mode}\",\"protocol_version\":{protocol_version},\"transcript\":\"{transcript}\",\"batch_size\":{count},\"full_parameters\":{full},\"verification_scope\":\"{scope}\",\"verified\":true,\"seed\":42,\"prime\":{},\"width\":{width},\"lookup_field_degree\":{},\"helper_left_extra\":{helper_left_extra},\"polynomial_size\":{},\"input_dimension\":{},\"output_dimension\":{},\"basis_bits\":{},\"key_switch_basis_bits\":{},\"lookup_repetitions\":1,\"setup_ns\":{setup_ns},\"trace_ns\":{trace_ns},\"prove_ns\":{prove_ns},\"serialization_ns\":{serialization_ns},\"complete_ns\":{complete_ns},\"deserialize_ns\":{deserialize_ns},\"verify_ns\":{verify_ns},\"proof_bytes\":{proof_bytes},\"proof_sha256\":\"{proof_sha256}\",\"statements_sha256\":\"{statements_sha256}\",\"fhe_parameters_sha256\":\"{fhe_parameters_sha256}\",\"native_keys_sha256\":\"{native_keys_sha256}\",\"whole_proof_security_certified\":false{group_metadata}{iteration_metadata}}}",
            F::MODULUS_VALUE,EF::D,params.ring_dimension(),params.lwe_dimension(),params.lwe_dimension(),params.blind_rotation_basis().bits(),params.key_switching_basis_bits());
        for (index,((_,_,left,right),digest)) in inputs.iter().zip(&member_digests).enumerate() {
            println!("HB_BATCH_MEMBER {{\"batch_size\":{count},\"index\":{index},\"left_plaintext\":{left},\"right_plaintext\":{right},\"decrypted_plaintext\":{},\"statement_sha256\":\"{digest}\",\"proof_sha256\":\"{proof_sha256}\",\"verified\":true}}",1-left*right);
        }
    }
}
