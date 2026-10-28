import unittest
from fractions import Fraction
from full_pbs_budget import full_bounds,from_log
from packed_budget import BABYBEAR

class FullInventoryTests(unittest.TestCase):
    def fixture(self):
        record=dict(kind="complete-binary-nand-pbs",prime=BABYBEAR,width=8,polynomial_size=1024,
                    input_dimension=728,output_dimension=728,basis_bits=8,key_switch_basis_bits=5,
                    lookup_repetitions=16,private_coefficient_roots=9,ntt_links=9)
        layouts={}
        for role,n,left,message,length in [("source",18,3,4096,8192),("helper",21,5,8192,16384),
                                           ("final_source",8,1,16,32),("final_helper",11,4,16,32)]:
            layouts[role]=dict(role=role,row_code="block-rs",prime=BABYBEAR,width=8,variables=n,left_vars=left,
                               row_message_scalars=1<<(n-left),row_message_blocks=message,
                               row_encoded_blocks=length,block_width=8,queries=544)
        return record,layouts
    def test_all_stages_are_included_with_actual_private_ntt_inventory(self):
        record,layouts=self.fixture();errors=full_bounds(record,layouts)
        self.assertEqual({key.split("_")[0] for key in errors},{"hadamard","private","decomposition","accumulator","monomial","key"})
        self.assertEqual(errors["private_ntt_row_identity"],9*Fraction(11,BABYBEAR)**8)
        self.assertEqual(errors["private_ntt_random_linear_test"],18*Fraction(8192,BABYBEAR)**8)
        self.assertEqual(errors["key_switch_ntt_row_identity"],8*Fraction(1,BABYBEAR)**8)
        self.assertLess(sum(errors.values()),Fraction(1,2**128))
    def test_protocol_metadata_is_explicit_for_direct_sampling(self):
        record,layouts=self.fixture()
        legacy=full_bounds(record,layouts)
        direct=dict(record,protocol_version=2,transcript="merlin-direct-canonical-rejection-v1")
        self.assertEqual(full_bounds(direct,layouts),legacy)
        for change in [dict(protocol_version=2),dict(protocol_version=1,transcript="merlin-direct-canonical-rejection-v1"),dict(protocol_version=3,transcript="unknown")]:
            with self.assertRaises(ValueError):full_bounds(dict(record,**change),layouts)

    def test_aggregated_hadamard_adds_full_field_cancellation(self):
        record,layouts=self.fixture()
        record.update(protocol_version=3,transcript="merlin-direct-prime-parent-extension-child-v1",
                      lookup_backend="extension",lookup_field_degree=6,lookup_repetitions=1)
        old=full_bounds(record,layouts)
        aggregate=dict(record,protocol_version=4,transcript="merlin-direct-extension-comparisons-aggregated-hadamard-v1",hadamard_backend="multi-root")
        new=full_bounds(aggregate,layouts)
        term=new.pop("hadamard_aggregation_cancellation")
        self.assertEqual(new,old)
        self.assertEqual(term,Fraction(1,BABYBEAR**6))
        with self.assertRaises(ValueError):full_bounds(dict(aggregate,hadamard_backend="independent"),layouts)
        alternate={k:dict(v) for k,v in layouts.items()}
        alternate["source"].update(block_width=4,row_message_blocks=8192,row_encoded_blocks=16384)
        full_bounds(record,alternate)
        with self.assertRaises(ValueError):full_bounds(aggregate,alternate)

    def test_deferred_sources_keep_conservative_per_limb_inventory(self):
        record,layouts=self.fixture()
        record.update(protocol_version=4,transcript="merlin-direct-extension-comparisons-aggregated-hadamard-v1",
                      lookup_backend="extension",lookup_field_degree=6,lookup_repetitions=1,hadamard_backend="multi-root")
        old=full_bounds(record,layouts)
        deferred=dict(record,protocol_version=5,lookup_backend="deferred-extension",
                      transcript="merlin-direct-aggregated-hadamard-deferred-lookup-sources-v1")
        self.assertEqual(full_bounds(deferred,layouts),old)
        for change in [dict(lookup_backend="extension"),dict(hadamard_backend="independent"),dict(protocol_version=4),dict(transcript=record["transcript"])]:
            with self.assertRaises(ValueError):full_bounds(dict(deferred,**change),layouts)
        padded={k:dict(v) for k,v in layouts.items()}
        padded["final_source"].update(block_width=32,row_message_blocks=4,row_encoded_blocks=8)
        # Existing physical padded row geometry is supported by component
        # bounds, but excluded from this deferred fixed-word inventory.
        full_bounds(record,padded)
        with self.assertRaises(ValueError):full_bounds(deferred,padded)

    def test_shared_queries_retain_old_terms_and_count_six_field_cancellations(self):
        record,layouts=self.fixture()
        record.update(protocol_version=5,transcript="merlin-direct-aggregated-hadamard-deferred-lookup-sources-v1",
            lookup_backend="deferred-extension",lookup_field_degree=6,lookup_repetitions=1,hadamard_backend="multi-root")
        old=full_bounds(record,layouts)
        shared=dict(record,protocol_version=8,transcript="merlin-direct-shared-query-comparisons-v1",lookup_backend="shared-extension")
        new=full_bounds(shared,layouts)
        self.assertEqual(new.pop("shared_lookup_aggregation_cancellation"),Fraction(6,BABYBEAR**6))
        self.assertEqual(new,old)
        with self.assertRaises(ValueError):full_bounds(dict(shared,lookup_backend="deferred-extension"),layouts)
        padded={k:dict(v) for k,v in layouts.items()}
        padded["helper"].update(block_width=16,row_message_blocks=4096,row_encoded_blocks=8192)
        full_bounds(record,padded)
        with self.assertRaises(ValueError):full_bounds(shared,padded)

    def test_invalid_inventory_or_layout_is_rejected(self):
        record,layouts=self.fixture()
        for change in [dict(ntt_links=8),dict(private_coefficient_roots=17),dict(output_dimension=1024),dict(polynomial_size=2048)]:
            with self.assertRaises(ValueError):full_bounds(dict(record,**change),layouts)
        for role,change in [("source",dict(variables=17)),("helper",dict(row_message_scalars=1)),("final_source",dict(prime=17)),("final_helper",dict(row_code="other"))]:
            altered={k:dict(v) for k,v in layouts.items()};altered[role].update(change)
            with self.assertRaises(ValueError):full_bounds(record,altered)
        with self.assertRaises(ValueError):full_bounds(record,{k:v for k,v in layouts.items() if k!="helper"})
    def test_queries_are_not_counted_as_independent_shared_responses(self):
        record,layouts=self.fixture();errors=full_bounds(record,layouts)
        gap=Fraction(8192-4096+1,3*8192)
        self.assertEqual(errors["private_ntt_proximity"],36*(1-gap)**544)
        self.assertEqual(errors["accumulator_proximity"],14*(1-gap)**544)
        with self.assertRaises(ValueError):from_log("no complete record")

    def test_extension_inventory_uses_full_field_and_base_pcs_domains(self):
        record,layouts=self.fixture()
        record.update(protocol_version=3,transcript="merlin-direct-prime-parent-extension-child-v1",
                      lookup_backend="extension",lookup_field_degree=5,lookup_repetitions=1)
        errors=full_bounds(record,layouts)
        p=BABYBEAR;q=p**5
        pair=Fraction(1024,q)+Fraction(2**21+511,q-513)
        self.assertEqual(errors["decomposition_rational_identity"],8*pair)
        self.assertEqual(errors["decomposition_sumcheck"],Fraction(8*21,q))
        self.assertEqual(errors["decomposition_identity_equality_reduction"],Fraction(8*21,q))
        self.assertEqual(errors["decomposition_identity_sumcheck"],Fraction(8*3*21,q))
        self.assertEqual(errors["decomposition_helper_random_linear_test"],8*Fraction(16384,p)**8)
        self.assertEqual(errors["decomposition_source_random_linear_test"],24*Fraction(8192,p)**8)
        self.assertEqual(errors["key_switch_decomposition_sumcheck"],Fraction(7*11,q))
        self.assertLess(sum(errors.values()),Fraction(1,2**128))
        # Only independently sampled GF pairs exponentiate the rational error.
        record["lookup_repetitions"]=2
        twice=full_bounds(record,layouts)
        self.assertEqual(twice["decomposition_rational_identity"],8*pair**2)
        self.assertEqual(twice["decomposition_identity_sumcheck"],2*errors["decomposition_identity_sumcheck"])
        self.assertEqual(twice["decomposition_source_random_linear_test"],errors["decomposition_source_random_linear_test"])

    def test_extension_configuration_is_explicit_and_checked(self):
        record,layouts=self.fixture()
        record.update(protocol_version=3,transcript="merlin-direct-prime-parent-extension-child-v1",
                      lookup_backend="extension",lookup_field_degree=5,lookup_repetitions=1)
        for change in [dict(lookup_backend="lanes"),dict(lookup_field_degree=None),
                       dict(lookup_field_degree=3),dict(lookup_field_degree=16),
                       dict(lookup_field_degree=True),dict(lookup_field_degree=5.0)]:
            with self.assertRaises(ValueError): full_bounds(dict(record,**change),layouts)

    def test_goldilocks_cubic_width_four_inventory(self):
        p=2**64-2**32+1
        record=dict(kind="complete-binary-nand-pbs",prime=p,width=4,polynomial_size=1024,
            input_dimension=728,output_dimension=728,basis_bits=8,key_switch_basis_bits=5,
            lookup_repetitions=1,private_coefficient_roots=17,ntt_links=17,
            protocol_version=3,transcript="merlin-direct-prime-parent-extension-child-v1",
            lookup_backend="extension",lookup_field_degree=3)
        layouts={}
        for role,n,left in [("source",19,4),("helper",21,6),("final_source",9,3),("final_helper",11,5)]:
            scalars=1<<(n-left);blocks=scalars//4
            layouts[role]=dict(role=role,row_code="block-rs",prime=p,width=4,variables=n,left_vars=left,
                row_message_scalars=scalars,row_message_blocks=blocks,row_encoded_blocks=2*blocks,block_width=4,queries=544)
        errors=full_bounds(record,layouts)
        self.assertEqual(errors["decomposition_sumcheck"],Fraction(16*21,p**3))
        self.assertLess(sum(errors.values()),Fraction(1,2**128))
        for degree in [0,1,6,True,3.0]:
            with self.assertRaises(ValueError):full_bounds(dict(record,lookup_field_degree=degree),layouts)

    def test_extension_characteristic_and_partial_mask_remain_distinct(self):
        from packed_budget import extension_decomposition_component_bounds
        p=BABYBEAR
        component=dict(prime=p,width=8,degree=4,variables=1,factors=1,
            row_message_scalars=2,row_message_blocks=1,row_encoded_blocks=2,block_width=8,queries=32,
            helper_variables=4,helper_row_message_scalars=16,helper_row_message_blocks=2,
            helper_row_encoded_blocks=4,helper_block_width=8,helper_queries=32,
            logical_len=7,public_table_len=4,excluded_challenges=5,tuple_columns=3,
            linear_checks=1,linear_sources=4,repetitions=1,lookup_field_degree=5)
        errors=extension_decomposition_component_bounds(component)
        self.assertEqual(errors["identity_sumcheck"],Fraction(16,p**5))
        self.assertEqual(errors["rational_identity"],Fraction(8,p**5)+Fraction(10,p**5-5))
        with self.assertRaises(ValueError):extension_decomposition_component_bounds(dict(component,degree=3))
        # A large extension cardinality does not prevent characteristic-p cancellation.
        large=dict(component,variables=28,helper_variables=31,logical_len=p-3)
        with self.assertRaises(ValueError):extension_decomposition_component_bounds(large)
