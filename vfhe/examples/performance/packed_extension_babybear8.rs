type F = algebra::BabyBear;
type EF = algebra::BabyBearExtension8;
use vfhe::bfhe::BABYBEAR_BINARY_128_BITS_PARAMETERS as PARAMETERS;
const FIELD: &str = "babybear";
include!("packed_extension_pbs.rs.inc");
