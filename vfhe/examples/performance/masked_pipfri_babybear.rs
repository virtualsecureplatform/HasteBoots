type FF = algebra::BabyBear;
type EF = algebra::BabyBearExtension5;
use vfhe::bfhe::BABYBEAR_BINARY_128_BITS_PARAMETERS as PARAMETERS;
const FIELD: &str = "babybear-ext5";
include!("masked_pipfri_pbs.rs.inc");
