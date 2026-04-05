use very_simple_rest::rest_api_from_eon;

rest_api_from_eon!("tests/fixtures/not_exists_policy_api.eon");

#[test]
fn grouped_not_exists_policies_generate_compilable_code() {}
