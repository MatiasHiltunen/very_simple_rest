//! Exercise the exact build-time compiler with valid and unsafe EON variants.
#[allow(dead_code)] // Reuse the build entrypoint without executing its filesystem output.
#[path = "../build.rs"]
mod compilation;

const SOURCE: &str = include_str!("../api.eon");

#[test]
fn eon_changes_really_control_routes_roles_and_database_schema() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("changed.eon");
    let changed = SOURCE
        .replace("\"Project\"", "\"Programme\"")
        .replace("project.id", "programme.id")
        .replace("create: \"editor\"", "create: \"approver\"");
    std::fs::write(&path, changed).unwrap();
    let (contract, schema) = compilation::compile(&path).unwrap();
    let resource = contract
        .resources
        .iter()
        .find(|r| r.name == "Programme")
        .unwrap();
    assert_eq!(resource.table, "programme");
    assert_eq!(resource.create.role, "approver");
    assert!(schema.contains("CREATE TABLE programme"));
    assert!(!schema.contains("CREATE TABLE project"));
}

#[test]
fn unsafe_or_unsupported_configuration_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invalid.eon");
    let cases = [
        SOURCE.replace("admin_bypass: false", "admin_bypass: true"),
        SOURCE.replace("default_read: Authenticated", "default_read: Public"),
        SOURCE.replace("read: \"reader\"", "read: \"\""),
        SOURCE.replace("equals: \"claim.tenant_id\"", "equals: \"user.id\""),
        SOURCE.replace("value: \"claim.tenant_id\"", "value: \"user.id\""),
        SOURCE.replace("db: \"Sqlite\"", "db: \"Postgres\""),
        SOURCE.replace("on_delete: Restrict", "on_delete: Cascade"),
        SOURCE.replace(
            "security: {",
            "security: {\n unknown_security_feature: true",
        ),
        SOURCE.replace(
            "name: \"name\", type: \"String\"",
            "name: \"name\", type: \"String\", garde: { length: { max: 10 } }",
        ),
    ];
    for (index, source) in cases.into_iter().enumerate() {
        assert_ne!(source, SOURCE, "mutation must modify the fixture");
        std::fs::write(&path, source).unwrap();
        assert!(
            compilation::compile(&path).is_err(),
            "unsafe variant {index}"
        );
    }
}
