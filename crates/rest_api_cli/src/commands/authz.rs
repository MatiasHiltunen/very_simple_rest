use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result, bail};
use colored::Colorize;
use rest_macro_core::{
    authorization::{
        ActionAuthorization, AuthorizationAction, AuthorizationAssignment,
        AuthorizationAssignmentTrace, AuthorizationCondition, AuthorizationConditionTrace,
        AuthorizationContract, AuthorizationExistsCondition, AuthorizationExistsConditionTrace,
        AuthorizationHybridSource, AuthorizationLiteralValue, AuthorizationMatch,
        AuthorizationModel, AuthorizationOperator, AuthorizationOutcome, AuthorizationRuntime,
        AuthorizationRuntimeAccessResult, AuthorizationScopeBinding, AuthorizationScopedAssignment,
        AuthorizationScopedAssignmentCreateInput, AuthorizationScopedAssignmentEventKind,
        AuthorizationScopedAssignmentEventRecord, AuthorizationScopedAssignmentRecord,
        AuthorizationScopedAssignmentTarget, AuthorizationScopedAssignmentTrace,
        AuthorizationSimulationInput, AuthorizationSimulationResult, AuthorizationValueSource,
        ResourceAuthorization,
        delete_runtime_assignment_with_audit as delete_stored_runtime_assignment_with_audit,
        list_runtime_assignment_events_for_user, list_runtime_assignments_for_user,
        load_runtime_assignments_for_user,
        renew_runtime_assignment_with_audit as renew_stored_runtime_assignment_with_audit,
        revoke_runtime_assignment_with_audit as revoke_stored_runtime_assignment_with_audit,
    },
    compiler,
};
use serde_json::Value;

use super::db::connect_database;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(serde::Serialize)]
struct RuntimeAssignmentDeleteResult {
    id: String,
    deleted: bool,
}

pub fn explain_authorization(
    input: &Path,
    output: Option<&Path>,
    format: OutputFormat,
    force: bool,
) -> Result<()> {
    let service = compiler::load_service_from_path(input)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .with_context(|| format!("failed to load service definition from {}", input.display()))?;
    let rendered = render_authorization_explanation(&service, format)?;

    if let Some(output) = output {
        if output.exists() && !force {
            anyhow::bail!(
                "authorization explanation already exists at {} (use --force to overwrite)",
                output.display()
            );
        }
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(output, rendered).with_context(|| {
            format!(
                "failed to write authorization explanation to {}",
                output.display()
            )
        })?;
        println!(
            "{} {}",
            "Generated authorization explanation:".green().bold(),
            output.display()
        );
    } else {
        print!("{rendered}");
        if !rendered.ends_with('\n') {
            println!();
        }
    }

    Ok(())
}

pub fn render_authorization_explanation(
    service: &compiler::ServiceSpec,
    format: OutputFormat,
) -> Result<String> {
    let model = compiler::compile_service_authorization(service);
    match format {
        OutputFormat::Text => Ok(render_text_explanation(service, &model)),
        OutputFormat::Json => serde_json::to_string_pretty(&model)
            .context("failed to serialize authorization model to JSON"),
    }
}

pub async fn simulate_authorization(
    input: &Path,
    resource_name: Option<&str>,
    action: AuthorizationAction,
    user_id: Option<i64>,
    roles: &[String],
    claims: &[String],
    row: &[String],
    related_rows: &[String],
    proposed: &[String],
    scope: Option<&str>,
    hybrid_source: Option<rest_macro_core::authorization::AuthorizationHybridSource>,
    scoped_assignments: &[String],
    load_runtime_assignments: bool,
    database_url: Option<&str>,
    config_path: Option<&Path>,
    output: Option<&Path>,
    format: OutputFormat,
    force: bool,
) -> Result<()> {
    let mut runtime_assignments = parse_scoped_assignments(scoped_assignments)?;
    if load_runtime_assignments {
        let database_url = database_url
            .ok_or_else(|| anyhow::anyhow!("runtime assignment loading requires a database url"))?;
        let user_id = user_id
            .ok_or_else(|| anyhow::anyhow!("--load-runtime-assignments requires --user-id"))?;
        let pool = connect_database(database_url, config_path)
            .await
            .context("failed to connect database for runtime authorization assignments")?;
        let mut stored = load_runtime_assignments_for_user(&pool, user_id)
            .await
            .map_err(anyhow::Error::msg)?;
        runtime_assignments.append(&mut stored);
    }

    let service = compiler::load_service_from_path(input)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .with_context(|| format!("failed to load service definition from {}", input.display()))?;
    let rendered = render_authorization_simulation(
        &service,
        resource_name,
        AuthorizationSimulationInput {
            action,
            user_id,
            roles: roles.to_vec(),
            claims: parse_key_value_values(claims, "claim")?,
            row: parse_key_value_values(row, "row")?,
            related_rows: parse_related_rows(related_rows)?,
            proposed: parse_key_value_values(proposed, "proposed")?,
            scope: scope.map(parse_scope_binding).transpose()?,
            hybrid_source,
            scoped_assignments: runtime_assignments,
        }
        .normalized(),
        format,
    )?;

    if let Some(output) = output {
        if output.exists() && !force {
            anyhow::bail!(
                "authorization simulation already exists at {} (use --force to overwrite)",
                output.display()
            );
        }
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(output, rendered).with_context(|| {
            format!(
                "failed to write authorization simulation to {}",
                output.display()
            )
        })?;
        println!(
            "{} {}",
            "Generated authorization simulation:".green().bold(),
            output.display()
        );
    } else {
        print!("{rendered}");
        if !rendered.ends_with('\n') {
            println!();
        }
    }

    Ok(())
}

pub async fn list_runtime_assignments(
    user_id: i64,
    database_url: &str,
    config_path: Option<&Path>,
    output: Option<&Path>,
    format: OutputFormat,
    force: bool,
) -> Result<()> {
    let pool = connect_database(database_url, config_path)
        .await
        .context("failed to connect database for runtime authorization assignments")?;
    let assignments = list_runtime_assignments_for_user(&pool, user_id)
        .await
        .map_err(anyhow::Error::msg)?;
    let rendered = render_runtime_assignments(&assignments, format)?;
    write_output(rendered, output, force, "runtime authorization assignments")
}

pub async fn list_runtime_assignment_history(
    user_id: i64,
    database_url: &str,
    config_path: Option<&Path>,
    output: Option<&Path>,
    format: OutputFormat,
    force: bool,
) -> Result<()> {
    let pool = connect_database(database_url, config_path)
        .await
        .context("failed to connect database for runtime authorization assignment history")?;
    let events = list_runtime_assignment_events_for_user(&pool, user_id)
        .await
        .map_err(anyhow::Error::msg)?;
    let rendered = render_runtime_assignment_history(&events, format)?;
    write_output(
        rendered,
        output,
        force,
        "runtime authorization assignment history",
    )
}

pub async fn create_runtime_assignment(
    input: &Path,
    user_id: i64,
    assignment: &str,
    expires_at: Option<&str>,
    created_by_user_id: Option<i64>,
    database_url: &str,
    config_path: Option<&Path>,
    output: Option<&Path>,
    format: OutputFormat,
    force: bool,
) -> Result<()> {
    let runtime = load_authorization_runtime(input, database_url, config_path).await?;
    let scoped_assignment = parse_scoped_assignment(assignment, "runtime.assignment.cli")?;
    let created = runtime
        .create_assignment(
            AuthorizationScopedAssignmentCreateInput {
                user_id,
                target: scoped_assignment.target,
                scope: scoped_assignment.scope,
                expires_at: expires_at.map(str::to_owned),
            }
            .into_record(created_by_user_id)
            .map_err(anyhow::Error::msg)?,
        )
        .await
        .map_err(anyhow::Error::msg)?;
    let rendered = render_runtime_assignment_record(&created, format)?;
    write_output(rendered, output, force, "runtime authorization assignment")
}

pub async fn delete_runtime_assignment(
    assignment_id: &str,
    actor_user_id: Option<i64>,
    reason: Option<&str>,
    database_url: &str,
    config_path: Option<&Path>,
    output: Option<&Path>,
    format: OutputFormat,
    force: bool,
) -> Result<()> {
    let pool = connect_database(database_url, config_path)
        .await
        .context("failed to connect database for runtime authorization assignments")?;
    let deleted = delete_stored_runtime_assignment_with_audit(
        &pool,
        assignment_id,
        actor_user_id,
        reason.map(str::to_owned),
    )
    .await
    .map_err(anyhow::Error::msg)?;
    let rendered = render_runtime_assignment_delete_result(
        &RuntimeAssignmentDeleteResult {
            id: assignment_id.to_owned(),
            deleted,
        },
        format,
    )?;
    write_output(
        rendered,
        output,
        force,
        "runtime authorization delete result",
    )
}

pub async fn revoke_runtime_assignment(
    assignment_id: &str,
    actor_user_id: Option<i64>,
    reason: Option<&str>,
    database_url: &str,
    config_path: Option<&Path>,
    output: Option<&Path>,
    format: OutputFormat,
    force: bool,
) -> Result<()> {
    let pool = connect_database(database_url, config_path)
        .await
        .context("failed to connect database for runtime authorization assignments")?;
    let revoked = revoke_stored_runtime_assignment_with_audit(
        &pool,
        assignment_id,
        actor_user_id,
        reason.map(str::to_owned),
    )
    .await
    .map_err(anyhow::Error::msg)?
    .ok_or_else(|| {
        anyhow::anyhow!("runtime authorization assignment `{assignment_id}` not found")
    })?;
    let rendered = render_runtime_assignment_record(&revoked, format)?;
    write_output(
        rendered,
        output,
        force,
        "runtime authorization assignment revocation",
    )
}

pub async fn renew_runtime_assignment(
    assignment_id: &str,
    expires_at: &str,
    actor_user_id: Option<i64>,
    reason: Option<&str>,
    database_url: &str,
    config_path: Option<&Path>,
    output: Option<&Path>,
    format: OutputFormat,
    force: bool,
) -> Result<()> {
    let pool = connect_database(database_url, config_path)
        .await
        .context("failed to connect database for runtime authorization assignments")?;
    let renewed = renew_stored_runtime_assignment_with_audit(
        &pool,
        assignment_id,
        expires_at,
        actor_user_id,
        reason.map(str::to_owned),
    )
    .await
    .map_err(anyhow::Error::msg)?
    .ok_or_else(|| {
        anyhow::anyhow!("runtime authorization assignment `{assignment_id}` not found")
    })?;
    let rendered = render_runtime_assignment_record(&renewed, format)?;
    write_output(
        rendered,
        output,
        force,
        "runtime authorization assignment renewal",
    )
}

pub async fn evaluate_runtime_access(
    input: &Path,
    resource: &str,
    action: AuthorizationAction,
    user_id: i64,
    scope: &str,
    database_url: &str,
    config_path: Option<&Path>,
    output: Option<&Path>,
    format: OutputFormat,
    force: bool,
) -> Result<()> {
    let runtime = load_authorization_runtime(input, database_url, config_path).await?;
    let result = runtime
        .evaluate_runtime_access_for_user(user_id, resource, action, parse_scope_binding(scope)?)
        .await
        .map_err(anyhow::Error::msg)?;
    let rendered = render_runtime_access_result(&result, format)?;
    write_output(rendered, output, force, "runtime authorization evaluation")
}

async fn load_authorization_runtime(
    input: &Path,
    database_url: &str,
    config_path: Option<&Path>,
) -> Result<AuthorizationRuntime> {
    let service = compiler::load_service_from_path(input)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .with_context(|| format!("failed to load service definition from {}", input.display()))?;
    let pool = connect_database(database_url, config_path)
        .await
        .context("failed to connect database for runtime authorization assignments")?;
    Ok(AuthorizationRuntime::new(
        compiler::compile_service_authorization(&service),
        pool,
    ))
}

fn write_output(rendered: String, output: Option<&Path>, force: bool, label: &str) -> Result<()> {
    if let Some(output) = output {
        if output.exists() && !force {
            bail!(
                "{label} output already exists at {} (use --force to overwrite)",
                output.display()
            );
        }
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(output, rendered)
            .with_context(|| format!("failed to write {label} to {}", output.display()))?;
        println!("{} {}", "Generated".green().bold(), output.display());
    } else {
        print!("{rendered}");
        if !rendered.ends_with('\n') {
            println!();
        }
    }
    Ok(())
}

pub fn render_authorization_simulation(
    service: &compiler::ServiceSpec,
    resource_name: Option<&str>,
    simulation_input: AuthorizationSimulationInput,
    format: OutputFormat,
) -> Result<String> {
    let model = compiler::compile_service_authorization(service);
    let result = model
        .simulate_resource_action(resource_name, &simulation_input)
        .map_err(anyhow::Error::msg)?;

    match format {
        OutputFormat::Text => Ok(render_text_simulation(service, &result)),
        OutputFormat::Json => serde_json::to_string_pretty(&result)
            .context("failed to serialize authorization simulation to JSON"),
    }
}

pub fn render_runtime_assignments(
    assignments: &[AuthorizationScopedAssignmentRecord],
    format: OutputFormat,
) -> Result<String> {
    match format {
        OutputFormat::Text => Ok(render_text_runtime_assignments(assignments)),
        OutputFormat::Json => serde_json::to_string_pretty(assignments)
            .context("failed to serialize runtime authorization assignments to JSON"),
    }
}

pub fn render_runtime_assignment_history(
    events: &[AuthorizationScopedAssignmentEventRecord],
    format: OutputFormat,
) -> Result<String> {
    match format {
        OutputFormat::Text => Ok(render_text_runtime_assignment_history(events)),
        OutputFormat::Json => serde_json::to_string_pretty(events)
            .context("failed to serialize runtime authorization assignment history to JSON"),
    }
}

pub fn render_runtime_assignment_record(
    assignment: &AuthorizationScopedAssignmentRecord,
    format: OutputFormat,
) -> Result<String> {
    match format {
        OutputFormat::Text => Ok(render_text_runtime_assignment_record(assignment)),
        OutputFormat::Json => serde_json::to_string_pretty(assignment)
            .context("failed to serialize runtime authorization assignment to JSON"),
    }
}

fn render_runtime_assignment_delete_result(
    result: &RuntimeAssignmentDeleteResult,
    format: OutputFormat,
) -> Result<String> {
    match format {
        OutputFormat::Text => Ok(render_text_runtime_assignment_delete_result(result)),
        OutputFormat::Json => serde_json::to_string_pretty(result)
            .context("failed to serialize runtime authorization delete result to JSON"),
    }
}

pub fn render_runtime_access_result(
    result: &AuthorizationRuntimeAccessResult,
    format: OutputFormat,
) -> Result<String> {
    match format {
        OutputFormat::Text => Ok(render_text_runtime_access_result(result)),
        OutputFormat::Json => serde_json::to_string_pretty(result)
            .context("failed to serialize runtime authorization access result to JSON"),
    }
}

fn render_text_explanation(service: &compiler::ServiceSpec, model: &AuthorizationModel) -> String {
    let mut output = String::new();
    output.push_str("Authorization explanation\n");
    output.push_str(&format!("module: {}\n", service.module_ident));
    output.push_str(&format!("resources: {}\n", model.resources.len()));
    if !model.contract.is_empty() {
        render_contract_text(&mut output, &model.contract);
    }

    for resource in &model.resources {
        output.push('\n');
        render_resource_text(&mut output, resource);
    }

    output
}

fn render_text_runtime_assignments(assignments: &[AuthorizationScopedAssignmentRecord]) -> String {
    let mut output = String::new();
    output.push_str("Runtime authorization assignments\n");
    output.push_str(&format!("count: {}\n", assignments.len()));
    if assignments.is_empty() {
        output.push_str("assignments: none\n");
        return output;
    }

    output.push_str("assignments:\n");
    for assignment in assignments {
        output.push_str(&format!(
            "  - {}\n",
            render_runtime_assignment_record_line(assignment)
        ));
    }
    output
}

fn render_text_runtime_assignment_history(
    events: &[AuthorizationScopedAssignmentEventRecord],
) -> String {
    let mut output = String::new();
    output.push_str("Runtime authorization assignment history\n");
    output.push_str(&format!("count: {}\n", events.len()));
    if events.is_empty() {
        output.push_str("events: none\n");
        return output;
    }

    output.push_str("events:\n");
    for event in events {
        output.push_str(&format!(
            "  - {}\n",
            render_runtime_assignment_event_line(event)
        ));
    }
    output
}

fn render_text_runtime_assignment_record(
    assignment: &AuthorizationScopedAssignmentRecord,
) -> String {
    let mut output = String::new();
    output.push_str("Runtime authorization assignment\n");
    output.push_str(&format!("id: {}\n", assignment.id));
    output.push_str(&format!("user_id: {}\n", assignment.user_id));
    output.push_str(&format!(
        "target: {}\n",
        render_scoped_assignment_target(&assignment.target)
    ));
    output.push_str(&format!(
        "scope: {}={}\n",
        assignment.scope.scope, assignment.scope.value
    ));
    output.push_str(&format!("created_at: {}\n", assignment.created_at));
    output.push_str(&format!(
        "created_by_user_id: {}\n",
        assignment
            .created_by_user_id
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_owned())
    ));
    output.push_str(&format!(
        "expires_at: {}\n",
        assignment.expires_at.as_deref().unwrap_or("none")
    ));
    output
}

fn render_text_runtime_assignment_delete_result(result: &RuntimeAssignmentDeleteResult) -> String {
    let mut output = String::new();
    output.push_str("Runtime authorization delete result\n");
    output.push_str(&format!("id: {}\n", result.id));
    output.push_str(&format!("deleted: {}\n", result.deleted));
    output
}

fn render_text_runtime_access_result(result: &AuthorizationRuntimeAccessResult) -> String {
    let mut output = String::new();
    output.push_str("Runtime authorization access\n");
    output.push_str(&format!("user_id: {}\n", result.user_id));
    output.push_str(&format!("resource_id: {}\n", result.resource_id));
    output.push_str(&format!("resource: {}\n", result.resource));
    output.push_str(&format!("action_id: {}\n", result.action_id));
    output.push_str(&format!("action: {}\n", action_label(result.action)));
    output.push_str(&format!(
        "scope: {}={}\n",
        result.scope.scope, result.scope.value
    ));
    output.push_str(&format!("allowed: {}\n", result.allowed));

    if result.runtime_assignments.is_empty() {
        output.push_str("runtime_assignments: none\n");
    } else {
        output.push_str("runtime_assignments:\n");
        for assignment in &result.runtime_assignments {
            output.push_str(&format!(
                "  - {}\n",
                render_scoped_assignment_trace(assignment)
            ));
        }
    }

    if result.resolved_permissions.is_empty() {
        output.push_str("resolved_permissions: none\n");
    } else {
        output.push_str(&format!(
            "resolved_permissions: {}\n",
            result.resolved_permissions.join(", ")
        ));
    }

    if result.resolved_templates.is_empty() {
        output.push_str("resolved_templates: none\n");
    } else {
        output.push_str(&format!(
            "resolved_templates: {}\n",
            result.resolved_templates.join(", ")
        ));
    }

    if result.notes.is_empty() {
        output.push_str("notes: none\n");
    } else {
        output.push_str("notes:\n");
        for note in &result.notes {
            output.push_str(&format!("  - {note}\n"));
        }
    }

    output
}

fn render_runtime_assignment_record_line(
    assignment: &AuthorizationScopedAssignmentRecord,
) -> String {
    let mut details = Vec::new();
    details.push(format!("user_id={}", assignment.user_id));
    details.push(format!(
        "target={}",
        render_scoped_assignment_target(&assignment.target)
    ));
    details.push(format!(
        "scope={}={}",
        assignment.scope.scope, assignment.scope.value
    ));
    details.push(format!("created_at={}", assignment.created_at));
    if let Some(created_by_user_id) = assignment.created_by_user_id {
        details.push(format!("created_by_user_id={created_by_user_id}"));
    }
    if let Some(expires_at) = &assignment.expires_at {
        details.push(format!("expires_at={expires_at}"));
    }
    format!("{} [{}]", assignment.id, details.join(", "))
}

fn render_runtime_assignment_event_line(
    event: &AuthorizationScopedAssignmentEventRecord,
) -> String {
    let mut details = Vec::new();
    details.push(format!("assignment_id={}", event.assignment_id));
    details.push(format!("user_id={}", event.user_id));
    details.push(format!(
        "event={}",
        runtime_assignment_event_kind_label(event.event)
    ));
    details.push(format!(
        "target={}",
        render_scoped_assignment_target(&event.target)
    ));
    details.push(format!("scope={}={}", event.scope.scope, event.scope.value));
    details.push(format!("occurred_at={}", event.occurred_at));
    if let Some(actor_user_id) = event.actor_user_id {
        details.push(format!("actor_user_id={actor_user_id}"));
    }
    if let Some(expires_at) = &event.expires_at {
        details.push(format!("expires_at={expires_at}"));
    }
    if let Some(reason) = &event.reason {
        details.push(format!("reason={reason}"));
    }
    format!("{} [{}]", event.id, details.join(", "))
}

fn render_contract_text(output: &mut String, contract: &AuthorizationContract) {
    output.push_str(&format!(
        "\ncontract.management_api: enabled={}, mount={}\n",
        contract.management_api.enabled, contract.management_api.mount
    ));
    output.push_str(&format!("\ncontract.scopes: {}\n", contract.scopes.len()));
    for scope in &contract.scopes {
        output.push_str(&format!("  - {}", scope.name));
        if let Some(parent) = &scope.parent {
            output.push_str(&format!(" (parent: {parent})"));
        }
        if let Some(description) = &scope.description {
            output.push_str(&format!(" - {description}"));
        }
        output.push('\n');
    }

    output.push_str(&format!(
        "contract.permissions: {}\n",
        contract.permissions.len()
    ));
    for permission in &contract.permissions {
        output.push_str(&format!(
            "  - {} [actions={}, resources={}, scopes={}]\n",
            permission.name,
            permission
                .actions
                .iter()
                .map(|action| action_label(*action))
                .collect::<Vec<_>>()
                .join(", "),
            permission.resources.join(", "),
            if permission.scopes.is_empty() {
                "none".to_owned()
            } else {
                permission.scopes.join(", ")
            }
        ));
    }

    output.push_str(&format!(
        "contract.templates: {}\n",
        contract.templates.len()
    ));
    for template in &contract.templates {
        output.push_str(&format!(
            "  - {} [permissions={}, scopes={}]\n",
            template.name,
            template.permissions.join(", "),
            if template.scopes.is_empty() {
                "none".to_owned()
            } else {
                template.scopes.join(", ")
            }
        ));
    }

    output.push_str(&format!(
        "contract.hybrid_enforcement.resources: {}\n",
        contract.hybrid_enforcement.resources.len()
    ));
    for resource in &contract.hybrid_enforcement.resources {
        let sources = resource.scope_sources.labels().join(", ");
        output.push_str(&format!(
            "  - {} [scope={}, scope_field={}, sources={}, actions={}]\n",
            resource.resource,
            resource.scope,
            resource.scope_field,
            if sources.is_empty() { "none" } else { &sources },
            resource
                .actions
                .iter()
                .map(|action| action_label(*action))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
}

fn render_text_simulation(
    service: &compiler::ServiceSpec,
    result: &AuthorizationSimulationResult,
) -> String {
    let mut output = String::new();
    output.push_str("Authorization simulation\n");
    output.push_str(&format!("module: {}\n", service.module_ident));
    output.push_str(&format!("resource_id: {}\n", result.resource_id));
    output.push_str(&format!("resource: {}\n", result.resource));
    output.push_str(&format!("action_id: {}\n", result.action_id));
    output.push_str(&format!("action: {}\n", action_label(result.action)));
    output.push_str(&format!("outcome: {}\n", outcome_label(result.outcome)));
    output.push_str(&format!("allowed: {}\n", result.allowed));
    output.push_str(&format!("admin: {}\n", result.admin));
    output.push_str(&format!(
        "role_rule_id: {}\n",
        result.role_rule_id.as_deref().unwrap_or("none")
    ));
    output.push_str(&format!(
        "required_role: {}\n",
        result.required_role.as_deref().unwrap_or("none")
    ));
    output.push_str(&format!(
        "role_check: {}\n",
        if result.role_check_passed {
            "passed"
        } else {
            "failed"
        }
    ));
    output.push_str(&format!(
        "admin_bypass_applied: {}\n",
        result.admin_bypass_applied
    ));

    if result.controlled_fields.is_empty() {
        output.push_str("controlled_fields: none\n");
    } else {
        output.push_str(&format!(
            "controlled_fields: {}\n",
            result.controlled_fields.join(", ")
        ));
    }

    match &result.filter {
        Some(filter) => output.push_str(&format!("filter: {}\n", render_condition_trace(filter))),
        None => output.push_str("filter: none\n"),
    }

    if result.assignments.is_empty() {
        output.push_str("assignments: none\n");
    } else {
        output.push_str("assignments:\n");
        for assignment in &result.assignments {
            output.push_str(&format!("  - {}\n", render_assignment_trace(assignment)));
        }
    }

    match &result.scope {
        Some(scope) => output.push_str(&format!("scope: {}={}\n", scope.scope, scope.value)),
        None => output.push_str("scope: none\n"),
    }

    if result.runtime_assignments.is_empty() {
        output.push_str("runtime_assignments: none\n");
    } else {
        output.push_str("runtime_assignments:\n");
        for assignment in &result.runtime_assignments {
            output.push_str(&format!(
                "  - {}\n",
                render_scoped_assignment_trace(assignment)
            ));
        }
    }

    if result.resolved_permissions.is_empty() {
        output.push_str("resolved_permissions: none\n");
    } else {
        output.push_str(&format!(
            "resolved_permissions: {}\n",
            result.resolved_permissions.join(", ")
        ));
    }

    if result.resolved_templates.is_empty() {
        output.push_str("resolved_templates: none\n");
    } else {
        output.push_str(&format!(
            "resolved_templates: {}\n",
            result.resolved_templates.join(", ")
        ));
    }

    if let Some(hybrid) = &result.hybrid {
        output.push_str("hybrid:\n");
        output.push_str(&format!(
            "  source: {}\n",
            hybrid_source_label(hybrid.source)
        ));
        match &hybrid.scope {
            Some(scope) => output.push_str(&format!("  scope: {}={}\n", scope.scope, scope.value)),
            None => output.push_str("  scope: none\n"),
        }
        output.push_str(&format!("  runtime_allowed: {}\n", hybrid.runtime_allowed));
        output.push_str(&format!(
            "  effective_outcome: {}\n",
            outcome_label(hybrid.effective_outcome)
        ));
        output.push_str(&format!(
            "  effective_allowed: {}\n",
            hybrid.effective_allowed
        ));
        output.push_str(&format!(
            "  fallback_applied: {}\n",
            hybrid.fallback_applied
        ));
        output.push_str(&format!(
            "  skip_static_row_policy: {}\n",
            hybrid.skip_static_row_policy
        ));
        if hybrid.notes.is_empty() {
            output.push_str("  notes: none\n");
        } else {
            output.push_str("  notes:\n");
            for note in &hybrid.notes {
                output.push_str(&format!("    - {note}\n"));
            }
        }
    } else {
        output.push_str("hybrid: none\n");
    }

    if result.notes.is_empty() {
        output.push_str("notes: none\n");
    } else {
        output.push_str("notes:\n");
        for note in &result.notes {
            output.push_str(&format!("  - {note}\n"));
        }
    }

    output
}

fn render_resource_text(output: &mut String, resource: &ResourceAuthorization) {
    output.push_str(&format!(
        "resource {} (id {}, table {})\n",
        resource.resource, resource.id, resource.table
    ));
    output.push_str(&format!("  admin_bypass: {}\n", resource.admin_bypass));

    let controlled_fields = resource.controlled_fields().into_iter().collect::<Vec<_>>();
    if controlled_fields.is_empty() {
        output.push_str("  controlled_fields: none\n");
    } else {
        output.push_str(&format!(
            "  controlled_fields: {}\n",
            controlled_fields.join(", ")
        ));
    }

    for action in &resource.actions {
        render_action_text(output, action);
    }
}

fn render_action_text(output: &mut String, action: &ActionAuthorization) {
    output.push_str(&format!("  {}:\n", action_label(action.action)));
    output.push_str(&format!("    id: {}\n", action.id));
    output.push_str(&format!(
        "    role_rule_id: {}\n",
        action.role_rule_id.as_deref().unwrap_or("none")
    ));
    output.push_str(&format!(
        "    role: {}\n",
        action.required_role.as_deref().unwrap_or("none")
    ));

    match &action.filter {
        Some(filter) => output.push_str(&format!("    filter: {}\n", render_condition(filter))),
        None => output.push_str("    filter: none\n"),
    }

    if action.assignments.is_empty() {
        output.push_str("    assignments: none\n");
    } else {
        output.push_str("    assignments:\n");
        for assignment in &action.assignments {
            output.push_str(&format!("      - {}\n", render_assignment(assignment)));
        }
    }
}

fn render_condition(condition: &AuthorizationCondition) -> String {
    match condition {
        AuthorizationCondition::Match(rule) => render_match(rule),
        AuthorizationCondition::All { id, conditions } => {
            format!("{} {}", id, join_conditions("AND", conditions))
        }
        AuthorizationCondition::Any { id, conditions } => {
            format!("{} {}", id, join_conditions("OR", conditions))
        }
        AuthorizationCondition::Not { id, condition } => {
            format!("{id} NOT ({})", render_condition(condition))
        }
        AuthorizationCondition::Exists {
            id,
            resource,
            table,
            conditions,
        } => format!(
            "{} EXISTS {}:{} [{}]",
            id,
            resource,
            table,
            conditions
                .iter()
                .map(render_exists_condition)
                .collect::<Vec<_>>()
                .join(" AND ")
        ),
    }
}

fn join_conditions(operator: &str, conditions: &[AuthorizationCondition]) -> String {
    if conditions.is_empty() {
        return "none".to_owned();
    }
    if conditions.len() == 1 {
        return render_condition(&conditions[0]);
    }
    let rendered = conditions.iter().map(render_condition).collect::<Vec<_>>();
    format!("({})", rendered.join(&format!(" {operator} ")))
}

fn render_match(rule: &AuthorizationMatch) -> String {
    match (rule.operator, rule.source.as_ref()) {
        (AuthorizationOperator::Equals, Some(source)) => {
            format!("{} {} == {}", rule.id, rule.field, render_source(source))
        }
        (AuthorizationOperator::IsNull, _) => format!("{} {} IS NULL", rule.id, rule.field),
        (AuthorizationOperator::IsNotNull, _) => {
            format!("{} {} IS NOT NULL", rule.id, rule.field)
        }
        (AuthorizationOperator::Equals, None) => {
            format!("{} {} == <missing-source>", rule.id, rule.field)
        }
    }
}

fn render_exists_condition(condition: &AuthorizationExistsCondition) -> String {
    match condition {
        AuthorizationExistsCondition::Match(rule) => render_match(rule),
        AuthorizationExistsCondition::CurrentRowField {
            id,
            field,
            row_field,
        } => format!("{id} {field} == row.{row_field}"),
        AuthorizationExistsCondition::All { id, conditions } => format!(
            "{} ({})",
            id,
            conditions
                .iter()
                .map(render_exists_condition)
                .collect::<Vec<_>>()
                .join(" AND ")
        ),
        AuthorizationExistsCondition::Any { id, conditions } => format!(
            "{} ({})",
            id,
            conditions
                .iter()
                .map(render_exists_condition)
                .collect::<Vec<_>>()
                .join(" OR ")
        ),
        AuthorizationExistsCondition::Not { id, condition } => {
            format!("{id} NOT ({})", render_exists_condition(condition))
        }
    }
}

fn render_assignment(assignment: &AuthorizationAssignment) -> String {
    format!(
        "{} {} = {}",
        assignment.id,
        assignment.field,
        render_source(&assignment.source)
    )
}

fn render_condition_trace(trace: &AuthorizationConditionTrace) -> String {
    match trace {
        AuthorizationConditionTrace::Match {
            id,
            field,
            operator,
            source,
            row_value,
            source_value,
            matched,
            indeterminate,
            missing_field,
            missing_source,
        } => {
            let mut details = Vec::new();
            details.push(if *matched {
                "matched".to_owned()
            } else {
                "matched=false".to_owned()
            });
            if *indeterminate {
                details.push("indeterminate".to_owned());
            }
            if *missing_field {
                details.push("missing_field".to_owned());
            }
            if *missing_source {
                details.push("missing_source".to_owned());
            }
            if let Some(row_value) = row_value {
                details.push(format!("row={}", render_json_value(row_value)));
            }
            if let Some(source_value) = source_value {
                details.push(format!("source={}", render_json_value(source_value)));
            }
            let rendered_source =
                source
                    .as_ref()
                    .map(render_source)
                    .unwrap_or_else(|| match operator {
                        AuthorizationOperator::Equals => "<missing-source>".to_owned(),
                        AuthorizationOperator::IsNull => "null".to_owned(),
                        AuthorizationOperator::IsNotNull => "not-null".to_owned(),
                    });
            format!(
                "{} {} {} {} [{}]",
                id,
                field,
                operator_label(*operator),
                rendered_source,
                details.join(", ")
            )
        }
        AuthorizationConditionTrace::All {
            id,
            matched,
            indeterminate,
            conditions,
        } => format!(
            "{} ({}) [{}]",
            id,
            conditions
                .iter()
                .map(render_condition_trace)
                .collect::<Vec<_>>()
                .join(" AND "),
            render_trace_status(*matched, *indeterminate)
        ),
        AuthorizationConditionTrace::Any {
            id,
            matched,
            indeterminate,
            conditions,
        } => format!(
            "{} ({}) [{}]",
            id,
            conditions
                .iter()
                .map(render_condition_trace)
                .collect::<Vec<_>>()
                .join(" OR "),
            render_trace_status(*matched, *indeterminate)
        ),
        AuthorizationConditionTrace::Not {
            id,
            matched,
            indeterminate,
            condition,
        } => format!(
            "{} NOT ({}) [{}]",
            id,
            render_condition_trace(condition),
            render_trace_status(*matched, *indeterminate)
        ),
        AuthorizationConditionTrace::Exists {
            id,
            resource,
            table,
            matched,
            indeterminate,
            related_row_count,
            matched_row_index,
            missing_related_rows,
            missing_related_fields,
            conditions,
            note,
        } => {
            let mut details = vec![render_trace_status(*matched, *indeterminate).to_owned()];
            details.push(format!("related_rows={related_row_count}"));
            if let Some(index) = matched_row_index {
                details.push(format!("matched_row={}", index + 1));
            }
            if *missing_related_rows {
                details.push("missing_related_rows".to_owned());
            }
            if *missing_related_fields {
                details.push("missing_related_fields".to_owned());
            }
            if let Some(note) = note {
                details.push(note.clone());
            }
            format!(
                "{} EXISTS {}:{} [{}] [{}]",
                id,
                resource,
                table,
                conditions
                    .iter()
                    .map(render_exists_condition_trace)
                    .collect::<Vec<_>>()
                    .join(" AND "),
                details.join(", ")
            )
        }
    }
}

fn render_exists_condition_trace(trace: &AuthorizationExistsConditionTrace) -> String {
    match trace {
        AuthorizationExistsConditionTrace::Match {
            id,
            field,
            operator,
            source,
            source_value,
            missing_source,
            related_value,
            matched,
            indeterminate,
            missing_related_field,
        } => {
            let mut details = Vec::new();
            details.push(render_trace_status(*matched, *indeterminate).to_owned());
            if *missing_source {
                details.push("missing_source".to_owned());
            }
            if *missing_related_field {
                details.push("missing_related_field".to_owned());
            }
            if let Some(source_value) = source_value {
                details.push(format!("source={}", render_json_value(source_value)));
            }
            if let Some(related_value) = related_value {
                details.push(format!("related={}", render_json_value(related_value)));
            }
            let rendered_source =
                source
                    .as_ref()
                    .map(render_source)
                    .unwrap_or_else(|| match operator {
                        AuthorizationOperator::Equals => "<missing-source>".to_owned(),
                        AuthorizationOperator::IsNull => "null".to_owned(),
                        AuthorizationOperator::IsNotNull => "not-null".to_owned(),
                    });
            format!(
                "{} {} {} {} [{}]",
                id,
                field,
                operator_label(*operator),
                rendered_source,
                if details.is_empty() {
                    "ready".to_owned()
                } else {
                    details.join(", ")
                }
            )
        }
        AuthorizationExistsConditionTrace::CurrentRowField {
            id,
            field,
            row_field,
            row_value,
            missing_row_field,
            related_value,
            matched,
            indeterminate,
            missing_related_field,
        } => {
            let mut details = Vec::new();
            details.push(render_trace_status(*matched, *indeterminate).to_owned());
            if *missing_row_field {
                details.push("missing_row_field".to_owned());
            }
            if *missing_related_field {
                details.push("missing_related_field".to_owned());
            }
            if let Some(row_value) = row_value {
                details.push(format!("row={}", render_json_value(row_value)));
            }
            if let Some(related_value) = related_value {
                details.push(format!("related={}", render_json_value(related_value)));
            }
            format!(
                "{} {} == row.{} [{}]",
                id,
                field,
                row_field,
                if details.is_empty() {
                    "ready".to_owned()
                } else {
                    details.join(", ")
                }
            )
        }
        AuthorizationExistsConditionTrace::All {
            id,
            matched,
            indeterminate,
            conditions,
        } => format!(
            "{} ({}) [{}]",
            id,
            conditions
                .iter()
                .map(render_exists_condition_trace)
                .collect::<Vec<_>>()
                .join(" AND "),
            render_trace_status(*matched, *indeterminate)
        ),
        AuthorizationExistsConditionTrace::Any {
            id,
            matched,
            indeterminate,
            conditions,
        } => format!(
            "{} ({}) [{}]",
            id,
            conditions
                .iter()
                .map(render_exists_condition_trace)
                .collect::<Vec<_>>()
                .join(" OR "),
            render_trace_status(*matched, *indeterminate)
        ),
        AuthorizationExistsConditionTrace::Not {
            id,
            matched,
            indeterminate,
            condition,
        } => format!(
            "{} NOT ({}) [{}]",
            id,
            render_exists_condition_trace(condition),
            render_trace_status(*matched, *indeterminate)
        ),
    }
}

fn render_assignment_trace(trace: &AuthorizationAssignmentTrace) -> String {
    let mut details = Vec::new();
    details.push(format!("id={}", trace.id));
    details.push(format!("source={}", render_source(&trace.source)));
    if let Some(value) = &trace.source_value {
        details.push(format!("source_value={}", render_json_value(value)));
    }
    if let Some(value) = &trace.proposed_value {
        details.push(format!("proposed={}", render_json_value(value)));
    }
    if let Some(value) = &trace.effective_value {
        details.push(format!("effective={}", render_json_value(value)));
    }
    if trace.admin_override_allowed {
        details.push("admin_override_allowed=true".to_owned());
    }
    if trace.admin_override_applied {
        details.push("admin_override_applied=true".to_owned());
    }
    if trace.missing_source {
        details.push("missing_source=true".to_owned());
    }
    format!(
        "{} [{}]",
        render_assignment(&trace_to_assignment(trace)),
        details.join(", ")
    )
}

fn render_scoped_assignment_trace(trace: &AuthorizationScopedAssignmentTrace) -> String {
    let mut details = Vec::new();
    details.push(format!(
        "target={}",
        render_scoped_assignment_target(&trace.target)
    ));
    details.push(format!("scope={}={}", trace.scope.scope, trace.scope.value));
    details.push(format!("scope_matched={}", trace.scope_matched));
    details.push(format!("target_matched={}", trace.target_matched));
    if let Some(template) = &trace.resolved_template {
        details.push(format!("resolved_template={template}"));
    }
    if !trace.resolved_permissions.is_empty() {
        details.push(format!(
            "resolved_permissions={}",
            trace.resolved_permissions.join(", ")
        ));
    }
    format!("{} [{}]", trace.id, details.join(", "))
}

fn trace_to_assignment(trace: &AuthorizationAssignmentTrace) -> AuthorizationAssignment {
    AuthorizationAssignment {
        id: trace.id.clone(),
        field: trace.field.clone(),
        source: trace.source.clone(),
    }
}

fn render_source(source: &AuthorizationValueSource) -> String {
    match source {
        AuthorizationValueSource::UserId => "user.id".to_owned(),
        AuthorizationValueSource::Claim { name, ty } => format!("claim.{name}:{ty:?}"),
        AuthorizationValueSource::InputField { name } => format!("input.{name}"),
        AuthorizationValueSource::Literal { value } => match value {
            AuthorizationLiteralValue::String(value) => format!("{value:?}"),
            AuthorizationLiteralValue::I64(value) => value.to_string(),
            AuthorizationLiteralValue::Bool(value) => value.to_string(),
        },
    }
}

fn render_scoped_assignment_target(target: &AuthorizationScopedAssignmentTarget) -> String {
    match target {
        AuthorizationScopedAssignmentTarget::Permission { name } => {
            format!("permission:{name}")
        }
        AuthorizationScopedAssignmentTarget::Template { name } => {
            format!("template:{name}")
        }
    }
}

fn runtime_assignment_event_kind_label(
    kind: AuthorizationScopedAssignmentEventKind,
) -> &'static str {
    match kind {
        AuthorizationScopedAssignmentEventKind::Created => "created",
        AuthorizationScopedAssignmentEventKind::Revoked => "revoked",
        AuthorizationScopedAssignmentEventKind::Renewed => "renewed",
        AuthorizationScopedAssignmentEventKind::Deleted => "deleted",
    }
}

fn action_label(action: AuthorizationAction) -> &'static str {
    match action {
        AuthorizationAction::Read => "read",
        AuthorizationAction::Create => "create",
        AuthorizationAction::Update => "update",
        AuthorizationAction::Delete => "delete",
    }
}

fn outcome_label(outcome: AuthorizationOutcome) -> &'static str {
    match outcome {
        AuthorizationOutcome::Allowed => "allowed",
        AuthorizationOutcome::Denied => "denied",
        AuthorizationOutcome::Incomplete => "incomplete",
    }
}

fn hybrid_source_label(source: AuthorizationHybridSource) -> &'static str {
    match source {
        AuthorizationHybridSource::Item => "item",
        AuthorizationHybridSource::CollectionFilter => "collection_filter",
        AuthorizationHybridSource::NestedParent => "nested_parent",
        AuthorizationHybridSource::CreatePayload => "create_payload",
    }
}

fn operator_label(operator: rest_macro_core::authorization::AuthorizationOperator) -> &'static str {
    match operator {
        rest_macro_core::authorization::AuthorizationOperator::Equals => "==",
        rest_macro_core::authorization::AuthorizationOperator::IsNull => "IS NULL",
        rest_macro_core::authorization::AuthorizationOperator::IsNotNull => "IS NOT NULL",
    }
}

fn render_trace_status(matched: bool, indeterminate: bool) -> &'static str {
    if indeterminate {
        "indeterminate"
    } else if matched {
        "matched"
    } else {
        "matched=false"
    }
}

fn render_json_value(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Null => "null".to_owned(),
        _ => value.to_string(),
    }
}

fn parse_key_value_values(values: &[String], label: &str) -> Result<BTreeMap<String, Value>> {
    let mut parsed = BTreeMap::new();
    for raw in values {
        let (key, value) = parse_key_value(raw, label)?;
        if parsed.insert(key.clone(), value).is_some() {
            bail!("duplicate {label} key `{key}`");
        }
    }
    Ok(parsed)
}

fn parse_related_rows(values: &[String]) -> Result<BTreeMap<String, Vec<BTreeMap<String, Value>>>> {
    let mut parsed = BTreeMap::new();
    for raw in values {
        let (resource, row_spec) = raw.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("related rows must use `Resource:key=value,other=value` syntax")
        })?;
        let resource = resource.trim();
        if resource.is_empty() {
            bail!("related row resource cannot be empty");
        }
        let row_spec = row_spec.trim();
        if row_spec.is_empty() {
            bail!("related row fields cannot be empty");
        }
        let fields = row_spec
            .split(',')
            .map(str::trim)
            .filter(|segment| !segment.is_empty())
            .map(|segment| parse_key_value(segment, "related row"))
            .collect::<Result<Vec<_>>>()?;
        if fields.is_empty() {
            bail!("related row fields cannot be empty");
        }
        let mut row = BTreeMap::new();
        for (key, value) in fields {
            if row.insert(key.clone(), value).is_some() {
                bail!("duplicate related row key `{key}`");
            }
        }
        parsed
            .entry(resource.to_owned())
            .or_insert_with(Vec::new)
            .push(row);
    }
    Ok(parsed)
}

fn parse_key_value(raw: &str, label: &str) -> Result<(String, Value)> {
    let (key, value) = raw
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("{label} values must use key=value syntax"))?;
    let key = key.trim();
    if key.is_empty() {
        bail!("{label} key cannot be empty");
    }
    Ok((key.to_owned(), parse_cli_value(value.trim())))
}

fn parse_cli_value(value: &str) -> Value {
    if value.eq_ignore_ascii_case("null") {
        Value::Null
    } else if value.eq_ignore_ascii_case("true") {
        Value::Bool(true)
    } else if value.eq_ignore_ascii_case("false") {
        Value::Bool(false)
    } else if let Ok(value) = value.parse::<i64>() {
        Value::from(value)
    } else {
        Value::String(value.to_owned())
    }
}

fn parse_scope_binding(raw: &str) -> Result<AuthorizationScopeBinding> {
    let (scope, value) = raw
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("scope values must use ScopeName=value syntax"))?;
    let scope = scope.trim();
    let value = value.trim();
    if scope.is_empty() {
        bail!("scope name cannot be empty");
    }
    if value.is_empty() {
        bail!("scope value cannot be empty");
    }
    Ok(AuthorizationScopeBinding {
        scope: scope.to_owned(),
        value: value.to_owned(),
    })
}

fn parse_scoped_assignments(values: &[String]) -> Result<Vec<AuthorizationScopedAssignment>> {
    values
        .iter()
        .enumerate()
        .map(|(index, raw)| {
            parse_scoped_assignment(raw, &format!("runtime.assignment.{}", index + 1))
        })
        .collect()
}

fn parse_scoped_assignment(raw: &str, id: &str) -> Result<AuthorizationScopedAssignment> {
    let (target, scope) = raw.split_once('@').ok_or_else(|| {
        anyhow::anyhow!(
            "runtime assignments must use `permission:Name@Scope=value` or `template:Name@Scope=value`"
        )
    })?;
    let target = parse_scoped_assignment_target(target.trim())?;
    let scope = parse_scope_binding(scope.trim())?;
    Ok(AuthorizationScopedAssignment {
        id: id.to_owned(),
        target,
        scope,
    })
}

fn parse_scoped_assignment_target(raw: &str) -> Result<AuthorizationScopedAssignmentTarget> {
    let (kind, name) = raw.split_once(':').ok_or_else(|| {
        anyhow::anyhow!("runtime assignment targets must use `permission:Name` or `template:Name`")
    })?;
    let name = name.trim();
    if name.is_empty() {
        bail!("runtime assignment target name cannot be empty");
    }
    match kind.trim().to_ascii_lowercase().as_str() {
        "permission" => Ok(AuthorizationScopedAssignmentTarget::Permission {
            name: name.to_owned(),
        }),
        "template" => Ok(AuthorizationScopedAssignmentTarget::Template {
            name: name.to_owned(),
        }),
        _ => bail!("runtime assignment target kind must be `permission` or `template`"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;

    use serde_json::Value;
    use uuid::Uuid;

    use super::{
        OutputFormat, create_runtime_assignment, delete_runtime_assignment,
        evaluate_runtime_access, explain_authorization, list_runtime_assignment_history,
        list_runtime_assignments, parse_cli_value, parse_related_rows, parse_scope_binding,
        parse_scoped_assignments, render_authorization_explanation,
        render_authorization_simulation, renew_runtime_assignment, revoke_runtime_assignment,
        simulate_authorization,
    };
    use rest_macro_core::{
        authorization::{AuthorizationAction, AuthorizationSimulationInput},
        compiler,
    };

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    fn load_service(name: &str) -> compiler::ServiceSpec {
        compiler::load_service_from_path(&fixture_path(name)).expect("fixture should load")
    }

    fn test_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/authz_tests")
            .join(Uuid::new_v4().to_string())
    }

    #[test]
    fn render_authorization_explanation_describes_current_tenant_policy_shape() {
        let rendered =
            render_authorization_explanation(&load_service("tenant_api.eon"), OutputFormat::Text)
                .expect("explanation should render");

        assert!(rendered.contains("Authorization explanation"));
        assert!(
            rendered.contains("resource TenantPost (id resource.tenant_post, table tenant_post)")
        );
        assert!(rendered.contains("admin_bypass: false"));
        assert!(rendered.contains("controlled_fields: tenant_id, user_id"));
        assert!(
            rendered.contains(
                "filter: resource.tenant_post.action.read.filter (resource.tenant_post.action.read.filter.1 user_id == user.id AND resource.tenant_post.action.read.filter.2 tenant_id == claim.tenant_id:I64)"
            )
        );
        assert!(rendered.contains(
            "- resource.tenant_post.action.create.assignment.tenant_id tenant_id = claim.tenant_id:I64"
        ));
    }

    #[test]
    fn explain_authorization_can_write_json_output() {
        let root = test_root();
        let output = root.join("authz.json");
        explain_authorization(
            &fixture_path("auth_claims_api.eon"),
            Some(&output),
            OutputFormat::Json,
            false,
        )
        .expect("authorization explanation should write");

        let document: Value = serde_json::from_str(
            &fs::read_to_string(&output).expect("json output should be readable"),
        )
        .expect("json output should parse");

        assert_eq!(document["resources"][0]["id"], "resource.scoped_doc");
        assert_eq!(document["resources"][0]["resource"], "ScopedDoc");
        assert_eq!(
            document["resources"][0]["actions"][0]["id"],
            "resource.scoped_doc.action.read"
        );
        assert_eq!(document["resources"][0]["actions"][0]["action"], "read");
        assert_eq!(
            document["resources"][0]["actions"][0]["filter"]["id"],
            "resource.scoped_doc.action.read.filter"
        );
        assert_eq!(
            document["resources"][0]["actions"][0]["filter"]["source"]["name"],
            "tenant_id"
        );
    }

    #[test]
    fn render_authorization_simulation_shows_matching_row_policy() {
        let rendered = render_authorization_simulation(
            &load_service("tenant_api.eon"),
            Some("TenantPost"),
            AuthorizationSimulationInput {
                action: AuthorizationAction::Read,
                user_id: Some(7),
                roles: Vec::new(),
                claims: BTreeMap::from([("tenant_id".to_owned(), Value::from(3))]),
                row: BTreeMap::from([
                    ("user_id".to_owned(), Value::from(7)),
                    ("tenant_id".to_owned(), Value::from(3)),
                ]),
                proposed: BTreeMap::new(),
                related_rows: BTreeMap::new(),
                scope: None,
                hybrid_source: None,
                scoped_assignments: Vec::new(),
            },
            OutputFormat::Text,
        )
        .expect("simulation should render");

        assert!(rendered.contains("Authorization simulation"));
        assert!(rendered.contains("resource_id: resource.tenant_post"));
        assert!(rendered.contains("action_id: resource.tenant_post.action.read"));
        assert!(rendered.contains("outcome: allowed"));
        assert!(rendered.contains("role_check: passed"));
        assert!(
            rendered
                .contains("resource.tenant_post.action.read.filter.1 user_id == user.id [matched")
        );
        assert!(rendered.contains(
            "resource.tenant_post.action.read.filter.2 tenant_id == claim.tenant_id:I64 [matched"
        ));
        assert!(rendered.contains("runtime_assignments: none"));
    }

    #[test]
    fn render_authorization_simulation_resolves_runtime_scoped_assignments() {
        let rendered = render_authorization_simulation(
            &load_service("authorization_contract_api.eon"),
            Some("ScopedDoc"),
            AuthorizationSimulationInput {
                action: AuthorizationAction::Read,
                user_id: Some(7),
                roles: Vec::new(),
                claims: BTreeMap::new(),
                row: BTreeMap::new(),
                proposed: BTreeMap::new(),
                related_rows: BTreeMap::new(),
                scope: Some(parse_scope_binding("Family=42").expect("scope should parse")),
                hybrid_source: None,
                scoped_assignments: parse_scoped_assignments(&[
                    "template:FamilyMember@Family=42".to_owned()
                ])
                .expect("scoped assignments should parse"),
            },
            OutputFormat::Text,
        )
        .expect("simulation should render");

        assert!(rendered.contains("scope: Family=42"));
        assert!(rendered.contains("runtime_assignments:"));
        assert!(rendered.contains("runtime.assignment.1"));
        assert!(rendered.contains("resolved_permissions: FamilyRead"));
        assert!(rendered.contains("resolved_templates: FamilyMember"));
        assert!(rendered.contains("generated handlers do not enforce"));
    }

    #[test]
    fn render_authorization_simulation_reports_hybrid_item_fallback() {
        let rendered = render_authorization_simulation(
            &load_service("hybrid_runtime_api.eon"),
            Some("ScopedDoc"),
            AuthorizationSimulationInput {
                action: AuthorizationAction::Read,
                user_id: Some(7),
                roles: vec!["member".to_owned()],
                claims: BTreeMap::new(),
                row: BTreeMap::from([
                    ("user_id".to_owned(), Value::from(1)),
                    ("family_id".to_owned(), Value::from(42)),
                ]),
                proposed: BTreeMap::new(),
                related_rows: BTreeMap::new(),
                scope: None,
                hybrid_source: Some(
                    rest_macro_core::authorization::AuthorizationHybridSource::Item,
                ),
                scoped_assignments: parse_scoped_assignments(&[
                    "template:FamilyMember@Family=42".to_owned()
                ])
                .expect("scoped assignments should parse"),
            },
            OutputFormat::Text,
        )
        .expect("simulation should render");

        assert!(rendered.contains("outcome: denied"));
        assert!(rendered.contains("hybrid:"));
        assert!(rendered.contains("source: item"));
        assert!(rendered.contains("scope: Family=42"));
        assert!(rendered.contains("effective_outcome: allowed"));
        assert!(rendered.contains("fallback_applied: true"));
    }

    #[test]
    fn render_authorization_simulation_reports_hybrid_collection_scope_widening() {
        let rendered = render_authorization_simulation(
            &load_service("hybrid_runtime_api.eon"),
            Some("ScopedDoc"),
            AuthorizationSimulationInput {
                action: AuthorizationAction::Read,
                user_id: Some(7),
                roles: vec!["member".to_owned()],
                claims: BTreeMap::new(),
                row: BTreeMap::new(),
                proposed: BTreeMap::new(),
                related_rows: BTreeMap::new(),
                scope: Some(parse_scope_binding("Family=42").expect("scope should parse")),
                hybrid_source: Some(
                    rest_macro_core::authorization::AuthorizationHybridSource::CollectionFilter,
                ),
                scoped_assignments: parse_scoped_assignments(&[
                    "template:FamilyMember@Family=42".to_owned()
                ])
                .expect("scoped assignments should parse"),
            },
            OutputFormat::Text,
        )
        .expect("simulation should render");

        assert!(rendered.contains("outcome: incomplete"));
        assert!(rendered.contains("source: collection_filter"));
        assert!(rendered.contains("effective_outcome: allowed"));
        assert!(rendered.contains("skip_static_row_policy: true"));
    }

    #[test]
    fn render_authorization_explanation_includes_static_contract_sections() {
        let rendered = render_authorization_explanation(
            &load_service("authorization_contract_api.eon"),
            OutputFormat::Text,
        )
        .expect("explanation should render");

        assert!(rendered.contains("contract.scopes: 2"));
        assert!(rendered.contains("Household (parent: Family)"));
        assert!(rendered.contains("contract.permissions: 2"));
        assert!(rendered.contains("FamilyManage [actions=update, delete"));
        assert!(rendered.contains("contract.templates: 2"));
        assert!(rendered.contains("FamilyManager [permissions=FamilyRead, FamilyManage"));
    }

    #[tokio::test]
    async fn simulate_authorization_can_write_json_output() {
        let root = test_root();
        let output = root.join("authz-sim.json");
        simulate_authorization(
            &fixture_path("auth_claims_api.eon"),
            Some("ScopedDoc"),
            AuthorizationAction::Create,
            Some(1),
            &["admin".to_owned()],
            &[],
            &[],
            &[],
            &["tenant_id=42".to_owned()],
            None,
            None,
            &[],
            false,
            None,
            None,
            Some(&output),
            OutputFormat::Json,
            false,
        )
        .await
        .expect("simulation should write");

        let document: Value = serde_json::from_str(
            &fs::read_to_string(&output).expect("json output should be readable"),
        )
        .expect("json output should parse");

        assert_eq!(document["resource_id"], "resource.scoped_doc");
        assert_eq!(document["resource"], "ScopedDoc");
        assert_eq!(document["action_id"], "resource.scoped_doc.action.create");
        assert_eq!(document["action"], "create");
        assert_eq!(document["outcome"], "allowed");
        assert_eq!(
            document["assignments"][0]["id"],
            "resource.scoped_doc.action.create.assignment.tenant_id"
        );
        assert_eq!(document["assignments"][0]["admin_override_applied"], true);
        assert_eq!(document["assignments"][0]["effective_value"], 42);
    }

    #[test]
    fn parse_cli_value_infers_null_bool_integer_and_string() {
        assert_eq!(parse_cli_value("null"), Value::Null);
        assert_eq!(parse_cli_value("true"), Value::Bool(true));
        assert_eq!(parse_cli_value("42"), Value::from(42));
        assert_eq!(parse_cli_value("pro"), Value::String("pro".to_owned()));
    }

    #[test]
    fn parse_runtime_scope_and_assignments() {
        let scope = parse_scope_binding("Family=42").expect("scope should parse");
        assert_eq!(scope.scope, "Family");
        assert_eq!(scope.value, "42");

        let assignments = parse_scoped_assignments(&[
            "permission:FamilyRead@Family=42".to_owned(),
            "template:FamilyManager@Household=7".to_owned(),
        ])
        .expect("assignments should parse");

        assert_eq!(assignments.len(), 2);
        assert_eq!(assignments[0].id, "runtime.assignment.1");
        assert_eq!(assignments[1].id, "runtime.assignment.2");
    }

    #[test]
    fn parse_related_rows_groups_rows_by_resource() {
        let rows = parse_related_rows(&[
            "FamilyMember:family_id=42,user_id=7".to_owned(),
            "FamilyMember:family_id=42,user_id=9".to_owned(),
        ])
        .expect("related rows should parse");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows["FamilyMember"].len(), 2);
        assert_eq!(rows["FamilyMember"][0]["family_id"], Value::from(42));
        assert_eq!(rows["FamilyMember"][0]["user_id"], Value::from(7));
    }

    #[test]
    fn render_authorization_simulation_evaluates_exists_with_related_rows() {
        let rendered = render_authorization_simulation(
            &load_service("exists_policy_api.eon"),
            Some("SharedDoc"),
            AuthorizationSimulationInput {
                action: AuthorizationAction::Read,
                user_id: Some(7),
                roles: Vec::new(),
                claims: BTreeMap::new(),
                row: BTreeMap::from([("family_id".to_owned(), Value::from(42))]),
                proposed: BTreeMap::new(),
                related_rows: BTreeMap::from([(
                    "FamilyMember".to_owned(),
                    vec![BTreeMap::from([
                        ("family_id".to_owned(), Value::from(42)),
                        ("user_id".to_owned(), Value::from(7)),
                    ])],
                )]),
                scope: None,
                hybrid_source: None,
                scoped_assignments: Vec::new(),
            },
            OutputFormat::Text,
        )
        .expect("simulation should render");

        assert!(rendered.contains("outcome: allowed"));
        assert!(rendered.contains("matched_row=1"));
        assert!(rendered.contains("related_rows=1"));
    }

    #[tokio::test]
    async fn simulate_authorization_loads_runtime_assignments_from_database() {
        use rest_macro_core::auth::AuthDbBackend;
        use rest_macro_core::authorization::authorization_runtime_migration_sql;
        use sqlx::Executor;

        sqlx::any::install_default_drivers();

        let root = test_root();
        fs::create_dir_all(&root).expect("test root should exist");
        let database_path = root.join("authz-runtime.db");
        let database_url = format!("sqlite:{}?mode=rwc", database_path.display());
        let pool = sqlx::AnyPool::connect(&database_url)
            .await
            .expect("database should connect");
        pool.execute(authorization_runtime_migration_sql(AuthDbBackend::Sqlite).as_str())
            .await
            .expect("runtime assignment migration should apply");
        sqlx::query(
            "INSERT INTO authz_scoped_assignment \
             (id, user_id, created_by_user_id, created_at, expires_at, target_kind, target_name, scope_name, scope_value) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind("runtime.assignment.db.1")
        .bind(7_i64)
        .bind(1_i64)
        .bind(rest_macro_core::authorization::runtime_assignment_timestamp_now())
        .bind(Option::<String>::None)
        .bind("template")
        .bind("FamilyMember")
        .bind("Family")
        .bind("42")
        .execute(&pool)
        .await
        .expect("runtime assignment row should insert");
        drop(pool);

        let output = root.join("authz-runtime-sim.txt");
        simulate_authorization(
            &fixture_path("authorization_contract_api.eon"),
            Some("ScopedDoc"),
            AuthorizationAction::Read,
            Some(7),
            &[],
            &[],
            &[],
            &[],
            &[],
            Some("Family=42"),
            None,
            &[],
            true,
            Some(&database_url),
            None,
            Some(&output),
            OutputFormat::Text,
            false,
        )
        .await
        .expect("simulation should load runtime assignments from the database");

        let rendered = fs::read_to_string(&output).expect("simulation output should be readable");
        assert!(rendered.contains("runtime.assignment.db.1"));
        assert!(rendered.contains("resolved_permissions: FamilyRead"));
        assert!(rendered.contains("resolved_templates: FamilyMember"));
    }

    #[tokio::test]
    async fn runtime_assignment_commands_manage_persisted_assignments() {
        use rest_macro_core::auth::AuthDbBackend;
        use rest_macro_core::authorization::authorization_runtime_migration_sql;
        use sqlx::Executor;

        sqlx::any::install_default_drivers();

        let root = test_root();
        fs::create_dir_all(&root).expect("test root should exist");
        let database_path = root.join("authz-runtime-cli.db");
        let database_url = format!("sqlite:{}?mode=rwc", database_path.display());
        let pool = sqlx::AnyPool::connect(&database_url)
            .await
            .expect("database should connect");
        pool.execute(authorization_runtime_migration_sql(AuthDbBackend::Sqlite).as_str())
            .await
            .expect("runtime assignment migration should apply");
        drop(pool);

        let initial_expires_at = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::days(1))
            .expect("initial expiry should compute")
            .to_rfc3339_opts(chrono::SecondsFormat::Micros, false);
        let create_output = root.join("create.json");
        create_runtime_assignment(
            &fixture_path("authz_management_api.eon"),
            7,
            "template:FamilyMember@Family=42",
            Some(&initial_expires_at),
            Some(1),
            &database_url,
            None,
            Some(&create_output),
            OutputFormat::Json,
            false,
        )
        .await
        .expect("runtime assignment should create");

        let created: Value = serde_json::from_str(
            &fs::read_to_string(&create_output).expect("created assignment output should exist"),
        )
        .expect("created assignment output should parse");
        let assignment_id = created["id"]
            .as_str()
            .expect("created assignment should include id")
            .to_owned();
        assert_eq!(created["user_id"], 7);
        assert_eq!(created["target"]["kind"], "template");
        assert_eq!(created["target"]["name"], "FamilyMember");
        assert_eq!(created["scope"]["scope"], "Family");
        assert_eq!(created["scope"]["value"], "42");
        assert_eq!(created["created_by_user_id"], 1);

        let list_output = root.join("list.txt");
        list_runtime_assignments(
            7,
            &database_url,
            None,
            Some(&list_output),
            OutputFormat::Text,
            false,
        )
        .await
        .expect("runtime assignments should list");
        let listed = fs::read_to_string(&list_output).expect("list output should exist");
        assert!(listed.contains("Runtime authorization assignments"));
        assert!(listed.contains(&assignment_id));
        assert!(listed.contains("target=template:FamilyMember"));
        assert!(listed.contains("scope=Family=42"));

        let evaluate_output = root.join("evaluate.txt");
        evaluate_runtime_access(
            &fixture_path("authz_management_api.eon"),
            "ScopedDoc",
            AuthorizationAction::Read,
            7,
            "Family=42",
            &database_url,
            None,
            Some(&evaluate_output),
            OutputFormat::Text,
            false,
        )
        .await
        .expect("runtime access should evaluate");
        let evaluated =
            fs::read_to_string(&evaluate_output).expect("evaluation output should exist");
        assert!(evaluated.contains("Runtime authorization access"));
        assert!(evaluated.contains("allowed: true"));
        assert!(evaluated.contains("resolved_permissions: FamilyRead"));
        assert!(evaluated.contains("resolved_templates: FamilyMember"));

        let revoke_output = root.join("revoke.txt");
        revoke_runtime_assignment(
            &assignment_id,
            Some(11),
            Some("suspend"),
            &database_url,
            None,
            Some(&revoke_output),
            OutputFormat::Text,
            false,
        )
        .await
        .expect("runtime assignment should revoke");
        let revoked = fs::read_to_string(&revoke_output).expect("revoke output should exist");
        assert!(revoked.contains("Runtime authorization assignment"));
        assert!(revoked.contains(&assignment_id));
        assert!(revoked.contains("expires_at: "));

        let evaluate_after_revoke = root.join("evaluate-after-revoke.txt");
        evaluate_runtime_access(
            &fixture_path("authz_management_api.eon"),
            "ScopedDoc",
            AuthorizationAction::Read,
            7,
            "Family=42",
            &database_url,
            None,
            Some(&evaluate_after_revoke),
            OutputFormat::Text,
            false,
        )
        .await
        .expect("runtime access should evaluate after revoke");
        let evaluated_after_revoke = fs::read_to_string(&evaluate_after_revoke)
            .expect("post-revoke evaluation output should exist");
        assert!(evaluated_after_revoke.contains("allowed: false"));

        let renewed_expires_at = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::days(3))
            .expect("renewed expiry should compute")
            .to_rfc3339_opts(chrono::SecondsFormat::Micros, false);
        let renew_output = root.join("renew.json");
        renew_runtime_assignment(
            &assignment_id,
            &renewed_expires_at,
            Some(12),
            Some("restore"),
            &database_url,
            None,
            Some(&renew_output),
            OutputFormat::Json,
            false,
        )
        .await
        .expect("runtime assignment should renew");
        let renewed: Value = serde_json::from_str(
            &fs::read_to_string(&renew_output).expect("renew output should exist"),
        )
        .expect("renew output should parse");
        assert_eq!(renewed["id"], assignment_id);
        assert_eq!(renewed["expires_at"], renewed_expires_at);

        let history_output = root.join("history.txt");
        list_runtime_assignment_history(
            7,
            &database_url,
            None,
            Some(&history_output),
            OutputFormat::Text,
            false,
        )
        .await
        .expect("runtime assignment history should list");
        let history = fs::read_to_string(&history_output).expect("history output should exist");
        assert!(history.contains("Runtime authorization assignment history"));
        assert!(history.contains("event=created"));
        assert!(history.contains("event=revoked"));
        assert!(history.contains("actor_user_id=11"));
        assert!(history.contains("reason=suspend"));
        let history_after_renew_output = root.join("history-after-renew.txt");
        list_runtime_assignment_history(
            7,
            &database_url,
            None,
            Some(&history_after_renew_output),
            OutputFormat::Text,
            false,
        )
        .await
        .expect("runtime assignment history should list after renew");
        let history_after_renew = fs::read_to_string(&history_after_renew_output)
            .expect("renewed history output should exist");
        assert!(history_after_renew.contains("event=renewed"));
        assert!(history_after_renew.contains("actor_user_id=12"));
        assert!(history_after_renew.contains("reason=restore"));

        let evaluate_after_renew = root.join("evaluate-after-renew.txt");
        evaluate_runtime_access(
            &fixture_path("authz_management_api.eon"),
            "ScopedDoc",
            AuthorizationAction::Read,
            7,
            "Family=42",
            &database_url,
            None,
            Some(&evaluate_after_renew),
            OutputFormat::Text,
            false,
        )
        .await
        .expect("runtime access should evaluate after renew");
        let evaluated_after_renew = fs::read_to_string(&evaluate_after_renew)
            .expect("post-renew evaluation output should exist");
        assert!(evaluated_after_renew.contains("allowed: true"));

        let delete_output = root.join("delete.json");
        delete_runtime_assignment(
            &assignment_id,
            Some(13),
            Some("cleanup"),
            &database_url,
            None,
            Some(&delete_output),
            OutputFormat::Json,
            false,
        )
        .await
        .expect("runtime assignment should delete");
        let deleted: Value = serde_json::from_str(
            &fs::read_to_string(&delete_output).expect("delete output should exist"),
        )
        .expect("delete output should parse");
        assert_eq!(deleted["id"], assignment_id);
        assert_eq!(deleted["deleted"], true);

        let list_after_delete = root.join("list-after-delete.txt");
        list_runtime_assignments(
            7,
            &database_url,
            None,
            Some(&list_after_delete),
            OutputFormat::Text,
            false,
        )
        .await
        .expect("runtime assignments should list after delete");
        let listed_after_delete =
            fs::read_to_string(&list_after_delete).expect("list-after-delete output should exist");
        assert!(listed_after_delete.contains("count: 0"));
        assert!(listed_after_delete.contains("assignments: none"));

        let history_after_delete_output = root.join("history-after-delete.txt");
        list_runtime_assignment_history(
            7,
            &database_url,
            None,
            Some(&history_after_delete_output),
            OutputFormat::Text,
            false,
        )
        .await
        .expect("runtime assignment history should list after delete");
        let history_after_delete = fs::read_to_string(&history_after_delete_output)
            .expect("delete history output should exist");
        assert!(history_after_delete.contains("event=deleted"));
        assert!(history_after_delete.contains("actor_user_id=13"));
        assert!(history_after_delete.contains("reason=cleanup"));
    }
}
