use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result, bail};
use colored::Colorize;
use rest_macro_core::{
    authorization::{
        ActionAuthorization, AuthorizationAction, AuthorizationAssignment,
        AuthorizationAssignmentTrace, AuthorizationCondition, AuthorizationConditionTrace,
        AuthorizationContract, AuthorizationExistsCondition, AuthorizationExistsConditionTrace,
        AuthorizationMatch, AuthorizationModel, AuthorizationOutcome, AuthorizationScopeBinding,
        AuthorizationScopedAssignment, AuthorizationScopedAssignmentTarget,
        AuthorizationScopedAssignmentTrace, AuthorizationSimulationInput,
        AuthorizationSimulationResult, AuthorizationValueSource, ResourceAuthorization,
        load_runtime_assignments_for_user,
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

fn render_contract_text(output: &mut String, contract: &AuthorizationContract) {
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
    format!(
        "{} {} == {}",
        rule.id,
        rule.field,
        render_source(&rule.source)
    )
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
            format!(
                "{} {} {} {} [{}]",
                id,
                field,
                operator_label(*operator),
                render_source(source),
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
            format!(
                "{} {} == {} [{}]",
                id,
                field,
                render_source(source),
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

fn operator_label(operator: rest_macro_core::authorization::AuthorizationOperator) -> &'static str {
    match operator {
        rest_macro_core::authorization::AuthorizationOperator::Equals => "==",
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
            let (target, scope) = raw.split_once('@').ok_or_else(|| {
                anyhow::anyhow!(
                    "runtime assignments must use `permission:Name@Scope=value` or `template:Name@Scope=value`"
                )
            })?;
            let target = parse_scoped_assignment_target(target.trim())?;
            let scope = parse_scope_binding(scope.trim())?;
            Ok(AuthorizationScopedAssignment {
                id: format!("runtime.assignment.{}", index + 1),
                target,
                scope,
            })
        })
        .collect()
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
        OutputFormat, explain_authorization, parse_cli_value, parse_related_rows,
        parse_scope_binding, parse_scoped_assignments, render_authorization_explanation,
        render_authorization_simulation, simulate_authorization,
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
}
