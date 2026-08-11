//! Audit helper token generation shared by CRUD and resource-action handlers.

use proc_macro2::{Literal, TokenStream};
use quote::quote;
use syn::Path;

use super::super::model::ResourceSpec;

pub(super) fn audit_sink_resource<'a>(
    resource: &ResourceSpec,
    resources: &'a [ResourceSpec],
) -> Option<&'a ResourceSpec> {
    let audit = resource.audit.as_ref()?;
    resources.iter().find(|candidate| {
        candidate.struct_ident == audit.resource || candidate.table_name == audit.resource
    })
}

pub(super) fn create_audit_event_kind(resource: &ResourceSpec) -> Option<String> {
    resource
        .audit
        .as_ref()
        .filter(|audit| audit.audits_create())
        .map(|_| "create".to_owned())
}

pub(super) fn update_audit_event_kind(
    resource: &ResourceSpec,
    action_name: Option<&str>,
) -> Option<String> {
    let audit = resource.audit.as_ref()?;
    if let Some(action_name) = action_name
        && audit.audits_action(action_name)
    {
        return Some(format!("action:{action_name}"));
    }

    audit.audits_update().then(|| "update".to_owned())
}

pub(super) fn delete_audit_event_kind(
    resource: &ResourceSpec,
    action_name: Option<&str>,
) -> Option<String> {
    let audit = resource.audit.as_ref()?;
    if let Some(action_name) = action_name
        && audit.audits_action(action_name)
    {
        return Some(format!("action:{action_name}"));
    }

    audit.audits_delete().then(|| "delete".to_owned())
}

pub(super) fn audit_helper_method_tokens(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    runtime_crate: &Path,
) -> TokenStream {
    let Some(sink) = audit_sink_resource(resource, resources) else {
        return quote!();
    };

    let table_name = Literal::string(&resource.table_name);
    let id_field = Literal::string(&resource.id_field);
    let sink_table = Literal::string(&sink.table_name);
    let resource_name = Literal::string(&resource.struct_ident.to_string());

    quote! {
        async fn fetch_unfiltered_by_id_for_audit<E>(
            id: i64,
            executor: &E,
        ) -> Result<Option<Self>, #runtime_crate::sqlx::Error>
        where
            E: #runtime_crate::db::DbExecutor + ?Sized,
        {
            let sql = format!(
                "SELECT * FROM {} WHERE {} = {}",
                #table_name,
                #id_field,
                Self::list_placeholder(1),
            );
            #runtime_crate::db::query_as::<#runtime_crate::sqlx::Any, Self>(&sql)
                .bind(id)
                .fetch_optional(executor)
                .await
        }

        fn audit_actor_user_id(user: &#runtime_crate::core::auth::UserContext) -> Option<i64> {
            (user.id != 0).then_some(user.id)
        }

        fn audit_payload_json(
            before: Option<&Self>,
            after: Option<&Self>,
        ) -> Result<String, HttpResponse> {
            let before = before
                .map(|item| Self::serialize_item_value(item, None))
                .transpose()?;
            let after = after
                .map(|item| Self::serialize_item_value(item, None))
                .transpose()?;
            #runtime_crate::serde_json::to_string(&match (before, after) {
                (Some(before), Some(after)) => #runtime_crate::serde_json::json!({
                    "before": before,
                    "after": after,
                }),
                (Some(before), None) => #runtime_crate::serde_json::json!({
                    "before": before,
                }),
                (None, Some(after)) => #runtime_crate::serde_json::json!({
                    "after": after,
                }),
                (None, None) => #runtime_crate::serde_json::json!({}),
            })
            .map_err(|error| #runtime_crate::core::errors::internal_error(error.to_string()))
        }

        async fn insert_audit_event<E>(
            executor: &E,
            user: &#runtime_crate::core::auth::UserContext,
            event_kind: &str,
            record_id: i64,
            before: Option<&Self>,
            after: Option<&Self>,
        ) -> Result<(), HttpResponse>
        where
            E: #runtime_crate::db::DbExecutor + ?Sized,
        {
            let payload_json = Self::audit_payload_json(before, after)?;
            let actor_roles_json = #runtime_crate::serde_json::to_string(&user.roles)
                .map_err(|error| {
                    #runtime_crate::core::errors::internal_error(error.to_string())
                })?;
            let sql = format!(
                "INSERT INTO {} (event_kind, resource_name, record_id, actor_user_id, actor_roles_json, payload_json) VALUES ({}, {}, {}, {}, {}, {})",
                #sink_table,
                Self::list_placeholder(1),
                Self::list_placeholder(2),
                Self::list_placeholder(3),
                Self::list_placeholder(4),
                Self::list_placeholder(5),
                Self::list_placeholder(6),
            );
            #runtime_crate::db::query(&sql)
                .bind(event_kind)
                .bind(#resource_name)
                .bind(record_id)
                .bind(Self::audit_actor_user_id(user))
                .bind(actor_roles_json)
                .bind(payload_json)
                .execute(executor)
                .await
                .map_err(|error| {
                    #runtime_crate::core::errors::internal_error(error.to_string())
                })?;
            Ok(())
        }
    }
}
