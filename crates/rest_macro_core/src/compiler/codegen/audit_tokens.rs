//! Audit helper token generation shared by CRUD and resource-action handlers.

use proc_macro2::{Literal, TokenStream};
use quote::quote;
use syn::Path;

use super::super::model::ResourceSpec;
use super::list_bind_type;

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
    let list_bind_ty = list_bind_type(resource);

    quote! {
        async fn fetch_unfiltered_by_id_for_audit<E>(
            id: i64,
            executor: &E,
        ) -> Result<Option<Self>, String>
        where
            E: #runtime_crate::vsr_runtime::typed_read::TypedItemReadExecutor<Self> + ?Sized,
        {
            let sql = format!(
                "SELECT * FROM {} WHERE {} = {}",
                #table_name,
                #id_field,
                Self::list_placeholder(1),
            );
            Self::execute_item_query(executor, &sql, vec![#list_bind_ty::Integer(id)]).await
        }

        fn audit_actor_user_id(user: &#runtime_crate::core::auth::UserContext) -> Option<i64> {
            (user.id != 0).then_some(user.id)
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
            E: #runtime_crate::vsr_runtime::statement::StatementExecutor + ?Sized,
        {
            let before = before
                .map(|item| Self::serialize_item_value(item, None))
                .transpose()?;
            let after = after
                .map(|item| Self::serialize_item_value(item, None))
                .transpose()?;
            let plan = #runtime_crate::vsr_runtime::audit::write::plan_audit_insert(
                #runtime_crate::vsr_runtime::audit::write::AuditInsert {
                    sink_table: #sink_table,
                    resource_name: #resource_name,
                    event_kind,
                    record_id,
                    actor_user_id: Self::audit_actor_user_id(user),
                    actor_roles: &user.roles,
                    before: before.as_ref(),
                    after: after.as_ref(),
                },
                Self::list_placeholder,
            )
            .map_err(|error| #runtime_crate::core::errors::internal_error(error.to_string()))?;
            let mut statement = #runtime_crate::vsr_runtime::statement::Statement::new(&plan.sql);
            for bind in plan.binds {
                statement = statement.bind(bind);
            }
            statement
                .execute(executor)
                .await
                .map_err(|error| {
                    #runtime_crate::core::errors::internal_error(error.to_string())
                })?;
            Ok(())
        }
    }
}
