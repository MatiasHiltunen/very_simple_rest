use crate::db::DbPool;

use super::db_ops::{
    auth_token_is_expired, delete_auth_token_by_id, delete_auth_tokens_for_user_purpose,
    detect_auth_backend, load_pending_auth_token, mark_auth_token_used, mark_user_email_verified,
    update_user_password,
};
use super::helpers::now_timestamp_string;
use super::user::AuthTokenPurpose;

pub(crate) enum TokenActionOutcome {
    Applied,
    Invalid,
    Expired,
}

pub(crate) async fn apply_email_verification_token(
    db: &DbPool,
    raw_token: &str,
) -> Result<TokenActionOutcome, sqlx::Error> {
    let backend = detect_auth_backend(db).await?;
    let tx = db.begin().await?;
    let Some(token) =
        load_pending_auth_token(&tx, raw_token, AuthTokenPurpose::EmailVerification).await?
    else {
        tx.rollback().await?;
        return Ok(TokenActionOutcome::Invalid);
    };
    if auth_token_is_expired(&token) {
        delete_auth_token_by_id(&tx, token.id).await?;
        tx.commit().await?;
        return Ok(TokenActionOutcome::Expired);
    }

    let now = now_timestamp_string();
    mark_user_email_verified(&tx, backend, token.user_id, &now).await?;
    mark_auth_token_used(&tx, token.id, &now).await?;
    delete_auth_tokens_for_user_purpose(&tx, token.user_id, AuthTokenPurpose::EmailVerification)
        .await?;
    tx.commit().await?;
    Ok(TokenActionOutcome::Applied)
}

pub(crate) async fn apply_password_reset_token(
    db: &DbPool,
    raw_token: &str,
    password_hash: &str,
) -> Result<TokenActionOutcome, sqlx::Error> {
    let backend = detect_auth_backend(db).await?;
    let tx = db.begin().await?;
    let Some(token) =
        load_pending_auth_token(&tx, raw_token, AuthTokenPurpose::PasswordReset).await?
    else {
        tx.rollback().await?;
        return Ok(TokenActionOutcome::Invalid);
    };
    if auth_token_is_expired(&token) {
        delete_auth_token_by_id(&tx, token.id).await?;
        tx.commit().await?;
        return Ok(TokenActionOutcome::Expired);
    }

    let now = now_timestamp_string();
    update_user_password(&tx, backend, token.user_id, password_hash, &now).await?;
    mark_auth_token_used(&tx, token.id, &now).await?;
    delete_auth_tokens_for_user_purpose(&tx, token.user_id, AuthTokenPurpose::PasswordReset)
        .await?;
    tx.commit().await?;
    Ok(TokenActionOutcome::Applied)
}
