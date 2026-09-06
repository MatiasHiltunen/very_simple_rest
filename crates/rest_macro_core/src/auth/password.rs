use std::sync::{Arc, OnceLock};

use actix_web::{HttpResponse, http::StatusCode};
use tokio::sync::Semaphore;

use crate::errors;

fn workers() -> &'static Arc<Semaphore> {
    static WORKERS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    WORKERS.get_or_init(|| {
        Arc::new(Semaphore::new(
            std::thread::available_parallelism()
                .map_or(1, usize::from)
                .clamp(1, 8),
        ))
    })
}

async fn run<T: Send + 'static>(
    workers: Arc<Semaphore>,
    work: impl FnOnce() -> Result<T, bcrypt::BcryptError> + Send + 'static,
) -> Result<T, HttpResponse> {
    // No unbounded queue. Cancellation must not release a running job's permit.
    let permit = workers.try_acquire_owned().map_err(|_| {
        errors::error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "auth_busy",
            "Authentication is busy; retry later",
        )
    })?;
    actix_web::rt::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .map_err(|_| errors::internal_error("Password worker failed"))?
    .map_err(|_| errors::internal_error("Password operation failed"))
}

pub(super) async fn hash(password: &str, cost: u32) -> Result<String, HttpResponse> {
    let password = password.to_owned();
    run(workers().clone(), move || bcrypt::hash(password, cost)).await
}

pub(super) async fn verify(password: &str, hash: &str) -> Result<bool, HttpResponse> {
    let password = password.to_owned();
    let hash = hash.to_owned();
    run(workers().clone(), move || bcrypt::verify(password, &hash)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_web::test]
    async fn worker_is_bounded_and_does_not_block_runtime() {
        let workers = Arc::new(Semaphore::new(1));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = std::sync::mpsc::channel();
        let task = actix_web::rt::spawn(run(workers.clone(), move || {
            started_tx.send(()).unwrap();
            finish_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            Ok(())
        }));
        started_rx.await.unwrap();
        assert_eq!(
            run(workers.clone(), || Ok(())).await.unwrap_err().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        task.abort();
        assert_eq!(workers.available_permits(), 0);
        finish_tx.send(()).unwrap();
        let permit = workers.acquire().await.unwrap();
        drop(permit);
        assert_eq!(run(workers, || Ok(7)).await.unwrap(), 7);
    }
}
