//! Bounded bcrypt work shared by native, generated and neutral HTTP handlers.

use super::request::AuthFailure;
use std::sync::{Arc, OnceLock};
use tokio::sync::Semaphore;

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
) -> Result<T, AuthFailure> {
    let runtime = tokio::runtime::Handle::try_current().map_err(|_| AuthFailure::PasswordWorker)?;
    let permit = workers.try_acquire_owned().map_err(|_| AuthFailure::Busy)?;
    // A started blocking task cannot be aborted. Hold its permit inside the job,
    // so cancelling the request never admits excess password work.
    runtime
        .spawn_blocking(move || {
            let _permit = permit;
            work()
        })
        .await
        .map_err(|_| AuthFailure::PasswordWorker)?
        .map_err(|_| AuthFailure::PasswordOperation)
}

/// Hash without blocking executor threads or queuing unbounded work.
pub async fn hash(password: &str, cost: u32) -> Result<String, AuthFailure> {
    let password = password.to_owned();
    run(workers().clone(), move || bcrypt::hash(password, cost)).await
}

/// Verify on the same bounded worker pool used by hashing.
pub async fn verify(password: &str, hash: &str) -> Result<bool, AuthFailure> {
    let password = password.to_owned();
    let hash = hash.to_owned();
    run(workers().clone(), move || bcrypt::verify(password, &hash)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn worker_is_bounded_even_after_cancellation() {
        let workers = Arc::new(Semaphore::new(1));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = std::sync::mpsc::channel();
        let task = tokio::spawn(run(workers.clone(), move || {
            started_tx.send(()).unwrap();
            finish_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            Ok(())
        }));
        started_rx.await.unwrap();
        assert_eq!(
            run(workers.clone(), || Ok(())).await.unwrap_err(),
            AuthFailure::Busy
        );
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(workers.available_permits(), 0);
        finish_tx.send(()).unwrap();
        let permit = tokio::time::timeout(std::time::Duration::from_secs(5), workers.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(permit);
        assert_eq!(run(workers, || Ok(7)).await.unwrap(), 7);
    }

    #[tokio::test]
    async fn hash_verify_and_errors() {
        let hash = hash("a-test-password", 4).await.unwrap();
        assert!(verify("a-test-password", &hash).await.unwrap());
        assert!(!verify("wrong-password", &hash).await.unwrap());
        assert_eq!(
            verify("password", "invalid-hash").await.unwrap_err(),
            AuthFailure::PasswordOperation
        );
    }
}
