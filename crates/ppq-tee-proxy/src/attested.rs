//! Keeps a sealed client bound to a *current* enclave key.
//!
//! `PpqClient` attests once and is then bound to that key forever. A daemon
//! runs for weeks and the enclave key changes whenever Tinfoil redeploys, so
//! the proxy re-attests: on a timer, and on the first unauthenticated failure
//! after a stale key would start being rejected.

use crate::backend::{SealedClient, SseStream};
use futures::future::BoxFuture;
use ppq_tee::{Error, PrivateModel, Result};
use serde_json::Value;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::Instant;

/// When to throw a verified client away and attest the enclave again.
#[derive(Debug, Clone, Copy)]
pub struct ReattestPolicy {
    /// A client older than this is replaced before its next use, whether or
    /// not it has failed.
    pub reattest_after: Duration,
    /// An unauthenticated failure triggers re-attestation only if the client
    /// is at least this old, so a persistent unrelated failure (a revoked API
    /// key, an outage) cannot turn every request into a full attestation.
    pub min_reattest_interval: Duration,
}

impl Default for ReattestPolicy {
    fn default() -> Self {
        Self {
            reattest_after: Duration::from_secs(60 * 60),
            min_reattest_interval: Duration::from_secs(30),
        }
    }
}

/// Attests the enclave and builds a client bound to what it proved.
pub type Attester<C> = Box<dyn Fn() -> BoxFuture<'static, Result<C>> + Send + Sync>;

pub struct Attested<C> {
    attest: Attester<C>,
    policy: ReattestPolicy,
    /// `None` only between a failed refresh and the next attempt: a client
    /// whose key is known to be rejected is never kept around to be reused.
    cached: RwLock<Option<Cached<C>>>,
}

struct Cached<C> {
    attested_at: Instant,
    client: Arc<C>,
}

impl<C> Clone for Cached<C> {
    fn clone(&self) -> Self {
        Self {
            attested_at: self.attested_at,
            client: Arc::clone(&self.client),
        }
    }
}

impl<C: SealedClient> Attested<C> {
    /// Attests eagerly, so a misconfiguration fails startup rather than the
    /// first request.
    pub async fn new(attest: Attester<C>, policy: ReattestPolicy) -> Result<Self> {
        let client = attest().await?;
        Ok(Self {
            attest,
            policy,
            cached: RwLock::new(Some(Cached {
                attested_at: Instant::now(),
                client: Arc::new(client),
            })),
        })
    }

    /// The current client, attesting first if the cached one has aged out.
    async fn current(&self) -> Result<Cached<C>> {
        if let Some(c) = self.cached.read().await.as_ref() {
            if c.attested_at.elapsed() < self.policy.reattest_after {
                return Ok(c.clone());
            }
        }
        self.replace(None).await
    }

    /// Attest again and cache the result. `stale` is the client the caller
    /// found wanting; if another task has already replaced it, that
    /// replacement is returned without attesting a second time.
    ///
    /// The write lock is deliberately held across the attestation: it is what
    /// turns a burst of concurrent failures into one attestation instead of
    /// one per request. Readers block for the duration, which is what they
    /// want — their cached client is the one being replaced.
    async fn replace(&self, stale: Option<&Arc<C>>) -> Result<Cached<C>> {
        let mut slot = self.cached.write().await;
        if let (Some(current), Some(stale)) = (slot.as_ref(), stale) {
            if !Arc::ptr_eq(&current.client, stale) {
                return Ok(current.clone());
            }
        }
        // Drop the old client before attesting so a failed attestation can
        // never leave a known-bad client in the cache.
        *slot = None;
        let client = (self.attest)().await?;
        let fresh = Cached {
            attested_at: Instant::now(),
            client: Arc::new(client),
        };
        *slot = Some(fresh.clone());
        Ok(fresh)
    }

    /// Run `op`, and on an unauthenticated failure re-attest and run it once
    /// more. Never more than one retry: the second failure is the answer.
    async fn with_reattest<T, F, Fut>(&self, op: F) -> Result<T>
    where
        F: Fn(Arc<C>) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let cached = self.current().await?;
        let err = match op(Arc::clone(&cached.client)).await {
            Ok(v) => return Ok(v),
            Err(e) => e,
        };
        if !warrants_reattest(&err)
            || cached.attested_at.elapsed() < self.policy.min_reattest_interval
        {
            return Err(err);
        }
        tracing::warn!(error = %err, "unauthenticated upstream failure; re-attesting the enclave");
        let fresh = self.replace(Some(&cached.client)).await?;
        op(fresh.client).await
    }
}

/// Only failures the enclave did *not* authenticate can be a stale-key
/// symptom. An `Enclave` error is signed enclave output and retrying it would
/// resend a request the enclave already answered.
fn warrants_reattest(err: &Error) -> bool {
    match err {
        Error::Http(_)
        | Error::Ehbp(_)
        | Error::UnauthenticatedUpstream { .. }
        | Error::Attestation(_) => true,
        Error::Enclave { .. } | Error::Json(_) | Error::InvalidModelId(_) => false,
    }
}

impl<C: SealedClient> SealedClient for Attested<C> {
    async fn list_models(&self) -> Result<Vec<PrivateModel>> {
        self.with_reattest(|c| async move { c.list_models().await })
            .await
    }

    async fn chat_completion(&self, body: Value) -> Result<Value> {
        self.with_reattest(|c| {
            let body = body.clone();
            async move { c.chat_completion(body).await }
        })
        .await
    }

    async fn chat_completion_stream(&self, body: Value) -> Result<SseStream> {
        self.with_reattest(|c| {
            let body = body.clone();
            async move { c.chat_completion_stream(body).await }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A client that answers with its own generation number, or with a
    /// scripted error for its first `failures` calls.
    struct Fake {
        generation: usize,
        failures: AtomicUsize,
        error: fn() -> Error,
    }

    impl SealedClient for Fake {
        async fn list_models(&self) -> Result<Vec<PrivateModel>> {
            unimplemented!("not exercised")
        }
        async fn chat_completion(&self, _body: Value) -> Result<Value> {
            if self
                .failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                return Err((self.error)());
            }
            Ok(Value::from(self.generation))
        }
        async fn chat_completion_stream(&self, _body: Value) -> Result<SseStream> {
            unimplemented!("not exercised")
        }
    }

    fn unauthenticated() -> Error {
        Error::UnauthenticatedUpstream {
            status: 400,
            body: "bad key".into(),
        }
    }

    fn enclave() -> Error {
        Error::Enclave {
            status: 429,
            body: "slow down".into(),
        }
    }

    /// Every attestation yields a client of the next generation. The first
    /// generation fails its first `failures` calls with `error`; later ones
    /// never fail. Returns the attester and a count of attestations performed.
    fn attester(failures: usize, error: fn() -> Error) -> (Attester<Fake>, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&count);
        let attest: Attester<Fake> = Box::new(move || {
            let generation = c.fetch_add(1, Ordering::SeqCst) + 1;
            Box::pin(async move {
                Ok(Fake {
                    generation,
                    failures: AtomicUsize::new(if generation == 1 { failures } else { 0 }),
                    error,
                })
            })
        });
        (attest, count)
    }

    fn policy() -> ReattestPolicy {
        ReattestPolicy {
            reattest_after: Duration::from_secs(3600),
            min_reattest_interval: Duration::from_secs(30),
        }
    }

    async fn complete(a: &Attested<Fake>) -> Result<Value> {
        a.chat_completion(Value::Null).await
    }

    #[tokio::test(start_paused = true)]
    async fn attests_once_at_construction_and_reuses_a_fresh_client() {
        let (attest, count) = attester(0, unauthenticated);
        let a = Attested::new(attest, policy()).await.unwrap();
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "construction attests eagerly"
        );
        for _ in 0..3 {
            assert_eq!(complete(&a).await.unwrap(), 1);
        }
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "a fresh client is never re-attested"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn reattests_after_the_client_ages_out() {
        let (attest, count) = attester(0, unauthenticated);
        let a = Attested::new(attest, policy()).await.unwrap();
        tokio::time::advance(Duration::from_secs(3600)).await;
        assert_eq!(
            complete(&a).await.unwrap(),
            2,
            "an aged-out client is replaced before use"
        );
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn an_unauthenticated_failure_reattests_and_retries_once() {
        let (attest, count) = attester(1, unauthenticated);
        let a = Attested::new(attest, policy()).await.unwrap();
        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(complete(&a).await.unwrap(), 2);
        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "exactly one re-attestation"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_failure_inside_the_interval_is_returned_not_retried() {
        let (attest, count) = attester(2, unauthenticated);
        let a = Attested::new(attest, policy()).await.unwrap();
        // Younger than min_reattest_interval: the failure is the answer.
        let err = complete(&a).await.unwrap_err();
        assert!(
            matches!(err, Error::UnauthenticatedUpstream { .. }),
            "got {err}"
        );
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "no re-attestation inside the interval"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_enclave_error_is_never_retried() {
        let (attest, count) = attester(1, enclave);
        let a = Attested::new(attest, policy()).await.unwrap();
        tokio::time::advance(Duration::from_secs(3599)).await;
        let err = complete(&a).await.unwrap_err();
        assert!(
            matches!(err, Error::Enclave { status: 429, .. }),
            "got {err}"
        );
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "authenticated enclave output is final"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_reattestation_leaves_no_client_behind() {
        let count = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&count);
        let attest: Attester<Fake> = Box::new(move || {
            let n = c.fetch_add(1, Ordering::SeqCst) + 1;
            Box::pin(async move {
                match n {
                    1 => Ok(Fake {
                        generation: 1,
                        failures: AtomicUsize::new(usize::MAX),
                        error: unauthenticated,
                    }),
                    2 => Err(Error::Attestation("rekor unreachable".into())),
                    _ => Ok(Fake {
                        generation: n,
                        failures: AtomicUsize::new(0),
                        error: unauthenticated,
                    }),
                }
            })
        });
        let a = Attested::new(attest, policy()).await.unwrap();
        tokio::time::advance(Duration::from_secs(31)).await;
        let err = complete(&a).await.unwrap_err();
        assert!(matches!(err, Error::Attestation(_)), "got {err}");
        // The next request must not reuse generation 1 (whose key is known
        // bad); it attests afresh and succeeds on generation 3.
        assert_eq!(complete(&a).await.unwrap(), 3);
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }
}
