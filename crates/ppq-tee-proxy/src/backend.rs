//! The operations the HTTP layer needs from the sealed channel, as a trait so
//! the server can be driven by a fake in tests instead of a live enclave.

use bytes::Bytes;
use futures::stream::BoxStream;
use futures::StreamExt;
use ppq_tee::{PpqClient, PrivateModel, Result};
use serde_json::Value;
use std::future::Future;

/// Decrypted server-sent-event bytes, exactly as the enclave produced them.
pub type SseStream = BoxStream<'static, Result<Bytes>>;

pub trait SealedClient: Send + Sync + 'static {
    fn list_models(&self) -> impl Future<Output = Result<Vec<PrivateModel>>> + Send;

    fn chat_completion(&self, body: Value) -> impl Future<Output = Result<Value>> + Send;

    /// The `Err` here arrives before any stream exists; once a stream is
    /// returned, its own items carry mid-stream failures.
    fn chat_completion_stream(&self, body: Value)
        -> impl Future<Output = Result<SseStream>> + Send;
}

impl SealedClient for PpqClient {
    async fn list_models(&self) -> Result<Vec<PrivateModel>> {
        PpqClient::list_models(self).await
    }

    async fn chat_completion(&self, body: Value) -> Result<Value> {
        PpqClient::chat_completion(self, body).await
    }

    async fn chat_completion_stream(&self, body: Value) -> Result<SseStream> {
        Ok(PpqClient::chat_completion_stream(self, body).await?.boxed())
    }
}
