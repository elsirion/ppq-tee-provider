# ppq-tee-proxy: a local OpenAI-compatible proxy over the attested channel

**Date:** 2026-09-22
**Status:** approved for implementation (built autonomously; assumptions listed at the end)

## Goal

A small daemon that runs on the user's machine, speaks the OpenAI HTTP API on
localhost, and forwards every chat completion through `ppq-tee`'s attested,
HPKE-sealed channel to PPQ.AI's TEE models. Any OpenAI-compatible client
(openai SDKs, aider, Open WebUI, `llm`, editors) can then use the TEE models by
pointing its base URL at the proxy. It is packaged and deployed with Nix: a
flake package for `nix run`, and a NixOS module that runs it as a hardened
systemd service.

## Non-goals

- Anything beyond chat completions and model discovery (no embeddings,
  images, files). The enclave only serves chat completions.
- Client authentication on the proxy. It binds to `127.0.0.1` by default and
  is for one machine; anyone who wants it on a LAN can bind it elsewhere and
  put their own auth in front.
- A home-manager or nix-darwin module. NixOS only, for now.

## Endpoints

| Method | Path | Behaviour |
| --- | --- | --- |
| `GET` | `/v1/models` | OpenAI list object of the TEE-backed (`e2e`) models from PPQ's catalogue. |
| `GET` | `/v1/models/{id}` | One model object, or an OpenAI-format 404. |
| `POST` | `/v1/chat/completions` | Forwarded through the sealed channel. `"stream": true` yields `text/event-stream`; otherwise the decrypted JSON body. |

`GET /v1/models` **is** the OpenAI standard for model discovery, so nothing
proprietary is added. Each entry is `{"id", "object": "model", "created",
"owned_by"}` plus three extension fields clients ignore but humans find
useful: `name`, `context_length`, `pricing`. `created` is `0`: PPQ's catalogue
carries no creation time and the field is required by the schema.

The model list is discovery metadata only, not a trust input (see the crate's
security model). The proxy does not validate request model ids against it; an
unknown id is relayed and rejected by the enclave.

## Components

All in a new workspace crate `crates/ppq-tee-proxy` (binary `ppq-tee-proxy`).

### `SealedClient` trait (`src/backend.rs`)

The three operations the HTTP layer needs, as a trait so the server can be
tested without a network or an enclave:

```rust
pub trait SealedClient: Send + Sync + 'static {
    fn list_models(&self) -> impl Future<Output = ppq_tee::Result<Vec<PrivateModel>>> + Send;
    fn chat_completion(&self, body: Value) -> impl Future<Output = ppq_tee::Result<Value>> + Send;
    fn chat_completion_stream(&self, body: Value)
        -> impl Future<Output = ppq_tee::Result<BoxStream<'static, ppq_tee::Result<Bytes>>>> + Send;
}
```

Implemented for `ppq_tee::PpqClient` (thin delegation) and for
`Attested<C>` below.

### `Attested<C>` (`src/attested.rs`) — re-attestation policy

`PpqClient` attests once at construction and is then bound to that enclave
key. A daemon runs for weeks, and the enclave's HPKE key changes whenever
Tinfoil redeploys, so the proxy needs to re-attest. `Attested<C>` wraps an
attest-and-build closure (`Fn() -> Future<Result<C>>`) and a
`RwLock<Option<(Instant, Arc<C>)>>`:

- **Lazy, time-bounded.** A request uses the cached client if it is younger
  than `reattest_after` (default 1h); otherwise it attests first. Startup
  attests eagerly so a misconfiguration fails the service, not the first
  request.
- **Error-triggered, rate-limited.** If a request fails with anything the
  enclave did *not* authenticate (`Http`, `Ehbp`, `UnauthenticatedUpstream`,
  `Attestation`) and the cached client is older than `min_reattest_interval`
  (30s), the cache is dropped, a fresh attestation is made and the request is
  retried once. A stale key therefore costs one failed upstream round-trip,
  not an hour of errors. An unrelated persistent failure (bad API key) costs
  at most one extra attestation per 30s. `Enclave` errors are authenticated
  enclave output and are never retried.
- Streaming requests only retry before any bytes have been sent to the
  client: the `Err` from `chat_completion_stream` arrives before a stream
  exists, and once a stream is handed out it is never retried.
- Concurrent requests during a refresh all wait on one attestation (the
  `RwLock` write guard is held across the build), never a thundering herd.

### HTTP layer (`src/server.rs`)

axum 0.8 router, generic over `Arc<C: SealedClient>` as state:

- Request body limit 16 MiB (chat requests with large contexts or images
  exceed axum's 2 MiB default).
- `POST /v1/chat/completions`: parse as a JSON object; a missing or non-string
  `model` is a 400 in OpenAI error format. `stream` (default false) selects
  the path. Streaming responses are `text/event-stream` with
  `cache-control: no-cache`, the decrypted SSE bytes forwarded as they arrive.
  A mid-stream error aborts the response body (the client sees a truncated
  stream, which is the honest signal) and is logged at `warn`.
- Errors map to OpenAI's `{"error": {"message", "type", "code"}}` shape:
  - `Enclave { status, body }` — forwarded verbatim with its status; it *is*
    the enclave's OpenAI-format error.
  - `UnauthenticatedUpstream` — 502; message names the upstream status and
    says the body is unauthenticated diagnostics.
  - `Http`, `Ehbp`, `Json` — 502.
  - `Attestation` — 503 (the enclave could not be re-verified).
  - `InvalidModelId` — 400.
- Every request logs method, path, status, duration and (for completions)
  the model id at `info`. Never bodies, never the API key.
- Graceful shutdown on SIGTERM/SIGINT so systemd stops are clean.

### Binary (`src/main.rs`)

clap, every flag also settable by environment variable:

| Flag | Env | Default |
| --- | --- | --- |
| `--listen` | `PPQ_PROXY_LISTEN` | `127.0.0.1:8090` |
| `--api-key-file` | `PPQ_API_KEY_FILE` | — (or `PPQ_API_KEY` directly, for `nix run`) |
| `--base-url` | `PPQ_BASE_URL` | `https://api.ppq.ai` |
| `--reattest-after` | `PPQ_REATTEST_AFTER` | `1h` (humantime) |

Startup: read the key (file wins over env; trailing newline trimmed), attest
once, log the attested domain and measurement prefix, then serve.

## Nix

`flake.nix` gains, next to the existing dev shell:

- `packages.default`: `buildRustPackage` on the workspace with
  `cargoLock.lockFile`, building only `-p ppq-tee-proxy`, using the same
  rust-overlay toolchain as the dev shell. rustls-only, so no OpenSSL or
  pkg-config.
- `apps.default`: `nix run . -- --listen ...` with `PPQ_API_KEY` in the env.
- `nixosModules.default`: `services.ppq-tee-proxy` with `enable`, `package`,
  `listenAddress` (`127.0.0.1`), `port` (`8090`), `apiKeyFile` (path outside
  the store, required), `baseUrl`, `reattestAfter`. The service runs as a
  `DynamicUser`, gets the key through `LoadCredential` (so the file can be
  root-only), `Restart=on-failure`, after `network-online.target`, with the
  usual hardening (`ProtectSystem=strict`, `PrivateTmp`, `NoNewPrivileges`,
  `RestrictAddressFamilies=AF_INET AF_INET6`, …).

## Testing

- `attested.rs`: unit tests with a fake client and a counting build closure:
  fresh cache is reused; expired cache re-attests; an unauthenticated error
  after `min_reattest_interval` re-attests and retries exactly once; an
  `Enclave` error never retries; a second failure inside the interval is
  returned without re-attesting.
- `server.rs`: tests drive the router with `tower::ServiceExt::oneshot`
  against a fake `SealedClient`: models list shape, single model and 404,
  non-streaming completion passthrough, streaming completion produces
  `text/event-stream` with the fake's chunks concatenated, 400 on a body
  without `model`, each error variant maps to its status and OpenAI shape.
- `nix build` and `nix flake check` succeed; a live smoke test against
  `api.ppq.ai` with the user's key is left to the user (it spends credit).

## Assumptions made without asking

1. The target is NixOS (a systemd service), not home-manager or nix-darwin.
   The package output works on any Nix host regardless.
2. The proxy holds the single PPQ API key; clients' own `Authorization`
   headers are ignored.
3. Port 8090, localhost only, by default.
