//! Drive a TEE-backed model through `rig-core`, with every request body
//! HPKE-sealed to the key the enclave's hardware proved.
//!
//! Run with:
//!   PPQ_API_KEY=sk-... cargo run -p ppq-tee --features rig --example rig_agent
//!
//! `PpqCompletionModel` is an ordinary `rig_core::completion::CompletionModel`,
//! so anything rig can drive with one works here unchanged. Agents live in the
//! separate `rig-agent` crate as of 0.41 — not depended on here, so that
//! `ppq-tee` stays a provider crate — but wrapping this model in one is two
//! lines:
//!
//! ```ignore
//! let agent = rig_agent::agent::AgentBuilder::new(ppq.completion_model("private/glm-5-2")?)
//!     .preamble("You are concise.")
//!     .build();
//! println!("{}", agent.prompt("Name three prime numbers.").await?);
//! ```

use ppq_tee::PpqClient;
use rig_core::completion::CompletionModel;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Attestation happens exactly once, here. Everything after it is sealed to
    // the key this proved.
    let ppq = PpqClient::builder()
        .api_key(std::env::var("PPQ_API_KEY")?)
        .build()
        .await?;

    println!(
        "attested enclave {}, measurement {}",
        ppq.attestation().domain,
        hex::encode(&ppq.attestation().measurement[..8]),
    );

    let model = ppq.completion_model("private/glm-5-2")?;

    let response = model
        .completion_request("Name three prime numbers.")
        .preamble("You are concise.".to_string())
        // glm-5-2 is a reasoning model: it spends tokens before it emits any
        // content, so too small a budget answers with `content: null`.
        .max_tokens(512)
        .send()
        .await?;

    for content in response.choice.iter() {
        if let rig_core::completion::AssistantContent::Text(text) = content {
            println!("{}", text.text);
        }
    }

    Ok(())
}
