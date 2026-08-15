//! PPQ's model catalogue, filtered down to the TEE-backed models.

use crate::Result;
use serde::Deserialize;

/// A TEE-backed model from PPQ's catalogue.
#[derive(Debug, Clone)]
pub struct PrivateModel {
    /// User-facing id, e.g. `private/glm-5-2`.
    pub id: String,
    pub name: String,
    pub context_length: u32,
    pub pricing: Pricing,
}

#[derive(Debug, Clone)]
pub struct Pricing {
    pub input_per_1m: f64,
    pub output_per_1m: f64,
    pub currency: String,
}

#[derive(Deserialize)]
struct Catalogue {
    data: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    context_length: u32,
    #[serde(rename = "privacyLevel", default)]
    privacy_level: String,
    #[serde(default)]
    pricing: Option<RawPricing>,
}

#[derive(Deserialize)]
struct RawPricing {
    #[serde(default)]
    currency: String,
    #[serde(rename = "input_per_1M_tokens", default)]
    input: f64,
    #[serde(rename = "output_per_1M_tokens", default)]
    output: f64,
}

/// Keep only the end-to-end encrypted (TEE) models.
pub fn parse_private(json: &str) -> Result<Vec<PrivateModel>> {
    let c: Catalogue = serde_json::from_str(json)?;
    Ok(c.data
        .into_iter()
        .filter(|e| e.privacy_level == "e2e")
        .map(|e| {
            let p = e.pricing.unwrap_or(RawPricing {
                currency: "USD".into(),
                input: 0.0,
                output: 0.0,
            });
            PrivateModel {
                id: e.id,
                name: e.name,
                context_length: e.context_length,
                pricing: Pricing {
                    input_per_1m: p.input,
                    output_per_1m: p.output,
                    currency: p.currency,
                },
            }
        })
        .collect())
}

/// Strip the `private/` prefix to get the id the enclave expects in the body.
///
/// This is a mechanical rule that holds for every TEE model; there is
/// deliberately no lookup table to drift out of date.
pub fn enclave_model_id(id: &str) -> &str {
    id.strip_prefix("private/").unwrap_or(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_only_e2e_models() {
        let json = r#"{"data":[
            {"id":"gemini-3.7-flash","privacyLevel":"anon","context_length":1},
            {"id":"z-ai/glm-5.2","privacyLevel":"zdr","context_length":2},
            {"id":"private/glm-5-2","name":"GLM 5.2 (Private via TEE)",
             "privacyLevel":"e2e","context_length":384000,
             "pricing":{"currency":"USD","input_per_1M_tokens":1.5,"output_per_1M_tokens":3.0}}
        ]}"#;
        let m = parse_private(json).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].id, "private/glm-5-2");
        assert_eq!(m[0].context_length, 384000);
        assert_eq!(m[0].pricing.output_per_1m, 3.0);
    }

    #[test]
    fn tolerates_e2e_entries_without_pricing() {
        let json = r#"{"data":[{"id":"private/x","privacyLevel":"e2e"}]}"#;
        assert_eq!(parse_private(json).unwrap().len(), 1);
    }

    #[test]
    fn strips_the_private_prefix() {
        assert_eq!(enclave_model_id("private/glm-5-2"), "glm-5-2");
        assert_eq!(enclave_model_id("private/kimi-k3"), "kimi-k3");
        assert_eq!(enclave_model_id("glm-5-2"), "glm-5-2");
    }
}
