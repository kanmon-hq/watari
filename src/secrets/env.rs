use super::SecretStore;
use crate::error::SecretError;
use crate::storage::SecretVersion;
use async_trait::async_trait;
use secrecy::SecretString;

/// SecretStore backed by environment variables.
#[derive(Debug, Clone, Default)]
pub struct EnvSecretStore;

impl EnvSecretStore {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl SecretStore for EnvSecretStore {
    async fn get(
        &self,
        reference: &str,
        _version: &SecretVersion,
    ) -> Result<SecretString, SecretError> {
        match std::env::var(reference) {
            Ok(val) => {
                if val.is_empty() {
                    Err(SecretError::NotFound(format!(
                        "environment variable '{reference}' is empty"
                    )))
                } else {
                    Ok(SecretString::new(val.into()))
                }
            }
            Err(std::env::VarError::NotPresent) => Err(SecretError::NotFound(format!(
                "environment variable '{reference}' not found"
            ))),
            Err(e) => Err(SecretError::Backend(format!(
                "failed to read env variable '{reference}': {e}"
            ))),
        }
    }
}
