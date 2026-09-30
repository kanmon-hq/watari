use super::SecretStore;
use crate::error::SecretError;
use crate::storage::SecretVersion;
use async_trait::async_trait;
use aws_sdk_secretsmanager::Client;
use secrecy::SecretString;

/// AWS Secrets Manager backend for SecretStore.
#[derive(Debug, Clone)]
pub struct AwsSecretStore {
    client: Client,
}

impl AwsSecretStore {
    pub async fn new() -> Self {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = Client::new(&config);
        Self { client }
    }

    pub fn with_client(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl SecretStore for AwsSecretStore {
    async fn get(
        &self,
        reference: &str,
        version: &SecretVersion,
    ) -> Result<SecretString, SecretError> {
        let mut req = self.client.get_secret_value().secret_id(reference);

        if let SecretVersion::Id(ver_id) = version {
            req = req.version_id(ver_id);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("AWS Secrets Manager error: {e}")))?;

        if let Some(secret_val) = resp.secret_string() {
            Ok(SecretString::new(secret_val.to_string().into()))
        } else {
            Err(SecretError::NotFound(format!(
                "secret '{reference}' does not contain a string value"
            )))
        }
    }
}
