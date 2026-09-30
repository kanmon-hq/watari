pub mod cached;
pub mod env;
pub mod file;

#[cfg(feature = "aws")]
pub mod aws;

use crate::error::SecretError;
use crate::storage::SecretVersion;
use async_trait::async_trait;
use secrecy::SecretString;

/// Trait for retrieving secrets from various backends.
#[async_trait]
pub trait SecretStore: Send + Sync {
    /// Retrieve a secret by reference and version.
    async fn get(
        &self,
        reference: &str,
        version: &SecretVersion,
    ) -> Result<SecretString, SecretError>;
}
