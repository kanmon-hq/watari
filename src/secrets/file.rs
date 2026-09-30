use super::SecretStore;
use crate::error::SecretError;
use crate::storage::SecretVersion;
use async_trait::async_trait;
use secrecy::SecretString;
use std::path::{Path, PathBuf};

/// SecretStore backed by files on local disk.
#[derive(Debug, Clone)]
pub struct FileSecretStore {
    base_dir: PathBuf,
}

impl FileSecretStore {
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Self {
        Self {
            base_dir: base_dir.as_ref().to_path_buf(),
        }
    }
}

#[async_trait]
impl SecretStore for FileSecretStore {
    async fn get(
        &self,
        reference: &str,
        _version: &SecretVersion,
    ) -> Result<SecretString, SecretError> {
        // Prevent path traversal
        if reference.contains("..") || reference.contains('/') || reference.contains('\\') {
            return Err(SecretError::NotFound(format!(
                "invalid secret reference '{reference}'"
            )));
        }

        let file_path = self.base_dir.join(reference);
        match tokio::fs::read_to_string(&file_path).await {
            Ok(content) => {
                let trimmed = content.trim_end_matches(&['\r', '\n'][..]);
                if trimmed.is_empty() {
                    Err(SecretError::NotFound(format!(
                        "secret file '{reference}' is empty"
                    )))
                } else {
                    Ok(SecretString::new(trimmed.to_string().into()))
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(SecretError::NotFound(
                format!("secret file '{reference}' not found"),
            )),
            Err(e) => Err(SecretError::Backend(format!(
                "failed to read secret file '{reference}': {e}"
            ))),
        }
    }
}
