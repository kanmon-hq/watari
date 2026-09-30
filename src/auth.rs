use crate::error::AppError;
use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;

/// Verify X-Gateway-Secret header using constant-time comparison.
pub fn verify_gateway_secret(
    header_value: Option<&str>,
    expected_secret: &SecretString,
) -> Result<(), AppError> {
    let raw = match header_value {
        Some(v) => v,
        None => return Err(AppError::Unauthorized),
    };

    let expected_bytes = expected_secret.expose_secret().as_bytes();
    let actual_bytes = raw.as_bytes();

    if expected_bytes.len() != actual_bytes.len() {
        return Err(AppError::Unauthorized);
    }

    if expected_bytes.ct_eq(actual_bytes).into() {
        Ok(())
    } else {
        Err(AppError::Unauthorized)
    }
}
