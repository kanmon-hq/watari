use crate::error::AppError;
use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;

/// Verify X-Gateway-Secret header using constant-time comparison with primary and optional previous secrets.
pub fn verify_gateway_auth(
    header_value: Option<&str>,
    primary_secret: Option<&SecretString>,
    previous_secret: Option<&SecretString>,
    insecure_no_gateway_auth: bool,
) -> Result<(), AppError> {
    if insecure_no_gateway_auth {
        return Ok(());
    }

    let raw = match header_value {
        Some(v) => v,
        None => return Err(AppError::Unauthorized),
    };

    let actual_bytes = raw.as_bytes();

    if let Some(primary) = primary_secret {
        let expected_bytes = primary.expose_secret().as_bytes();
        if expected_bytes.len() == actual_bytes.len() && expected_bytes.ct_eq(actual_bytes).into() {
            return Ok(());
        }
    }

    if let Some(previous) = previous_secret {
        let expected_bytes = previous.expose_secret().as_bytes();
        if expected_bytes.len() == actual_bytes.len() && expected_bytes.ct_eq(actual_bytes).into() {
            return Ok(());
        }
    }

    Err(AppError::Unauthorized)
}

/// Verify X-Gateway-Secret with a single expected secret (backward compatibility helper).
pub fn verify_gateway_secret(
    header_value: Option<&str>,
    expected_secret: &SecretString,
) -> Result<(), AppError> {
    verify_gateway_auth(header_value, Some(expected_secret), None, false)
}

/// Verify Admin API Key using constant-time comparison.
pub fn verify_admin_key(
    header_value: Option<&str>,
    admin_api_key: Option<&SecretString>,
) -> Result<(), AppError> {
    let expected_key = match admin_api_key {
        Some(k) => k,
        None => return Err(AppError::Unauthorized),
    };

    let raw = match header_value {
        Some(v) => {
            if let Some(token) = v.strip_prefix("Bearer ") {
                token.trim()
            } else {
                v.trim()
            }
        }
        None => return Err(AppError::Unauthorized),
    };

    let expected_bytes = expected_key.expose_secret().as_bytes();
    let actual_bytes = raw.as_bytes();

    if expected_bytes.len() == actual_bytes.len() && expected_bytes.ct_eq(actual_bytes).into() {
        Ok(())
    } else {
        Err(AppError::Unauthorized)
    }
}
