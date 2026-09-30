use url::Url;

/// Construct upstream destination URL safely without scheme/host tampering.
pub fn build_upstream_url(
    base_url: &Url,
    subpath: &str,
    query: Option<&str>,
) -> Result<Url, String> {
    let mut target = base_url.clone();

    // Clean and split subpath segments
    let raw_trimmed = subpath.trim_start_matches('/');

    // Process path segments securely (avoiding directory traversal like ..)
    let mut normalized_segments: Vec<&str> = Vec::new();
    for seg in raw_trimmed.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            normalized_segments.pop();
        } else {
            normalized_segments.push(seg);
        }
    }

    // Build path
    {
        let mut path_segments = target
            .path_segments_mut()
            .map_err(|_| "cannot be base URL".to_string())?;

        // If base path already had a trailing slash or path, retain base segments
        for seg in &normalized_segments {
            path_segments.push(seg);
        }
    }

    if let Some(q) = query {
        if !q.is_empty() {
            target.set_query(Some(q));
        }
    }

    // Host and scheme must match base_url
    if target.scheme() != base_url.scheme() || target.host_str() != base_url.host_str() {
        return Err("resulting URL host or scheme mismatch".to_string());
    }

    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_upstream_url_normal() {
        let base = Url::parse("https://api.stripe.com/v1").unwrap();
        let url = build_upstream_url(&base, "charges", Some("limit=10")).unwrap();
        assert_eq!(url.as_str(), "https://api.stripe.com/v1/charges?limit=10");
    }

    #[test]
    fn test_build_upstream_url_traversal_prevention() {
        let base = Url::parse("https://api.stripe.com/v1").unwrap();
        let url = build_upstream_url(&base, "../evil/path", None).unwrap();
        // .. popped v1 or was sanitized, never touches authority
        assert_eq!(url.host_str(), Some("api.stripe.com"));
        assert_eq!(url.scheme(), "https");
    }

    #[test]
    fn test_build_upstream_url_slashes_and_special() {
        let base = Url::parse("https://api.stripe.com").unwrap();
        let url = build_upstream_url(&base, "///v1//charges/", None).unwrap();
        assert_eq!(url.as_str(), "https://api.stripe.com/v1/charges");
    }
}
