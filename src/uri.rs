//! URI and local file path normalization helpers.

/// Percent-decode a UTF-8 URI component.
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Normalize a `file://` URI or local path into a clean filesystem path.
/// Returns `None` for non-file URIs (e.g. `http://`, `about:`, `applications:`).
pub fn normalize_file_uri(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(rest) = trimmed.strip_prefix("file://") {
        let path_part = if let Some(after_host) = rest.strip_prefix("localhost/") {
            format!("/{after_host}")
        } else if rest.starts_with('/') {
            rest.to_string()
        } else {
            return None;
        };
        let decoded = percent_decode(&path_part);
        if decoded.starts_with('/') {
            return Some(decoded);
        }
        return None;
    }

    if trimmed.starts_with('/') {
        return Some(trimmed.to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_file_uris_and_filters_non_files() {
        assert_eq!(
            normalize_file_uri("file:///var/home/silver/My%20Doc.pdf").as_deref(),
            Some("/var/home/silver/My Doc.pdf")
        );
        assert_eq!(
            normalize_file_uri("file://localhost/tmp/test.txt").as_deref(),
            Some("/tmp/test.txt")
        );
        assert_eq!(
            normalize_file_uri("/home/silver/notes.md").as_deref(),
            Some("/home/silver/notes.md")
        );
        assert_eq!(normalize_file_uri("https://example.com"), None);
        assert_eq!(normalize_file_uri("applications:org.kde.kate.desktop"), None);
    }
}
