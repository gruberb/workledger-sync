/// Validate that a string is a valid auth token: hex-encoded SHA-256 (64 hex chars).
/// The auth token is derived client-side as SHA-256("auth:" + syncId).
pub fn is_valid_auth_token(token: &str) -> bool {
    token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_auth_token() {
        // 64 hex chars
        assert!(is_valid_auth_token(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
    }

    #[test]
    fn test_invalid_auth_token() {
        assert!(!is_valid_auth_token("tooshort"));
        // 64 chars but non-hex
        assert!(!is_valid_auth_token(
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        ));
        // 63 hex chars (too short by one)
        assert!(!is_valid_auth_token(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"
        ));
    }
}
