use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

pub const UPLOAD_STATE_DOMAIN: &str = "registry_upload_state_v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StateTokenError {
    #[error("missing state token")]
    Missing,
    #[error("invalid token format")]
    InvalidFormat,
    #[error("invalid cryptographic signature")]
    InvalidSignature,
    #[error("invalid token domain identifier")]
    InvalidDomain,
    #[error("repository mismatch")]
    RepoMismatch,
    #[error("uuid mismatch")]
    UuidMismatch,
    #[error("offset mismatch (expected {expected}, found {found})")]
    OffsetMismatch { expected: u64, found: u64 },
    #[error("invalid token payload")]
    InvalidPayload,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UploadStateData {
    pub domain: String,
    pub repo: String,
    pub uuid: String,
    pub offset: u64,
    pub iat: u64,
}

impl UploadStateData {
    pub fn new(repo: impl Into<String>, uuid: impl Into<String>, offset: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            domain: UPLOAD_STATE_DOMAIN.to_string(),
            repo: repo.into(),
            uuid: uuid.into(),
            offset,
            iat: now,
        }
    }

    pub fn encode_and_sign(&self, signing_key: &[u8]) -> String {
        let payload_bytes = serde_json::to_vec(self).unwrap_or_default();
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload_bytes);

        let mut mac =
            Hmac::<Sha256>::new_from_slice(signing_key).expect("HMAC can take key of any size");
        mac.update(payload_b64.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);

        format!("{payload_b64}.{sig_b64}")
    }

    pub fn verify_and_decode(
        token_str: &str,
        signing_key: &[u8],
        expected_repo: &str,
    ) -> Result<Self, StateTokenError> {
        let trimmed = token_str.trim();
        if trimmed.is_empty() {
            return Err(StateTokenError::Missing);
        }

        // Require structured 2-part signed state tokens: <payload_b64>.<sig_b64>
        let parts: Vec<&str> = trimmed.split('.').collect();
        if parts.len() != 2 {
            return Err(StateTokenError::InvalidFormat);
        }

        let payload_b64 = parts[0];
        let sig_b64 = parts[1];

        // 1. Verify HMAC Signature
        let expected_sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig_b64)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(sig_b64))
            .map_err(|_| StateTokenError::InvalidSignature)?;

        // Enforce exact 32-byte SHA-256 MAC length to prevent truncation attacks
        if expected_sig.len() != 32 {
            return Err(StateTokenError::InvalidSignature);
        }

        let mut mac = Hmac::<Sha256>::new_from_slice(signing_key)
            .map_err(|_| StateTokenError::InvalidSignature)?;
        mac.update(payload_b64.as_bytes());
        mac.verify_slice(&expected_sig)
            .map_err(|_| StateTokenError::InvalidSignature)?;

        // 2. Decode payload
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(payload_b64))
            .map_err(|_| StateTokenError::InvalidPayload)?;

        let data: UploadStateData =
            serde_json::from_slice(&payload_bytes).map_err(|_| StateTokenError::InvalidPayload)?;

        // 3. Verify domain and format version
        if data.domain != UPLOAD_STATE_DOMAIN {
            return Err(StateTokenError::InvalidDomain);
        }

        // 4. Verify repository binding
        let norm_data_repo = data
            .repo
            .trim_start_matches('/')
            .strip_prefix("library/")
            .unwrap_or(&data.repo);
        let norm_exp_repo = expected_repo
            .trim_start_matches('/')
            .strip_prefix("library/")
            .unwrap_or(expected_repo);
        if norm_data_repo != norm_exp_repo {
            return Err(StateTokenError::RepoMismatch);
        }

        Ok(data)
    }

    pub fn validate_session(
        &self,
        expected_uuid: &str,
        stored_offset: u64,
    ) -> Result<(), StateTokenError> {
        if self.uuid != expected_uuid {
            return Err(StateTokenError::UuidMismatch);
        }
        if self.offset != stored_offset {
            return Err(StateTokenError::OffsetMismatch {
                expected: stored_offset,
                found: self.offset,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_1_valid_signed_state_token_is_accepted() {
        let key = b"secret-key-12345";
        let state = UploadStateData::new(
            "library/test-repo",
            "01234567-89ab-cdef-0123-456789abcdef",
            1024,
        );
        let token = state.encode_and_sign(key);

        let decoded = UploadStateData::verify_and_decode(&token, key, "library/test-repo").unwrap();
        assert_eq!(decoded.repo, "library/test-repo");
        assert_eq!(decoded.uuid, "01234567-89ab-cdef-0123-456789abcdef");
        assert_eq!(decoded.offset, 1024);
        assert!(
            decoded
                .validate_session("01234567-89ab-cdef-0123-456789abcdef", 1024)
                .is_ok()
        );
    }

    #[test]
    fn test_2_unsigned_repo_uuid_state_is_rejected() {
        let key = b"secret-key-12345";
        let unsigned = "library/test-repo:01234567-89ab-cdef-0123-456789abcdef";
        let res = UploadStateData::verify_and_decode(unsigned, key, "library/test-repo");
        assert_eq!(res, Err(StateTokenError::InvalidFormat));
    }

    #[test]
    fn test_3_malformed_token_is_rejected() {
        let key = b"secret-key-12345";
        assert_eq!(
            UploadStateData::verify_and_decode("", key, "library/test-repo"),
            Err(StateTokenError::Missing)
        );
        assert_eq!(
            UploadStateData::verify_and_decode("not-a-valid-token", key, "library/test-repo"),
            Err(StateTokenError::InvalidFormat)
        );
        assert_eq!(
            UploadStateData::verify_and_decode("a.b.c", key, "library/test-repo"),
            Err(StateTokenError::InvalidFormat)
        );
        assert_eq!(
            UploadStateData::verify_and_decode(".", key, "library/test-repo"),
            Err(StateTokenError::InvalidSignature)
        );
    }

    #[test]
    fn test_4_tampered_payload_is_rejected() {
        let key = b"secret-key-12345";
        let state1 = UploadStateData::new(
            "library/test-repo",
            "01234567-89ab-cdef-0123-456789abcdef",
            0,
        );
        let token1 = state1.encode_and_sign(key);
        let sig1 = token1.split('.').nth(1).unwrap();

        let state2 = UploadStateData::new(
            "library/test-repo",
            "01234567-89ab-cdef-0123-456789abcdef",
            9999,
        );
        let token2 = state2.encode_and_sign(key);
        let payload2 = token2.split('.').next().unwrap();

        // Pair payload from state2 with signature from state1
        let tampered = format!("{payload2}.{sig1}");
        let res = UploadStateData::verify_and_decode(&tampered, key, "library/test-repo");
        assert_eq!(res, Err(StateTokenError::InvalidSignature));
    }

    #[test]
    fn test_5_tampered_signature_is_rejected() {
        let key = b"secret-key-12345";
        let state = UploadStateData::new(
            "library/test-repo",
            "01234567-89ab-cdef-0123-456789abcdef",
            0,
        );
        let token = state.encode_and_sign(key);
        let tampered = format!("{}.invalid_sig_bytes", token.split('.').next().unwrap());
        let res = UploadStateData::verify_and_decode(&tampered, key, "library/test-repo");
        assert_eq!(res, Err(StateTokenError::InvalidSignature));
    }

    #[test]
    fn test_6_signed_token_for_another_repo_is_rejected() {
        let key = b"secret-key-12345";
        let state =
            UploadStateData::new("library/repo-a", "01234567-89ab-cdef-0123-456789abcdef", 0);
        let token = state.encode_and_sign(key);

        let res = UploadStateData::verify_and_decode(&token, key, "library/repo-b");
        assert_eq!(res, Err(StateTokenError::RepoMismatch));
    }

    #[test]
    fn test_7_signed_token_for_uuid_a_rejected_for_uuid_b() {
        let key = b"secret-key-12345";
        let state = UploadStateData::new(
            "library/test-repo",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            0,
        );
        let token = state.encode_and_sign(key);

        let decoded = UploadStateData::verify_and_decode(&token, key, "library/test-repo").unwrap();
        assert_eq!(
            decoded.validate_session("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 0),
            Err(StateTokenError::UuidMismatch)
        );
    }

    #[test]
    fn test_8_signed_token_offset_0_rejected_when_stored_offset_nonzero() {
        let key = b"secret-key-12345";
        let state = UploadStateData::new(
            "library/test-repo",
            "01234567-89ab-cdef-0123-456789abcdef",
            0,
        );
        let token = state.encode_and_sign(key);

        let decoded = UploadStateData::verify_and_decode(&token, key, "library/test-repo").unwrap();
        let stored_offset = 1024u64;
        assert_eq!(
            decoded.validate_session("01234567-89ab-cdef-0123-456789abcdef", stored_offset),
            Err(StateTokenError::OffsetMismatch {
                expected: 1024,
                found: 0,
            })
        );
    }

    #[test]
    fn test_9_stale_signed_offset_rejected() {
        let key = b"secret-key-12345";
        let state = UploadStateData::new(
            "library/test-repo",
            "01234567-89ab-cdef-0123-456789abcdef",
            512,
        );
        let token = state.encode_and_sign(key);

        let decoded = UploadStateData::verify_and_decode(&token, key, "library/test-repo").unwrap();
        let stored_offset = 1024u64;
        assert_eq!(
            decoded.validate_session("01234567-89ab-cdef-0123-456789abcdef", stored_offset),
            Err(StateTokenError::OffsetMismatch {
                expected: 1024,
                found: 512,
            })
        );
    }

    #[test]
    fn test_10_signed_token_with_correct_repo_uuid_offset_accepted() {
        let key = b"secret-key-12345";
        let uuid = "01234567-89ab-cdef-0123-456789abcdef";
        let offset = 2048u64;
        let state = UploadStateData::new("library/test-repo", uuid, offset);
        let token = state.encode_and_sign(key);

        let decoded = UploadStateData::verify_and_decode(&token, key, "library/test-repo").unwrap();
        assert_eq!(decoded.repo, "library/test-repo");
        assert_eq!(decoded.uuid, uuid);
        assert_eq!(decoded.offset, offset);
        assert!(decoded.validate_session(uuid, offset).is_ok());
    }

    #[test]
    fn test_11_cross_token_domain_replay_is_rejected() {
        let key = b"secret-key-12345";
        let mut state = UploadStateData::new(
            "library/test-repo",
            "01234567-89ab-cdef-0123-456789abcdef",
            0,
        );
        state.domain = "some_other_system_token_v1".to_string();
        let token = state.encode_and_sign(key);

        let res = UploadStateData::verify_and_decode(&token, key, "library/test-repo");
        assert_eq!(res, Err(StateTokenError::InvalidDomain));
    }

    #[test]
    fn test_12_truncated_mac_is_rejected() {
        let key = b"secret-key-12345";
        let state = UploadStateData::new(
            "library/test-repo",
            "01234567-89ab-cdef-0123-456789abcdef",
            0,
        );
        let token = state.encode_and_sign(key);
        let payload = token.split('.').next().unwrap();
        // 16-byte truncated signature instead of 32 bytes
        let short_sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 16]);
        let tampered = format!("{payload}.{short_sig}");

        let res = UploadStateData::verify_and_decode(&tampered, key, "library/test-repo");
        assert_eq!(res, Err(StateTokenError::InvalidSignature));
    }

    #[test]
    fn test_13_malformed_base64_in_payload_or_sig_rejected() {
        let key = b"secret-key-12345";
        let res1 = UploadStateData::verify_and_decode(
            "not_valid_b64!.valid_sig",
            key,
            "library/test-repo",
        );
        assert_eq!(res1, Err(StateTokenError::InvalidSignature));

        let res2 = UploadStateData::verify_and_decode(
            "valid_b64.not_valid_b64!",
            key,
            "library/test-repo",
        );
        assert_eq!(res2, Err(StateTokenError::InvalidSignature));
    }
}
