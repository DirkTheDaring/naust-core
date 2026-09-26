use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest {
    algo: String,
    hex: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum DigestParseError {
    #[error("unsupported digest algorithm")]
    UnsupportedAlgorithm,

    #[error("invalid digest format")]
    InvalidFormat,

    #[error("invalid hex")]
    InvalidHex,
}

impl Digest {
    pub fn parse(input: &str) -> Result<Self, DigestParseError> {
        let (algo, hex) = input
            .split_once(':')
            .ok_or(DigestParseError::InvalidFormat)?;
        let algo_lc = algo.trim().to_ascii_lowercase();
        let (normalized_algo, expected_len) = match algo_lc.as_str() {
            "sha256" | "intoto-sha256" => ("sha256".to_string(), 64),
            "sha512" => ("sha512".to_string(), 128),
            _ => return Err(DigestParseError::UnsupportedAlgorithm),
        };

        if hex.len() != expected_len {
            return Err(DigestParseError::InvalidFormat);
        }
        if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(DigestParseError::InvalidHex);
        }
        Ok(Self {
            algo: normalized_algo,
            hex: hex.to_ascii_lowercase(),
        })
    }

    pub fn as_str(&self) -> String {
        format!("{}:{}", self.algo, self.hex)
    }

    pub fn algorithm(&self) -> &str {
        &self.algo
    }

    pub fn hex(&self) -> &str {
        &self.hex
    }

    pub fn prefix2(&self) -> &str {
        // safe because hex length is at least 64
        &self.hex[..2]
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.algo, self.hex)
    }
}

impl serde::Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Digest::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_valid_sha256() {
        let d = Digest::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("valid digest");
        assert_eq!(
            d.hex(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(d.prefix2(), "01");
        assert_eq!(d.algorithm(), "sha256");
        assert_eq!(
            d.as_str(),
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn parse_accepts_valid_sha512() {
        let hex512 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let d = Digest::parse(&format!("sha512:{hex512}")).expect("valid sha512 digest");
        assert_eq!(d.hex(), hex512);
        assert_eq!(d.prefix2(), "01");
        assert_eq!(d.algorithm(), "sha512");
        assert_eq!(d.as_str(), format!("sha512:{hex512}"));
    }

    #[test]
    fn parse_rejects_non_supported_algo() {
        let err = Digest::parse("sha1:abcd").unwrap_err();
        assert!(matches!(
            err,
            DigestParseError::UnsupportedAlgorithm | DigestParseError::InvalidFormat
        ));
    }

    #[test]
    fn parse_accepts_intoto_sha256_alias() {
        let d = Digest::parse(
            "intoto-sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("valid intoto-sha256 digest alias");
        assert_eq!(
            d.as_str(),
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn parse_rejects_wrong_length() {
        let err = Digest::parse("sha256:abcd").unwrap_err();
        assert!(matches!(err, DigestParseError::InvalidFormat));

        let err512 = Digest::parse("sha512:0123456789abcdef").unwrap_err();
        assert!(matches!(err512, DigestParseError::InvalidFormat));
    }

    #[test]
    fn parse_rejects_non_hex() {
        let err = Digest::parse(
            "sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        )
        .unwrap_err();
        assert!(matches!(err, DigestParseError::InvalidHex));
    }
}
