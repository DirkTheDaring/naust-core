use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum RepoNameError {
    #[error("repository name is empty")]
    Empty,
    #[error("repository name component contains empty segment")]
    EmptySegment,
    #[error("repository name contains invalid character: {0}")]
    InvalidCharacter(char),
    #[error("repository name component contains invalid separator sequence: {0}")]
    InvalidSeparator(String),
    #[error("repository name component contains path traversal or invalid segment: {0}")]
    InvalidSegment(String),
    #[error("repository name cannot start or end with a slash")]
    LeadingOrTrailingSlash,
    #[error("repository name cannot contain consecutive slashes")]
    ConsecutiveSlashes,
}

/// A validated, immutable canonical repository name matching the normative OCI Distribution Spec:
/// `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(\/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*`
///
/// Guaranteed invariants:
/// 1. Consists of one or more slash-separated (`/`) segments.
/// 2. Each segment begins and ends with lowercase ASCII alphanumeric `[a-z0-9]`.
/// 3. Separators between alphanumeric runs within a segment are strictly:
///    - single dot `.` (consecutive `..` forbidden)
///    - single underscore `_` or double underscore `__` (3+ underscores `___` forbidden)
///    - one or more hyphens `-+` (`-`, `--`, `---`, etc. are valid)
///    - mixed adjacent separators without intervening alphanumeric are forbidden (`._`, `_.`, `-_`, etc.)
/// 4. No empty segments, leading slashes, trailing slashes, or double slashes (`//`).
/// 5. No dot segments (`.` or `..`), backslashes (`\`), uppercase, whitespace, non-ASCII, colons, `@`, `%`, or control characters.
/// 6. Path-traversal proof: Cannot escape a base directory or alias internal reserved paths.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalRepoName(String);

impl CanonicalRepoName {
    /// Validates and constructs a `CanonicalRepoName` from a string slice according to the OCI repository grammar.
    pub fn parse(s: &str) -> Result<Self, RepoNameError> {
        if s.is_empty() {
            return Err(RepoNameError::Empty);
        }
        if s.starts_with('/') || s.ends_with('/') {
            return Err(RepoNameError::LeadingOrTrailingSlash);
        }
        if s.contains("//") {
            return Err(RepoNameError::ConsecutiveSlashes);
        }

        // Validate each component segment
        for segment in s.split('/') {
            Self::validate_segment(segment)?;
        }

        Ok(Self(s.to_string()))
    }

    fn validate_segment(segment: &str) -> Result<(), RepoNameError> {
        if segment.is_empty() {
            return Err(RepoNameError::EmptySegment);
        }
        if segment == "." || segment == ".." {
            return Err(RepoNameError::InvalidSegment(segment.to_string()));
        }

        let bytes = segment.as_bytes();
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];

        if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
            return Err(RepoNameError::InvalidSegment(format!(
                "segment '{segment}' must start with lowercase alphanumeric"
            )));
        }
        if !last.is_ascii_lowercase() && !last.is_ascii_digit() {
            return Err(RepoNameError::InvalidSegment(format!(
                "segment '{segment}' must end with lowercase alphanumeric"
            )));
        }

        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if b.is_ascii_lowercase() || b.is_ascii_digit() {
                i += 1;
            } else if b == b'.' || b == b'_' || b == b'-' {
                let sep_char = b;
                let start = i;
                while i < bytes.len() && (bytes[i] == b'.' || bytes[i] == b'_' || bytes[i] == b'-')
                {
                    if bytes[i] != sep_char {
                        return Err(RepoNameError::InvalidSeparator(format!(
                            "mixed adjacent separators in segment '{segment}'"
                        )));
                    }
                    i += 1;
                }
                let sep_len = i - start;
                match sep_char {
                    b'.' => {
                        if sep_len != 1 {
                            return Err(RepoNameError::InvalidSeparator(format!(
                                "consecutive dots in segment '{segment}'"
                            )));
                        }
                    }
                    b'_' => {
                        if sep_len > 2 {
                            return Err(RepoNameError::InvalidSeparator(format!(
                                "more than two consecutive underscores in segment '{segment}'"
                            )));
                        }
                    }
                    b'-' => {
                        // One or more dashes allowed
                    }
                    _ => unreachable!(),
                }
            } else {
                return Err(RepoNameError::InvalidCharacter(b as char));
            }
        }

        Ok(())
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[inline]
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }

    #[inline]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for CanonicalRepoName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for CanonicalRepoName {
    type Err = RepoNameError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<String> for CanonicalRepoName {
    type Error = RepoNameError;

    #[inline]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl TryFrom<&str> for CanonicalRepoName {
    type Error = RepoNameError;

    #[inline]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<CanonicalRepoName> for String {
    #[inline]
    fn from(name: CanonicalRepoName) -> Self {
        name.0
    }
}

impl PartialEq<str> for CanonicalRepoName {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for CanonicalRepoName {
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for CanonicalRepoName {
    #[inline]
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl PartialEq<CanonicalRepoName> for str {
    #[inline]
    fn eq(&self, other: &CanonicalRepoName) -> bool {
        self == other.0
    }
}

impl PartialEq<CanonicalRepoName> for &str {
    #[inline]
    fn eq(&self, other: &CanonicalRepoName) -> bool {
        *self == other.0
    }
}

impl PartialEq<CanonicalRepoName> for String {
    #[inline]
    fn eq(&self, other: &CanonicalRepoName) -> bool {
        self == &other.0
    }
}

impl Serialize for CanonicalRepoName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CanonicalRepoName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oci_normative_valid_examples() {
        let valid = [
            "a",
            "team/image",
            "team/image_cache",
            "team/image__cache",
            "team/image-cache",
            "team/image--cache",
            "team/image---cache",
            "a.b/c_d/e__f/g---h",
            "sub.domain/project/image",
            "a/b/c/d/e",
            "a-1/b_2/c.3",
            "org.name/repo_name-1",
            "123/456",
            "0",
        ];
        for name in valid {
            let res = CanonicalRepoName::parse(name);
            assert!(res.is_ok(), "Expected valid name: {name}, got: {res:?}");
            assert_eq!(res.unwrap().as_str(), name);
        }
    }

    #[test]
    fn test_oci_normative_invalid_examples() {
        let invalid = [
            "",
            "/leading",
            "/leading/slash",
            "trailing/",
            "trailing/slash/",
            "double//slash",
            "dot/./segment",
            "parent/../segment",
            "..",
            ".",
            "a/../b",
            "a/./b",
            "Uppercase/repo",
            "unicode/репо",
            "percent%2Fencoded",
            "percent%20encoded",
            "back\\slash",
            "-start-dash/repo",
            "end-dash-/repo",
            "repo/-start-dash",
            "repo/end-dash-",
            "_start-underscore/repo",
            "end-underscore_/repo",
            ".start-dot/repo",
            "end-dot./repo",
            "invalid..dots",
            "invalid...dots",
            "invalid___triple_underscore",
            "invalid._mixed",
            "invalid_.mixed",
            "invalid-_mixed",
            "invalid_-mixed",
            "invalid.-mixed",
            "invalid-.mixed",
            "invalid__-mixed",
            "a b",
            "a\tb",
            "a\nb",
            "a:b",
            "a@b",
            "a?b",
            "a#b",
            "a!b",
            "a$b",
        ];
        for name in invalid {
            assert!(
                CanonicalRepoName::parse(name).is_err(),
                "Expected invalid name to fail: {name}"
            );
        }
    }

    #[test]
    fn test_serde_roundtrip() {
        let name = CanonicalRepoName::parse("team/image__cache--prod").unwrap();
        let json = serde_json::to_string(&name).unwrap();
        assert_eq!(json, "\"team/image__cache--prod\"");
        let deserialized: CanonicalRepoName = serde_json::from_str(&json).unwrap();
        assert_eq!(name, deserialized);

        // Deserializing invalid name must fail
        let bad_json = "\"team/INVALID\"";
        let res: Result<CanonicalRepoName, _> = serde_json::from_str(bad_json);
        assert!(res.is_err());
    }
}
