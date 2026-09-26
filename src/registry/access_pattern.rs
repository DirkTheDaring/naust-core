use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::canonical_name::{CanonicalRepoName, RepoNameError};

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum AccessPatternError {
    #[error("repository access pattern is empty")]
    Empty,
    #[error("invalid repository access pattern wildcard: only '*' or '<valid_repo>/*' is allowed")]
    InvalidWildcard,
    #[error("invalid repository name in access pattern: {0}")]
    InvalidRepoName(#[from] RepoNameError),
}

/// Explicit, closed model for repository access policy patterns.
///
/// Supported forms:
/// - `All`: Global wildcard `*` matching any valid repository.
/// - `Subtree`: Segment-delimited namespace wildcard `prefix/*` matching `prefix` and any `prefix/...` descendants.
/// - `Exact`: Exact repository name matching only that repository.
///
/// Disallows arbitrary regex/substring wildcards such as `prefix*`, `*app`, or `a*b` to prevent namespace confusion.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RepositoryAccessPattern {
    All,
    Subtree(CanonicalRepoName),
    Exact(CanonicalRepoName),
}

impl RepositoryAccessPattern {
    /// Validates and parses a repository access pattern string.
    pub fn parse(s: &str) -> Result<Self, AccessPatternError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(AccessPatternError::Empty);
        }
        if trimmed == "*" {
            return Ok(Self::All);
        }
        if let Some(prefix) = trimmed.strip_suffix("/*") {
            if prefix.contains('*') {
                return Err(AccessPatternError::InvalidWildcard);
            }
            let repo = CanonicalRepoName::parse(prefix)?;
            return Ok(Self::Subtree(repo));
        }
        if trimmed.contains('*') {
            return Err(AccessPatternError::InvalidWildcard);
        }
        let repo = CanonicalRepoName::parse(trimmed)?;
        Ok(Self::Exact(repo))
    }

    /// Evaluates whether a candidate repository matches this access pattern.
    ///
    /// Match rules:
    /// - `All`: Always returns `true`.
    /// - `Exact(exact)`: Returns `true` iff `exact == candidate`.
    /// - `Subtree(prefix)`: Returns `true` iff `prefix == candidate` or `candidate` starts with `{prefix}/` (segment-delimited).
    pub fn matches(&self, candidate: &CanonicalRepoName) -> bool {
        match self {
            Self::All => true,
            Self::Exact(exact) => exact == candidate,
            Self::Subtree(prefix) => {
                if prefix == candidate {
                    return true;
                }
                let cand_str = candidate.as_str();
                let prefix_str = prefix.as_str();
                if cand_str.starts_with(prefix_str) {
                    let next_byte = cand_str.as_bytes().get(prefix_str.len());
                    return next_byte == Some(&b'/');
                }
                false
            }
        }
    }
}

/// Returns `true` when `repo` is authorized by at least one pattern in `allowlist`.
///
/// - `*` (`RepositoryAccessPattern::All`) authorizes any repository.
/// - `prefix/*` (`RepositoryAccessPattern::Subtree`) authorizes `prefix` itself as well as any `prefix/...` descendants.
/// - Exact repository (`RepositoryAccessPattern::Exact`) authorizes only the specified repository name.
/// - Empty allowlist or non-matching repository returns `false`.
pub fn push_repository_allowed(
    allowlist: &[RepositoryAccessPattern],
    repo: &crate::registry::canonical_name::CanonicalRepoName,
) -> bool {
    allowlist.iter().any(|pat| pat.matches(repo))
}

impl fmt::Display for RepositoryAccessPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => write!(f, "*"),
            Self::Subtree(prefix) => write!(f, "{}/*", prefix.as_str()),
            Self::Exact(exact) => write!(f, "{}", exact.as_str()),
        }
    }
}

impl FromStr for RepositoryAccessPattern {
    type Err = AccessPatternError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for RepositoryAccessPattern {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for RepositoryAccessPattern {
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
    fn test_access_pattern_parsing() {
        assert_eq!(
            RepositoryAccessPattern::parse("*").unwrap(),
            RepositoryAccessPattern::All
        );

        let team = CanonicalRepoName::parse("team").unwrap();
        assert_eq!(
            RepositoryAccessPattern::parse("team").unwrap(),
            RepositoryAccessPattern::Exact(team.clone())
        );
        assert_eq!(
            RepositoryAccessPattern::parse("team/*").unwrap(),
            RepositoryAccessPattern::Subtree(team)
        );

        let complex = CanonicalRepoName::parse("org/team__cache/service--a").unwrap();
        assert_eq!(
            RepositoryAccessPattern::parse("org/team__cache/service--a/*").unwrap(),
            RepositoryAccessPattern::Subtree(complex)
        );

        // Invalid patterns
        assert!(RepositoryAccessPattern::parse("").is_err());
        assert!(RepositoryAccessPattern::parse("team*").is_err());
        assert!(RepositoryAccessPattern::parse("*team").is_err());
        assert!(RepositoryAccessPattern::parse("team/*/*").is_err());
        assert!(RepositoryAccessPattern::parse("team/image*").is_err());
        assert!(RepositoryAccessPattern::parse("INVALID/UPPER").is_err());
        assert!(RepositoryAccessPattern::parse("invalid..dots/*").is_err());
    }

    #[test]
    fn test_access_pattern_matching_truth_table() {
        let pat_team_exact = RepositoryAccessPattern::parse("team").unwrap();
        let pat_team_subtree = RepositoryAccessPattern::parse("team/*").unwrap();
        let pat_all = RepositoryAccessPattern::parse("*").unwrap();

        let cand_team = CanonicalRepoName::parse("team").unwrap();
        let cand_team_image = CanonicalRepoName::parse("team/image").unwrap();
        let cand_team_nested = CanonicalRepoName::parse("team/nested/image").unwrap();
        let cand_team_secret = CanonicalRepoName::parse("team-secret").unwrap();
        let cand_team_secret_image = CanonicalRepoName::parse("team-secret/image").unwrap();
        let cand_other = CanonicalRepoName::parse("other/repo").unwrap();

        // Exact pattern "team"
        assert!(pat_team_exact.matches(&cand_team));
        assert!(!pat_team_exact.matches(&cand_team_image));
        assert!(!pat_team_exact.matches(&cand_team_secret));

        // Subtree pattern "team/*"
        assert!(pat_team_subtree.matches(&cand_team)); // Documented legacy compatibility: prefix/* covers prefix
        assert!(pat_team_subtree.matches(&cand_team_image));
        assert!(pat_team_subtree.matches(&cand_team_nested));
        assert!(!pat_team_subtree.matches(&cand_team_secret)); // Segment boundary respected!
        assert!(!pat_team_subtree.matches(&cand_team_secret_image)); // Segment boundary respected!
        assert!(!pat_team_subtree.matches(&cand_other));

        // All pattern "*"
        assert!(pat_all.matches(&cand_team));
        assert!(pat_all.matches(&cand_team_image));
        assert!(pat_all.matches(&cand_team_secret_image));
        assert!(pat_all.matches(&cand_other));
    }
}
