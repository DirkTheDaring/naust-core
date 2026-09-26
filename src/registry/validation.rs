use crate::registry::canonical_name::CanonicalRepoName;

/// Validates an OCI repository name according to the normative OCI distribution specification.
///
/// Delegates directly to [`CanonicalRepoName::parse`] as the single source of truth.
#[inline]
pub fn is_valid_repo_name(name: &str) -> bool {
    CanonicalRepoName::parse(name).is_ok()
}

/// Validates an OCI tag name according to the OCI distribution specification.
///
/// Rules:
/// - Non-empty and at most 128 characters.
/// - Contains no slashes or whitespace.
/// - Must begin with an ASCII alphanumeric character or underscore.
/// - May contain ASCII alphanumeric characters, `.`, `_`, or `-`.
pub fn is_valid_tag(tag: &str) -> bool {
    if tag.is_empty() || tag.len() > 128 {
        return false;
    }
    if tag.contains('/') || tag.contains(char::is_whitespace) {
        return false;
    }
    let mut chars = tag.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphanumeric() || first == '_') {
        return false;
    }
    tag.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_repo_names() {
        assert!(is_valid_repo_name("library/alpine"));
        assert!(is_valid_repo_name("org.name/repo_name-1"));
        assert!(is_valid_repo_name("repo"));
        assert!(is_valid_repo_name("a/b/c/d"));
        assert!(is_valid_repo_name("123/456"));
        assert!(is_valid_repo_name("team/image__cache"));
        assert!(is_valid_repo_name("team/image---cache"));
    }

    #[test]
    fn test_invalid_repo_names() {
        assert!(!is_valid_repo_name(""));
        assert!(!is_valid_repo_name("/leading"));
        assert!(!is_valid_repo_name("trailing/"));
        assert!(!is_valid_repo_name(".."));
        assert!(!is_valid_repo_name("a/../b"));
        assert!(!is_valid_repo_name("a b"));
        assert!(!is_valid_repo_name("INVALID/UPPERCASE"));
        assert!(!is_valid_repo_name("-invalid-leading-dash"));
        assert!(!is_valid_repo_name("invalid___triple_underscore"));
        assert!(!is_valid_repo_name("invalid..dots"));
        assert!(!is_valid_repo_name("invalid//empty_seg"));
        assert!(!is_valid_repo_name("a/b-"));
        assert!(!is_valid_repo_name("a/b."));
        assert!(!is_valid_repo_name("a/b_"));
    }

    #[test]
    fn test_valid_tags() {
        assert!(is_valid_tag("latest"));
        assert!(is_valid_tag("v1.0.0"));
        assert!(is_valid_tag("v1.0.0-alpha.1"));
        assert!(is_valid_tag("_build_123"));
    }

    #[test]
    fn test_invalid_tags() {
        assert!(!is_valid_tag(""));
        assert!(!is_valid_tag("has/slash"));
        assert!(!is_valid_tag("has space"));
        assert!(!is_valid_tag(".leading_dot"));
        assert!(!is_valid_tag("-leading_dash"));
    }
}
