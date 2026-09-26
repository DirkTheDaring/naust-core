use crate::registry::digest::{Digest, DigestParseError};
use std::collections::HashMap;

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ManifestRefs {
    pub config: Option<Digest>,
    pub layers: Vec<Digest>,
    pub manifests: Vec<Digest>,
    pub blobs: Vec<Digest>,
    pub subject: Option<Digest>,
}

impl ManifestRefs {
    pub fn blob_references(&self) -> impl Iterator<Item = &Digest> {
        self.config
            .iter()
            .chain(self.layers.iter())
            .chain(self.blobs.iter())
    }

    pub fn manifest_references(&self) -> impl Iterator<Item = &Digest> {
        self.manifests.iter().chain(self.subject.iter())
    }

    pub fn all_references(&self) -> impl Iterator<Item = &Digest> {
        self.blob_references().chain(self.manifest_references())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestParseError {
    #[error("invalid json: {0}")]
    InvalidJson(#[source] serde_json::Error),

    #[error("manifest structure is not a json object")]
    NotAnObject,

    #[error("descriptor field '{field}' has invalid structure: {message}")]
    MalformedDescriptor {
        field: &'static str,
        message: &'static str,
    },

    #[error("invalid digest in descriptor field '{field}': '{raw}' ({error})")]
    InvalidDigest {
        field: &'static str,
        raw: String,
        #[source]
        error: DigestParseError,
    },

    #[error("schema version 1 unsupported")]
    SchemaV1Unsupported,

    #[error("docker schema v1 manifest unsupported")]
    DockerV1Unsupported,
}

pub fn parse_manifest_refs(bytes: &[u8]) -> Result<ManifestRefs, ManifestParseError> {
    let v: serde_json::Value =
        serde_json::from_slice(bytes).map_err(ManifestParseError::InvalidJson)?;

    let obj = v.as_object().ok_or(ManifestParseError::NotAnObject)?;
    let mut refs = ManifestRefs::default();

    // 1. manifests: optional array of descriptor objects
    if let Some(val) = obj.get("manifests") {
        if !val.is_null() {
            let arr = val
                .as_array()
                .ok_or(ManifestParseError::MalformedDescriptor {
                    field: "manifests",
                    message: "expected array",
                })?;
            for item in arr {
                let digest = parse_descriptor_digest(item, "manifests[]")?;
                refs.manifests.push(digest);
            }
        }
    }

    // 2. config: optional descriptor object
    if let Some(val) = obj.get("config") {
        if !val.is_null() {
            let digest = parse_descriptor_digest(val, "config")?;
            refs.config = Some(digest);
        }
    }

    // 3. layers: optional array of descriptor objects
    if let Some(val) = obj.get("layers") {
        if !val.is_null() {
            let arr = val
                .as_array()
                .ok_or(ManifestParseError::MalformedDescriptor {
                    field: "layers",
                    message: "expected array",
                })?;
            for item in arr {
                let digest = parse_descriptor_digest(item, "layers[]")?;
                refs.layers.push(digest);
            }
        }
    }

    // 4. blobs: optional array of descriptor objects (OCI artifact manifest)
    if let Some(val) = obj.get("blobs") {
        if !val.is_null() {
            let arr = val
                .as_array()
                .ok_or(ManifestParseError::MalformedDescriptor {
                    field: "blobs",
                    message: "expected array",
                })?;
            for item in arr {
                let digest = parse_descriptor_digest(item, "blobs[]")?;
                refs.blobs.push(digest);
            }
        }
    }

    // 5. subject: optional descriptor object
    if let Some(val) = obj.get("subject") {
        if !val.is_null() {
            let digest = parse_descriptor_digest(val, "subject")?;
            refs.subject = Some(digest);
        }
    }

    Ok(refs)
}

fn parse_descriptor_digest(
    val: &serde_json::Value,
    field: &'static str,
) -> Result<Digest, ManifestParseError> {
    let item_obj = val
        .as_object()
        .ok_or(ManifestParseError::MalformedDescriptor {
            field,
            message: "expected descriptor object",
        })?;

    let digest_val = item_obj
        .get("digest")
        .ok_or(ManifestParseError::MalformedDescriptor {
            field,
            message: "missing 'digest' field",
        })?;

    let digest_str = digest_val
        .as_str()
        .ok_or(ManifestParseError::MalformedDescriptor {
            field,
            message: "'digest' must be a string",
        })?;

    Digest::parse(digest_str).map_err(|e| ManifestParseError::InvalidDigest {
        field,
        raw: digest_str.to_string(),
        error: e,
    })
}

pub fn extract_subject_digest(manifest_bytes: &[u8]) -> Result<Option<Digest>, ManifestParseError> {
    parse_manifest_refs(manifest_bytes).map(|r| r.subject)
}

pub fn parse_referrer_info(
    manifest_bytes: &[u8],
) -> Result<Option<(Digest, Option<String>, Option<HashMap<String, String>>)>, ManifestParseError> {
    let refs = parse_manifest_refs(manifest_bytes)?;
    let Some(subject) = refs.subject else {
        return Ok(None);
    };

    let v: serde_json::Value =
        serde_json::from_slice(manifest_bytes).map_err(ManifestParseError::InvalidJson)?;

    let artifact_type = v
        .get("artifactType")
        .and_then(|a| a.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            v.get("config")
                .and_then(|c| c.get("mediaType"))
                .and_then(|m| m.as_str())
                .filter(|m| *m != "application/vnd.oci.empty.v1+json")
                .map(|s| s.to_string())
        });

    let annotations = v
        .get("annotations")
        .and_then(|a| a.as_object())
        .and_then(|obj| {
            let map = obj
                .iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect::<HashMap<_, _>>();
            if map.is_empty() { None } else { Some(map) }
        });

    Ok(Some((subject, artifact_type, annotations)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA256_1: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const SHA256_2: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    const SHA256_3: &str =
        "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    const SHA256_4: &str =
        "sha256:4444444444444444444444444444444444444444444444444444444444444444";
    const SHA512_1: &str = "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn test_table_driven_manifest_reference_extraction() {
        struct TestCase {
            name: &'static str,
            json: serde_json::Value,
            expected_config: Option<&'static str>,
            expected_layers: Vec<&'static str>,
            expected_manifests: Vec<&'static str>,
            expected_blobs: Vec<&'static str>,
            expected_subject: Option<&'static str>,
        }

        let cases = vec![
            TestCase {
                name: "OCI image manifest (config + layers)",
                json: serde_json::json!({
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "config": {
                        "mediaType": "application/vnd.oci.image.config.v1+json",
                        "digest": SHA256_1,
                        "size": 7023
                    },
                    "layers": [
                        {
                            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                            "digest": SHA256_2,
                            "size": 32654
                        },
                        {
                            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                            "digest": SHA256_3,
                            "size": 16724
                        }
                    ]
                }),
                expected_config: Some(SHA256_1),
                expected_layers: vec![SHA256_2, SHA256_3],
                expected_manifests: vec![],
                expected_blobs: vec![],
                expected_subject: None,
            },
            TestCase {
                name: "OCI image index (manifests)",
                json: serde_json::json!({
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "manifests": [
                        {
                            "mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "digest": SHA256_1,
                            "size": 500
                        },
                        {
                            "mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "digest": SHA256_2,
                            "size": 600
                        }
                    ]
                }),
                expected_config: None,
                expected_layers: vec![],
                expected_manifests: vec![SHA256_1, SHA256_2],
                expected_blobs: vec![],
                expected_subject: None,
            },
            TestCase {
                name: "OCI artifact manifest (blobs + subject)",
                json: serde_json::json!({
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.oci.artifact.manifest.v1+json",
                    "artifactType": "application/vnd.example.sbom.v1",
                    "blobs": [
                        {
                            "mediaType": "application/spdx+json",
                            "digest": SHA256_3,
                            "size": 1234
                        }
                    ],
                    "subject": {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": SHA256_4,
                        "size": 5678
                    }
                }),
                expected_config: None,
                expected_layers: vec![],
                expected_manifests: vec![],
                expected_blobs: vec![SHA256_3],
                expected_subject: Some(SHA256_4),
            },
            TestCase {
                name: "Docker Schema 2 manifest",
                json: serde_json::json!({
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                    "config": {
                        "mediaType": "application/vnd.docker.container.image.v1+json",
                        "digest": SHA256_1,
                        "size": 1470
                    },
                    "layers": [
                        {
                            "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                            "digest": SHA256_2,
                            "size": 2814120
                        }
                    ]
                }),
                expected_config: Some(SHA256_1),
                expected_layers: vec![SHA256_2],
                expected_manifests: vec![],
                expected_blobs: vec![],
                expected_subject: None,
            },
            TestCase {
                name: "Docker manifest list",
                json: serde_json::json!({
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
                    "manifests": [
                        {
                            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                            "digest": SHA256_1,
                            "size": 524
                        }
                    ]
                }),
                expected_config: None,
                expected_layers: vec![],
                expected_manifests: vec![SHA256_1],
                expected_blobs: vec![],
                expected_subject: None,
            },
            TestCase {
                name: "Sha512 references supported",
                json: serde_json::json!({
                    "schemaVersion": 2,
                    "config": {
                        "digest": SHA512_1
                    },
                    "layers": [
                        {
                            "digest": SHA512_1
                        }
                    ]
                }),
                expected_config: Some(SHA512_1),
                expected_layers: vec![SHA512_1],
                expected_manifests: vec![],
                expected_blobs: vec![],
                expected_subject: None,
            },
            TestCase {
                name: "Unknown extension fields tolerated",
                json: serde_json::json!({
                    "schemaVersion": 2,
                    "customExtension": { "foo": "bar", "num": 42 },
                    "annotations": { "org.opencontainers.image.title": "test" },
                    "config": {
                        "digest": SHA256_1,
                        "extraProp": true
                    },
                    "layers": [
                        {
                            "digest": SHA256_2,
                            "urls": ["https://example.com/layer"]
                        }
                    ]
                }),
                expected_config: Some(SHA256_1),
                expected_layers: vec![SHA256_2],
                expected_manifests: vec![],
                expected_blobs: vec![],
                expected_subject: None,
            },
            TestCase {
                name: "Missing optional fields (genuinely no references)",
                json: serde_json::json!({
                    "schemaVersion": 2
                }),
                expected_config: None,
                expected_layers: vec![],
                expected_manifests: vec![],
                expected_blobs: vec![],
                expected_subject: None,
            },
            TestCase {
                name: "Duplicate digests preserved in sequence",
                json: serde_json::json!({
                    "schemaVersion": 2,
                    "layers": [
                        { "digest": SHA256_1 },
                        { "digest": SHA256_1 }
                    ]
                }),
                expected_config: None,
                expected_layers: vec![SHA256_1, SHA256_1],
                expected_manifests: vec![],
                expected_blobs: vec![],
                expected_subject: None,
            },
            TestCase {
                name: "Empty arrays",
                json: serde_json::json!({
                    "schemaVersion": 2,
                    "manifests": [],
                    "layers": [],
                    "blobs": []
                }),
                expected_config: None,
                expected_layers: vec![],
                expected_manifests: vec![],
                expected_blobs: vec![],
                expected_subject: None,
            },
            TestCase {
                name: "Manifest with config, layers, blobs, and subject",
                json: serde_json::json!({
                    "schemaVersion": 2,
                    "config": { "digest": SHA256_1 },
                    "layers": [{ "digest": SHA256_2 }],
                    "blobs": [{ "digest": SHA256_3 }],
                    "subject": { "digest": SHA256_4 }
                }),
                expected_config: Some(SHA256_1),
                expected_layers: vec![SHA256_2],
                expected_manifests: vec![],
                expected_blobs: vec![SHA256_3],
                expected_subject: Some(SHA256_4),
            },
        ];

        for case in cases {
            let bytes = serde_json::to_vec(&case.json).unwrap();
            let parsed = parse_manifest_refs(&bytes)
                .unwrap_or_else(|e| panic!("failed to parse {}: {:?}", case.name, e));

            assert_eq!(
                parsed.config.as_ref().map(|d| d.as_str()),
                case.expected_config.map(|s| s.to_string()),
                "config mismatch in {}",
                case.name
            );
            let layer_strs: Vec<String> = parsed.layers.iter().map(|d| d.as_str()).collect();
            assert_eq!(
                layer_strs,
                case.expected_layers
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>(),
                "layers mismatch in {}",
                case.name
            );
            let manifest_strs: Vec<String> = parsed.manifests.iter().map(|d| d.as_str()).collect();
            assert_eq!(
                manifest_strs,
                case.expected_manifests
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>(),
                "manifests mismatch in {}",
                case.name
            );
            let blob_strs: Vec<String> = parsed.blobs.iter().map(|d| d.as_str()).collect();
            assert_eq!(
                blob_strs,
                case.expected_blobs
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>(),
                "blobs mismatch in {}",
                case.name
            );
            assert_eq!(
                parsed.subject.as_ref().map(|d| d.as_str()),
                case.expected_subject.map(|s| s.to_string()),
                "subject mismatch in {}",
                case.name
            );
        }
    }

    #[test]
    fn test_negative_1_invalid_digest_in_config() {
        let json = serde_json::json!({
            "schemaVersion": 2,
            "config": { "digest": "sha256:not-a-valid-hex" }
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        let err = parse_manifest_refs(&bytes).expect_err("should fail on invalid config digest");
        assert!(matches!(
            err,
            ManifestParseError::InvalidDigest {
                field: "config",
                ..
            }
        ));
    }

    #[test]
    fn test_negative_2_invalid_digest_in_layers() {
        let json = serde_json::json!({
            "schemaVersion": 2,
            "layers": [
                { "digest": SHA256_1 },
                { "digest": "invalid_algo:1234" }
            ]
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        let err = parse_manifest_refs(&bytes).expect_err("should fail on invalid layer digest");
        assert!(matches!(
            err,
            ManifestParseError::InvalidDigest {
                field: "layers[]",
                ..
            }
        ));
    }

    #[test]
    fn test_negative_3_invalid_digest_in_manifests() {
        let json = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [
                { "digest": "sha256:short" }
            ]
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        let err = parse_manifest_refs(&bytes).expect_err("should fail on invalid manifest digest");
        assert!(matches!(
            err,
            ManifestParseError::InvalidDigest {
                field: "manifests[]",
                ..
            }
        ));
    }

    #[test]
    fn test_negative_4_invalid_digest_in_blobs() {
        let json = serde_json::json!({
            "schemaVersion": 2,
            "blobs": [
                { "digest": "invalid-digest" }
            ]
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        let err = parse_manifest_refs(&bytes).expect_err("should fail on invalid blob digest");
        assert!(matches!(
            err,
            ManifestParseError::InvalidDigest {
                field: "blobs[]",
                ..
            }
        ));
    }

    #[test]
    fn test_negative_5_invalid_digest_in_subject() {
        let json = serde_json::json!({
            "schemaVersion": 2,
            "subject": { "digest": "sha256:invalid" }
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        let err = parse_manifest_refs(&bytes).expect_err("should fail on invalid subject digest");
        assert!(matches!(
            err,
            ManifestParseError::InvalidDigest {
                field: "subject",
                ..
            }
        ));
    }

    #[test]
    fn test_negative_6_mixed_valid_and_invalid_descriptors() {
        let json = serde_json::json!({
            "schemaVersion": 2,
            "config": { "digest": SHA256_1 },
            "layers": [
                { "digest": SHA256_2 },
                { "digest": "sha256:corrupt" }
            ]
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        let err = parse_manifest_refs(&bytes).expect_err("should fail on mixed descriptors");
        assert!(matches!(
            err,
            ManifestParseError::InvalidDigest {
                field: "layers[]",
                ..
            }
        ));
    }

    #[test]
    fn test_negative_7_wrong_json_types_for_descriptor_arrays_and_objects() {
        // config as string instead of object
        let json1 = serde_json::json!({ "schemaVersion": 2, "config": "not_an_object" });
        let err1 = parse_manifest_refs(&serde_json::to_vec(&json1).unwrap()).unwrap_err();
        assert!(matches!(
            err1,
            ManifestParseError::MalformedDescriptor {
                field: "config",
                ..
            }
        ));

        // layers as object instead of array
        let json2 = serde_json::json!({ "schemaVersion": 2, "layers": { "digest": SHA256_1 } });
        let err2 = parse_manifest_refs(&serde_json::to_vec(&json2).unwrap()).unwrap_err();
        assert!(matches!(
            err2,
            ManifestParseError::MalformedDescriptor {
                field: "layers",
                ..
            }
        ));

        // layers element without digest field
        let json3 = serde_json::json!({ "schemaVersion": 2, "layers": [{ "size": 100 }] });
        let err3 = parse_manifest_refs(&serde_json::to_vec(&json3).unwrap()).unwrap_err();
        assert!(matches!(
            err3,
            ManifestParseError::MalformedDescriptor {
                field: "layers[]",
                ..
            }
        ));

        // manifests as number
        let json4 = serde_json::json!({ "schemaVersion": 2, "manifests": 42 });
        let err4 = parse_manifest_refs(&serde_json::to_vec(&json4).unwrap()).unwrap_err();
        assert!(matches!(
            err4,
            ManifestParseError::MalformedDescriptor {
                field: "manifests",
                ..
            }
        ));
    }

    #[test]
    fn test_negative_8_malformed_json_and_non_object() {
        let err_json = parse_manifest_refs(b"not json").expect_err("invalid json");
        assert!(matches!(err_json, ManifestParseError::InvalidJson(_)));

        let err_array = parse_manifest_refs(b"[]").expect_err("array instead of object");
        assert!(matches!(err_array, ManifestParseError::NotAnObject));
    }

    #[test]
    fn test_negative_subject_extraction_and_referrer_info() {
        let invalid_subject = serde_json::json!({
            "subject": { "digest": "sha256:bad" }
        });
        let bytes = serde_json::to_vec(&invalid_subject).unwrap();
        assert!(extract_subject_digest(&bytes).is_err());
        assert!(parse_referrer_info(&bytes).is_err());
    }

    #[test]
    fn test_extract_subject_digest_valid_and_absent() {
        let manifest = serde_json::json!({
            "subject": {
                "digest": SHA256_1
            }
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        assert_eq!(
            extract_subject_digest(&bytes).unwrap().unwrap().as_str(),
            SHA256_1
        );

        let no_subject = serde_json::json!({ "schemaVersion": 2 });
        let bytes_no_subject = serde_json::to_vec(&no_subject).unwrap();
        assert_eq!(extract_subject_digest(&bytes_no_subject).unwrap(), None);
    }

    #[test]
    fn test_parse_referrer_info() {
        let manifest = serde_json::json!({
            "subject": {
                "digest": SHA256_1
            },
            "artifactType": "application/vnd.example.sbom.v1",
            "annotations": {
                "author": "Alice"
            }
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let (subject, artifact_type, annotations) = parse_referrer_info(&bytes)
            .unwrap()
            .expect("parsed referrer info");
        assert_eq!(subject.as_str(), SHA256_1);
        assert_eq!(
            artifact_type.as_deref(),
            Some("application/vnd.example.sbom.v1")
        );
        let ann = annotations.expect("annotations present");
        assert_eq!(ann.get("author").map(|s| s.as_str()), Some("Alice"));
    }

    #[test]
    fn test_helper_iterators() {
        let manifest = serde_json::json!({
            "config": { "digest": SHA256_1 },
            "layers": [{ "digest": SHA256_2 }],
            "blobs": [{ "digest": SHA256_3 }],
            "manifests": [{ "digest": SHA256_4 }],
            "subject": { "digest": SHA512_1 }
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let refs = parse_manifest_refs(&bytes).expect("parsed");

        let blob_refs: Vec<String> = refs.blob_references().map(|d| d.as_str()).collect();
        assert_eq!(blob_refs, vec![SHA256_1, SHA256_2, SHA256_3]);

        let manifest_refs: Vec<String> = refs.manifest_references().map(|d| d.as_str()).collect();
        assert_eq!(manifest_refs, vec![SHA256_4, SHA512_1]);

        let all_refs: Vec<String> = refs.all_references().map(|d| d.as_str()).collect();
        assert_eq!(
            all_refs,
            vec![SHA256_1, SHA256_2, SHA256_3, SHA256_4, SHA512_1]
        );
    }

    #[test]
    fn test_backward_compatibility_with_old_persisted_manifest_refs() {
        // Exact raw byte fixture previously written by proxy.rs into Sled:
        let old_persisted_json = br#"{"blobs":["sha256:1111111111111111111111111111111111111111111111111111111111111111"],"manifests":["sha256:2222222222222222222222222222222222222222222222222222222222222222"]}"#;
        let refs: ManifestRefs =
            serde_json::from_slice(old_persisted_json).expect("deserialize old record format");
        assert_eq!(refs.config, None);
        assert!(refs.layers.is_empty());
        assert_eq!(refs.blobs.len(), 1);
        assert_eq!(refs.blobs[0].as_str(), SHA256_1);
        assert_eq!(refs.manifests.len(), 1);
        assert_eq!(refs.manifests[0].as_str(), SHA256_2);
        assert_eq!(refs.subject, None);
    }
}
