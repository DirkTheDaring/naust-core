# naust-core

Registry-object primitives for the [Naust](https://github.com/DirkTheDaring/naust)
OCI/Docker container registry: value types, storage capability ports with
filesystem and S3 reference backends, upload/manifest/membership/GC engines,
the blob reference index, consistency coordination, and transport-neutral
application services. Deliberately free of HTTP, auth, and server
configuration — anyone can build a registry on top
(see `examples/minimal_registry.rs`).

Version 0.x: explicitly unstable until a second consumer exists (ADR-010 in
the naust repository, which also holds this crate's pre-split history and the
architecture documentation).

Path dependencies: expects `../storage-layer-rust`
([repo](https://github.com/DirkTheDaring/storage-layer-rust)) checked out as a
sibling.

Licensed under the [MIT License](LICENSE).
