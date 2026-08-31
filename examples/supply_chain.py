"""Verify approved provenance and bytes before loading an AI component."""

from trustrail import (
    ArtifactKind,
    ArtifactManifest,
    ArtifactRecord,
    ArtifactVerifier,
    TrustLevel,
)

# Build and sign/pin this manifest in a trusted control plane, not from runtime
# artifact metadata. In this example the trusted bytes stand in for that step.
approved_bytes = b"reviewed adapter weights"
record = ArtifactRecord.from_bytes(
    artifact_id="support-adapter-v3",
    kind=ArtifactKind.ADAPTER,
    supplier="reviewed-ml-team",
    source_uri="https://artifacts.example.test/adapters/support-v3",
    revision="2026.08.31",
    payload=approved_bytes,
    trust_level=TrustLevel.TRUSTED,
    approved=True,
    license_id="Apache-2.0",
)
manifest = ArtifactManifest(manifest_id="production-ai-components", artifacts=(record,))
verifier = ArtifactVerifier(manifest)

# downloaded_bytes must be checked before deserialization, import, or execution.
downloaded_bytes = b"reviewed adapter weights"
result = verifier.require_bytes(record.artifact_id, downloaded_bytes)

print(f"Verified: {result.is_verified}")
print(f"Manifest fingerprint to pin separately: {manifest.fingerprint_sha256}")
