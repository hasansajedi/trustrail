"""Security corpus and bypass regressions for OWASP LLM03:2025."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustrail import (
    ArtifactDigest,
    ArtifactKind,
    ArtifactManifest,
    ArtifactObservation,
    ArtifactRecord,
    ArtifactVerifier,
    DigestAlgorithm,
    GuardAction,
    TrustLevel,
)

CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "supply_chain_artifacts.json"
TRUSTED_DIGEST = ArtifactDigest(
    value="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
)


def _cases() -> list[dict[str, str]]:
    return json.loads(CORPUS_PATH.read_text())


def _record() -> ArtifactRecord:
    return ArtifactRecord(
        artifact_id="model.approved",
        kind=ArtifactKind.MODEL,
        supplier="approved-supplier",
        source_uri="https://models.example/approved",
        revision="commit-8f1c2d3e",
        digest=TRUSTED_DIGEST,
        trust_level=TrustLevel.TRUSTED,
        approved=True,
    )


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["name"])
def test_supply_chain_security_corpus(case: dict[str, str]):
    record = _record()
    observation = ArtifactObservation(
        artifact_id=record.artifact_id,
        kind=record.kind,
        supplier=record.supplier,
        source_uri=record.source_uri,
        revision=record.revision,
        digest=record.digest,
    )
    mutation = case["mutation"]
    if mutation == "digest":
        observation = observation.model_copy(update={"digest": ArtifactDigest(value="0" * 64)})
    elif mutation == "algorithm-substitution":
        observation = observation.model_copy(
            update={
                "digest": ArtifactDigest(
                    algorithm=DigestAlgorithm.SHA512,
                    value="0" * 128,
                )
            }
        )
    elif mutation == "supplier":
        observation = observation.model_copy(update={"supplier": "approved-supplier.evil"})
    elif mutation == "source":
        observation = observation.model_copy(
            update={"source_uri": "https://models.example.evil/approved"}
        )
    elif mutation == "revision":
        observation = observation.model_copy(update={"revision": "commit-8f1c2d3e-malicious"})
    elif mutation == "unknown-lookalike-id":
        observation = observation.model_copy(update={"artifact_id": "model.approved-lookalike"})

    result = ArtifactVerifier(
        ArtifactManifest(manifest_id="security-corpus", artifacts=(record,))
    ).verify(observation)

    assert result.action == GuardAction(case["expected_action"])


@pytest.mark.parametrize(
    "revision",
    ["latest", "refs/heads/main", "models/STABLE", "release-*", "^2.4.0", ">=3.0"],
)
def test_mutable_revision_bypasses_are_blocked(revision: str):
    record = _record().model_copy(update={"revision": revision})
    observation = ArtifactObservation(
        artifact_id=record.artifact_id,
        kind=record.kind,
        supplier=record.supplier,
        source_uri=record.source_uri,
        revision=record.revision,
        digest=record.digest,
    )

    result = ArtifactVerifier(
        ArtifactManifest(manifest_id="mutable-revisions", artifacts=(record,))
    ).verify(observation)

    assert result.is_blocked
