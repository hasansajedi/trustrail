"""Adaptive prompt-injection regression gates for CI and local evaluation."""

from __future__ import annotations

import argparse
import re
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from trustrail.guard import Guard
from trustrail.models.core import GuardResult
from trustrail.models.enums import GuardAction, GuardStage

MutationName = Literal[
    "identity",
    "alternating_case",
    "expanded_whitespace",
    "punctuation_wrapper",
    "zero_width_interleave",
]


class GuardEvaluator(Protocol):
    """Minimal interface required by the regression gate."""

    def check(self, value: str, stage: GuardStage) -> GuardResult:
        """Evaluate one generated variant."""
        ...


class RedTeamCase(BaseModel):
    """One labeled seed case and its deterministic adaptive mutations."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
    text: str = Field(min_length=1)
    stage: GuardStage = GuardStage.USER_INPUT
    mutations: tuple[MutationName, ...] = ("identity",)


class RedTeamCorpus(BaseModel):
    """Labeled attacks, benign controls, and merge-gate thresholds."""

    model_config = ConfigDict(extra="forbid")

    attacks: tuple[RedTeamCase, ...] = Field(min_length=1)
    benign: tuple[RedTeamCase, ...] = Field(min_length=1)
    min_detection_rate: float = Field(default=1.0, ge=0.0, le=1.0)
    max_false_positive_rate: float = Field(default=0.0, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_unique_ids(self) -> RedTeamCorpus:
        """Keep failure identifiers unambiguous across both label sets."""
        ids = [case.id for case in (*self.attacks, *self.benign)]
        if len(ids) != len(set(ids)):
            raise ValueError("Red-team case IDs must be unique")
        return self

    @classmethod
    def from_path(cls, path: str | Path) -> RedTeamCorpus:
        """Load and validate a UTF-8 JSON corpus."""
        return cls.model_validate_json(Path(path).read_text(encoding="utf-8"))


class RedTeamGateReport(BaseModel):
    """Content-free metrics and failure identifiers from one gate run."""

    model_config = ConfigDict(extra="forbid")

    passed: bool
    attack_variants: int
    detected_attacks: int
    benign_variants: int
    false_positives: int
    detection_rate: float = Field(ge=0.0, le=1.0)
    false_positive_rate: float = Field(ge=0.0, le=1.0)
    min_detection_rate: float = Field(ge=0.0, le=1.0)
    max_false_positive_rate: float = Field(ge=0.0, le=1.0)
    missed_case_ids: list[str] = Field(default_factory=list)
    false_positive_case_ids: list[str] = Field(default_factory=list)

    def assert_passed(self) -> None:
        """Raise a content-free CI failure when configured thresholds are missed."""
        if not self.passed:
            raise AssertionError(
                "Prompt-injection red-team gate failed: "
                f"detection_rate={self.detection_rate:.3f}, "
                f"false_positive_rate={self.false_positive_rate:.3f}, "
                f"missed_case_ids={self.missed_case_ids}, "
                f"false_positive_case_ids={self.false_positive_case_ids}"
            )


def _identity(text: str) -> str:
    return text


def _alternating_case(text: str) -> str:
    upper = False
    output: list[str] = []
    for character in text:
        if character.isalpha():
            output.append(character.upper() if upper else character.lower())
            upper = not upper
        else:
            output.append(character)
    return "".join(output)


def _expanded_whitespace(text: str) -> str:
    return re.sub(r"\s+", "   \n  ", text)


def _punctuation_wrapper(text: str) -> str:
    return f"... --- {text} !!! :::"


def _zero_width_interleave(text: str) -> str:
    return "".join(f"{character}\u200b" if character.isalpha() else character for character in text)


_MUTATIONS: dict[MutationName, Callable[[str], str]] = {
    "identity": _identity,
    "alternating_case": _alternating_case,
    "expanded_whitespace": _expanded_whitespace,
    "punctuation_wrapper": _punctuation_wrapper,
    "zero_width_interleave": _zero_width_interleave,
}


def adaptive_variants(case: RedTeamCase) -> list[tuple[str, str]]:
    """Return stable variant IDs and values without changing the seed corpus."""
    return [
        (f"{case.id}::{mutation}", _MUTATIONS[mutation](case.text)) for mutation in case.mutations
    ]


class PromptInjectionRegressionGate:
    """Measure adaptive attack detection and benign blocking as a CI gate."""

    def __init__(self, evaluator: GuardEvaluator | None = None) -> None:
        self._evaluator = evaluator if evaluator is not None else Guard.silent()

    def run(self, corpus: RedTeamCorpus) -> RedTeamGateReport:
        """Evaluate all variants and return metrics without case content."""
        attack_variants = [
            (variant_id, value, case.stage)
            for case in corpus.attacks
            for variant_id, value in adaptive_variants(case)
        ]
        benign_variants = [
            (variant_id, value, case.stage)
            for case in corpus.benign
            for variant_id, value in adaptive_variants(case)
        ]

        missed_case_ids = self._failed_ids(attack_variants, expect_block=True)
        false_positive_case_ids = self._failed_ids(benign_variants, expect_block=False)
        detected_attacks = len(attack_variants) - len(missed_case_ids)
        false_positives = len(false_positive_case_ids)
        detection_rate = detected_attacks / len(attack_variants)
        false_positive_rate = false_positives / len(benign_variants)
        passed = (
            detection_rate >= corpus.min_detection_rate
            and false_positive_rate <= corpus.max_false_positive_rate
        )
        return RedTeamGateReport(
            passed=passed,
            attack_variants=len(attack_variants),
            detected_attacks=detected_attacks,
            benign_variants=len(benign_variants),
            false_positives=false_positives,
            detection_rate=detection_rate,
            false_positive_rate=false_positive_rate,
            min_detection_rate=corpus.min_detection_rate,
            max_false_positive_rate=corpus.max_false_positive_rate,
            missed_case_ids=missed_case_ids,
            false_positive_case_ids=false_positive_case_ids,
        )

    def _failed_ids(
        self,
        variants: Sequence[tuple[str, str, GuardStage]],
        *,
        expect_block: bool,
    ) -> list[str]:
        failed: list[str] = []
        for variant_id, value, stage in variants:
            result = self._evaluator.check(value, stage)
            is_blocked = result.action == GuardAction.BLOCK
            if is_blocked != expect_block:
                failed.append(variant_id)
        return failed


def main(argv: list[str] | None = None) -> int:
    """Run a JSON corpus as a shell-friendly regression gate."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    args = parser.parse_args(argv)
    corpus = RedTeamCorpus.from_path(args.corpus)
    report = PromptInjectionRegressionGate().run(corpus)
    print(report.model_dump_json(indent=2))
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
