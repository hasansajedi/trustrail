"""Run an adaptive prompt-injection regression gate suitable for CI."""

from pathlib import Path

from trustrail.testing.red_team import PromptInjectionRegressionGate, RedTeamCorpus

repository_root = Path(__file__).resolve().parents[1]
corpus = RedTeamCorpus.from_path(
    repository_root / "tests/security_corpus/adaptive_prompt_injection.json"
)
report = PromptInjectionRegressionGate().run(corpus)

print(report.model_dump_json(indent=2))
report.assert_passed()
