# Adaptive prompt-injection regression

Static examples are necessary but insufficient: small changes in casing,
whitespace, punctuation, or invisible characters can reopen a previously fixed
prompt-injection path. aiRail's adaptive regression gate expands reviewed seed
cases with deterministic mutations and blocks a merge when configured metrics
regress.

The repository baseline currently requires:

- 100% blocking across all generated attack variants;
- 0% blocking across all generated benign variants; and
- stable, unique case IDs so failures are actionable without printing payloads.

The gate runs on pull requests to `main` or `develop`, pushes to those branches,
and the weekly security workflow. It complements broader manual and model-assisted
red teaming; it does not generate novel semantic attacks or prove resistance to an
adaptive adversary.

Review corpus changes like code. Require a reason for lowering thresholds, never
place real secrets or customer prompts in the repository, and test every supported
input boundary with the appropriate `GuardStage`. A passing gate is evidence that
known cases remain fixed, not a certification that prompt injection is solved.
