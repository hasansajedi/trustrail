# Frequently asked questions

## Which profile should I start with?

Use `Guard.balanced()` for most new applications. Choose `default()` when false
positives are particularly costly and `strict()` when untrusted content can
trigger tools, data access, or other side effects. Tune with a representative
benign and adversarial test corpus before production.

## What is the difference between `check` and `protect`?

`check` always returns a structured `GuardResult`. `protect` returns the safe or
transformed value and raises `GuardrailBlockedError` when the decision is
`BLOCK`. Use `check` when your application needs custom handling and `protect`
for a concise enforcement boundary.

## Does trustrail replace provider moderation?

No. It provides deterministic application-layer controls and provider adapter
protocols. Use it alongside model-provider safety systems, authorization,
sandboxing, output encoding, rate limiting, and normal secure development
practices.

## Where should checks run?

At every trust boundary: user input, retrieved documents, tool arguments, tool
responses, model output, and persistent memory. Select the matching `GuardStage`
so the correct policy set runs.

## Can I log findings safely?

Use an audit sink, but avoid logging complete prompts or detected secrets unless
your retention and access controls explicitly permit it. Prefer request IDs,
rule IDs, actions, scores, and redacted metadata.

## Why was apparently safe content blocked?

Inspect `result.findings`, including each rule ID, severity, message, and
confidence. Reproduce the case in a test, then decide whether to change the
profile, add contextual handling, or adjust a specific rule. Do not globally
disable a category to solve one false positive without reviewing the resulting
coverage gap.

## Is synchronous checking safe in async applications?

Use `await guard.acheck(...)` or `await guard.aprotect(...)` in async request
handlers. The synchronous API is appropriate for scripts and synchronous web
stacks.

## How should upgrades be deployed?

Pin the package version, run your benign and attack corpora against the new
version, review the changelog, and deploy gradually while monitoring rule-level
decision rates.
