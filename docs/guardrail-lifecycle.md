# Guardrail lifecycle

A production guardrail is a maintained control, not a one-time configuration.

## 1. Model the boundary

List every source of untrusted text and every consequential sink. Map each to a
`GuardStage`, then document controls outside trustrail such as authorization,
schema validation, escaping, and network isolation.

## 2. Establish a baseline

Start with `Guard.balanced()`. Build a labeled corpus containing normal domain
traffic, edge cases, known attacks, multilingual text, and encoded payloads.
Measure decisions per rule and stage.

## 3. Tune and test

Adjust thresholds or add focused custom rules. Add every production false
positive and confirmed bypass as a regression test. Test fail-open and
fail-closed behavior explicitly.

## 4. Deploy gradually

Run in observation mode at low-risk boundaries first, compare decisions with
current behavior, and then enable blocking. Keep rollback configuration ready.

## 5. Monitor and review

Track allow, warn, and block rates; latency; rule failures; and top finding IDs.
Review sharp changes by release, tenant, route, and model. Re-evaluate controls
when models, tools, prompts, retrieval sources, or business workflows change.
