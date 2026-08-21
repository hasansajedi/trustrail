# Resource consumption

LLM applications can be exhausted through large inputs, repeated requests,
recursive agents, expensive retrieval, or unbounded output. aiRail applies
resource rules at every guard stage and provides agent execution budgets.

```python
from aiRail import Guard, GuardConfig

guard = Guard(
    GuardConfig(
        max_text_length=20_000,
        timeout_seconds=3.0,
        block_at=60,
        warn_at=30,
    )
)
```

`max_text_length` is a character limit, not a model-token or HTTP byte limit.

## Resource limit rules

| Rule ID | Name | What it enforces |
| --- | --- | --- |
| RL-001 | Input Length | Maximum character and byte count per request |
| RL-002 | Token Estimate | Maximum estimated tokens (1 token ≈ 4 chars) |
| RL-003 | Message Count | Maximum conversation turns via `message_count` metadata |
| RL-004 | Repetitive Pattern | Blocks inputs with a high ratio of repeated n-grams (token bombs) |
| RL-005 | Cumulative Token Budget | Tracks estimated token usage per session; blocks when budget is exceeded |
| RL-006 | Nesting Depth Bomb | Blocks JSON/XML payloads with excessive nesting depth |

## Token-bomb detection (RL-004)

A token-bomb payload repeats the same short phrase thousands of times. It can
stay within raw character limits while inflating model compute costs
significantly. `RepetitivePatternRule` measures the fraction of 4-gram sequences
that repeat and blocks inputs above a threshold.

```python
from aiRail.rules.resource import RepetitivePatternRule

rule = RepetitivePatternRule(
    ngram_size=4,
    max_repetition_ratio=0.4,  # block if >40% of 4-grams repeat
    min_words=50,              # only check inputs with ≥50 words
)
```

## Cumulative session budget (RL-005)

Slow resource exhaustion attacks stay within per-request limits but aggregate
large token cost across multiple turns. `CumulativeTokenBudgetRule` tracks
estimated token usage per `session_id` and blocks further requests once the
session total exceeds a configured budget.

```python
from aiRail.rules.resource import CumulativeTokenBudgetRule

rule = CumulativeTokenBudgetRule(session_budget_tokens=100_000)
# Pass a consistent session_id in GuardContext for accurate tracking
```

Token estimates use the same 1 token ≈ 4 characters approximation as RL-002.
The budget counter resets only when the rule instance is replaced (e.g., on
process restart). For persistent budgets across restarts, maintain the counter
in your own session store and pass the current total via `context.metadata`.

## Nesting depth bomb detection (RL-006)

A 1 KB JSON payload with 500 levels of nesting can crash naive parsers or
cause stack overflows in LLM context-processing code. `NestingDepthRule`
measures the maximum bracket (`{[`) and XML tag depth using a lightweight
heuristic — no full parse is required.

```python
from aiRail.rules.resource import NestingDepthRule

rule = NestingDepthRule(
    max_json_depth=100,   # max allowed JSON/array nesting
    max_xml_depth=100,    # max allowed XML element nesting
)
result = rule.evaluate(request_body, context)
```

The rule inspects up to 200 000 characters of the input. For JSON it counts
`{` and `[` characters; for XML it uses a lightweight tag scanner. Both checks
are performed on every evaluation call.

## Enforce limits at every layer

- Request bytes and upload sizes at the proxy or server.
- Parsed object depth and collection length at schema validation.
- Model input/output token and monetary budgets.
- Retrieval count, document size, and embedding concurrency.
- Tool timeouts, response sizes, and network concurrency.
- Per-user and per-tenant rate limits at the API gateway.

Reject oversized data before buffering it in memory whenever the framework
supports streaming limits.
