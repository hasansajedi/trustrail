# Observability

Every async guard evaluation can emit an `AuditEvent` containing decisions and
operational metadata without storing the checked content.

```python
from trustrail import Guard, LoggingAuditSink, MemoryAuditSink

guard = Guard.balanced()
guard = Guard(audit_sink=LoggingAuditSink())

test_sink = MemoryAuditSink()
test_guard = Guard(audit_sink=test_sink)
```

Register an in-process severity callback for immediate alerts:

```python
from trustrail import Severity

def alert(result):
    print(result.stage, result.score.value)

guard.on(Severity.HIGH, alert)
```

## OpenTelemetry

```bash
python -m pip install "trustrail[otel]"
```

```python
from trustrail import Guard
from trustrail.observability import OtelAuditSink, setup_otel

setup_otel(service_name="chat-api")
guard = Guard(audit_sink=OtelAuditSink())
```

Audit events include rule IDs/categories, action, score, latency, input length,
and context identifiers. They intentionally omit input content. Treat request,
user, session, and tenant identifiers as sensitive metadata and configure trace
retention accordingly.
