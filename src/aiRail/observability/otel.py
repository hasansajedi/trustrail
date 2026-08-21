"""Optional OpenTelemetry integration for aiRail.

Import is guarded — requires 'otel' extra: pip install aiRail[otel]
"""

from __future__ import annotations

from aiRail.models.core import AuditEvent


def setup_otel(service_name: str = "aiRail") -> None:
    """Initialize OpenTelemetry tracing for aiRail.

    Requires: pip install aiRail[otel]
    """
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.sdk.trace import TracerProvider

        resource = Resource(attributes={SERVICE_NAME: service_name})
        provider = TracerProvider(resource=resource)
        trace.set_tracer_provider(provider)
    except ImportError as exc:
        raise ImportError("OpenTelemetry is not installed. Run: pip install aiRail[otel]") from exc


class OtelAuditSink:
    """Audit sink that emits OpenTelemetry spans and attributes.

    Requires: pip install aiRail[otel]
    """

    def __init__(self, tracer_name: str = "aiRail") -> None:
        try:
            from opentelemetry import trace

            self._tracer = trace.get_tracer(tracer_name)
            self._available = True
        except ImportError:
            self._available = False

    async def emit(self, event: AuditEvent) -> None:
        if not self._available:
            return

        with self._tracer.start_as_current_span("aiRail.guard.check") as span:
            span.set_attribute("aiRail.stage", event.stage.value)
            span.set_attribute("aiRail.action", event.action.value)
            span.set_attribute("aiRail.score", event.score)
            span.set_attribute("aiRail.rules_evaluated", event.rules_evaluated)
            span.set_attribute("aiRail.latency_ms", event.latency_ms)
            span.set_attribute("aiRail.input_length", event.input_length)
            span.set_attribute("aiRail.finding_count", len(event.finding_ids))

            if event.request_id:
                span.set_attribute("aiRail.request_id", event.request_id)

            if event.finding_categories:
                span.set_attribute(
                    "aiRail.findings",
                    ",".join(event.finding_categories),
                )
