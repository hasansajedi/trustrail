"""Optional OpenTelemetry integration for trustrail.

Import is guarded — requires 'otel' extra: pip install trustrail[otel]
"""

from __future__ import annotations

from trustrail.models.core import AuditEvent


def setup_otel(service_name: str = "trustrail") -> None:
    """Initialize OpenTelemetry tracing for trustrail.

    Requires: pip install trustrail[otel]
    """
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.sdk.trace import TracerProvider

        resource = Resource(attributes={SERVICE_NAME: service_name})
        provider = TracerProvider(resource=resource)
        trace.set_tracer_provider(provider)
    except ImportError as exc:
        message = "OpenTelemetry is not installed. Run: pip install trustrail[otel]"
        raise ImportError(message) from exc


class OtelAuditSink:
    """Audit sink that emits OpenTelemetry spans and attributes.

    Requires: pip install trustrail[otel]
    """

    def __init__(self, tracer_name: str = "trustrail") -> None:
        try:
            from opentelemetry import trace

            self._tracer = trace.get_tracer(tracer_name)
            self._available = True
        except ImportError:
            self._available = False

    async def emit(self, event: AuditEvent) -> None:
        if not self._available:
            return

        with self._tracer.start_as_current_span("trustrail.guard.check") as span:
            span.set_attribute("trustrail.stage", event.stage.value)
            span.set_attribute("trustrail.action", event.action.value)
            span.set_attribute("trustrail.score", event.score)
            span.set_attribute("trustrail.rules_evaluated", event.rules_evaluated)
            span.set_attribute("trustrail.latency_ms", event.latency_ms)
            span.set_attribute("trustrail.input_length", event.input_length)
            span.set_attribute("trustrail.finding_count", len(event.finding_ids))

            if event.request_id:
                span.set_attribute("trustrail.request_id", event.request_id)

            if event.finding_categories:
                span.set_attribute(
                    "trustrail.findings",
                    ",".join(event.finding_categories),
                )
