"""trustrail observability — optional OpenTelemetry integration."""

from trustrail.observability.otel import OtelAuditSink, setup_otel

__all__ = ["OtelAuditSink", "setup_otel"]
