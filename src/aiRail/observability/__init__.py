"""aiRail observability — optional OpenTelemetry integration."""

from aiRail.observability.otel import OtelAuditSink, setup_otel

__all__ = ["OtelAuditSink", "setup_otel"]
