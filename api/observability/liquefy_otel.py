#!/usr/bin/env python3
"""
Optional OpenTelemetry exporter for Liquefy.

This module is best-effort:
- If OTEL env/config is absent, it's a no-op.
- If otel dependencies are missing, it's a no-op.
"""

import os
from typing import Optional

_INITIALIZED = False
_ENABLED = False
_TRACER = None
_H_RATIO = None
_H_DURATION = None
_C_BYTES_SAVED = None


def _init_once() -> bool:
    global _INITIALIZED, _ENABLED, _TRACER, _H_RATIO, _H_DURATION, _C_BYTES_SAVED
    if _INITIALIZED:
        return _ENABLED
    _INITIALIZED = True

    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    if not endpoint:
        _ENABLED = False
        return False

    try:
        from opentelemetry import metrics, trace
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = Resource.create(
            {
                "service.name": os.environ.get("OTEL_SERVICE_NAME", "liquefy"),
                "service.version": os.environ.get("OTEL_SERVICE_VERSION", "2026.2"),
            }
        )

        tracer_provider = TracerProvider(resource=resource)
        tracer_provider.add_span_processor(
            BatchSpanProcessor(
                OTLPSpanExporter(
                    endpoint=endpoint,
                    insecure=True,
                )
            )
        )
        trace.set_tracer_provider(tracer_provider)
        _TRACER = trace.get_tracer("liquefy")

        meter_provider = MeterProvider(
            resource=resource,
            metric_readers=[
                PeriodicExportingMetricReader(
                    OTLPMetricExporter(
                        endpoint=endpoint,
                        insecure=True,
                    )
                )
            ],
        )
        metrics.set_meter_provider(meter_provider)
        meter = metrics.get_meter("liquefy")
        _H_RATIO = meter.create_histogram("liquefy.compression.ratio")
        _H_DURATION = meter.create_histogram("liquefy.compression.duration_ms")
        _C_BYTES_SAVED = meter.create_counter("liquefy.bytes_saved_total")

        _ENABLED = True
        return True
    except Exception:
        _ENABLED = False
        return False


def track_compression(
    *,
    engine_id: str,
    tenant_id: str,
    bytes_in: int,
    bytes_out: int,
    duration_ms: float,
) -> None:
    if not _init_once():
        return

    attrs = {
        "engine": str(engine_id),
        "tenant": str(tenant_id),
    }
    ratio = float(bytes_in / max(1, bytes_out))
    saved = int(bytes_in - bytes_out)

    try:
        span = _TRACER.start_span("liquefy.compress")
        span.set_attribute("engine", str(engine_id))
        span.set_attribute("tenant", str(tenant_id))
        span.set_attribute("bytes_in", int(bytes_in))
        span.set_attribute("bytes_out", int(bytes_out))
        span.set_attribute("bytes_saved", int(saved))
        span.set_attribute("ratio", ratio)
        span.set_attribute("duration_ms", float(duration_ms))
        span.end()
    except Exception:
        pass

    try:
        _H_RATIO.record(ratio, attributes=attrs)
        _H_DURATION.record(float(duration_ms), attributes=attrs)
        if saved > 0:
            _C_BYTES_SAVED.add(saved, attributes=attrs)
    except Exception:
        pass
