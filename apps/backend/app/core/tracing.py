"""OpenTelemetry tracing integration for the security assessment platform.

Provides distributed tracing for:
- Scan operations and job execution
- Plugin execution
- Database operations
- HTTP requests
- Celery task execution
"""

from collections.abc import Callable
from contextvars import ContextVar
from functools import wraps
from typing import Any, Optional

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
    OTLPSpanExporter as OTLPSpanExporterHTTP,
)
from opentelemetry.instrumentation.celery import CeleryInstrumentor
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
try:
    from opentelemetry.instrumentation.psycopg import PsycopgInstrumentor
except ImportError:
    from opentelemetry.instrumentation.psycopg2 import Psycopg2Instrumentor as PsycopgInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.propagate import set_global_textmap
from opentelemetry.propagators.b3 import B3MultiFormat
from opentelemetry.propagators.composite import CompositePropagator
from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter, SpanExporter
from opentelemetry.trace import SpanKind, Status, StatusCode, SpanContext

from app.config import get_settings

# Context variable for trace correlation
current_trace_id: ContextVar[str | None] = ContextVar("current_trace_id", default=None)
current_span_id: ContextVar[str | None] = ContextVar("current_span_id", default=None)

# Global tracer instance
_tracer: trace.Tracer | None = None
_is_initialized = False


def init_tracing(
    service_name: str = "sasp-backend",
    service_version: str = "0.1.0",
    otlp_endpoint: str | None = None,
    use_console_exporter: bool = False,
) -> trace.Tracer:
    """Initialize OpenTelemetry tracing.
    
    Args:
        service_name: Name of the service
        service_version: Version of the service
        otlp_endpoint: OTLP endpoint (e.g., "http://otel-collector:4318/v1/traces" or "otel-collector:4317")
        use_console_exporter: Whether to also export to console (for debugging)
    
    Returns:
        Configured tracer instance
    """
    global _tracer, _is_initialized

    if _is_initialized:
        return _tracer

    settings = get_settings()

    # Create resource with service info
    resource = Resource.create({
        SERVICE_NAME: service_name,
        SERVICE_VERSION: service_version,
        "deployment.environment": settings.app_env,
    })

    # Create tracer provider
    provider = TracerProvider(resource=resource)
    trace.set_tracer_provider(provider)

    # Configure exporters
    if otlp_endpoint:
        if otlp_endpoint.startswith("http"):
            # HTTP exporter
            exporter: SpanExporter = OTLPSpanExporterHTTP(endpoint=otlp_endpoint)
        else:
            # gRPC exporter
            exporter = OTLPSpanExporter(endpoint=otlp_endpoint)

        provider.add_span_processor(BatchSpanProcessor(exporter))

    if use_console_exporter or settings.app_env == "development":
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    # Set global propagator for context propagation (B3 + W3C)
    set_global_textmap(CompositePropagator([B3MultiFormat()]))

    # Get tracer
    _tracer = trace.get_tracer(service_name, service_version)
    _is_initialized = True

    return _tracer


def get_tracer() -> trace.Tracer:
    """Get the global tracer instance."""
    global _tracer
    if _tracer is None:
        _tracer = init_tracing()
    return _tracer


def instrument_all(
    app=None,
    celery_app=None,
    engine=None,
    redis_client=None,
) -> None:
    """Auto-instrument common libraries.
    
    Args:
        app: FastAPI application instance
        celery_app: Celery application instance
        engine: SQLAlchemy engine
        redis_client: Redis client
    """
    # FastAPI instrumentation
    if app:
        FastAPIInstrumentor.instrument_app(
            app,
            tracer_provider=trace.get_tracer_provider(),
            excluded_urls="/health,/metrics,/favicon.ico",
        )

    # Celery instrumentation
    if celery_app:
        CeleryInstrumentor().instrument()

    # SQLAlchemy instrumentation
    if engine:
        SQLAlchemyInstrumentor().instrument(engine=engine)

    # Psycopg instrumentation
    PsycopgInstrumentor().instrument()

    # Redis instrumentation
    if redis_client:
        RedisInstrumentor().instrument(redis_client=redis_client)

    # Requests instrumentation
    RequestsInstrumentor().instrument()


# =============================================================================
# Tracing Helpers
# =============================================================================

def start_span(
    name: str,
    kind: SpanKind = SpanKind.INTERNAL,
    attributes: dict[str, Any] | None = None,
    links: list[trace.Link] | None = None,
) -> trace.Span:
    """Start a new span with the given attributes."""
    tracer = get_tracer()
    span = tracer.start_span(name, kind=kind, attributes=attributes or {}, links=links or [])

    # Update context variables
    span_context = span.get_span_context()
    current_trace_id.set(format(span_context.trace_id, "032x"))
    current_span_id.set(format(span_context.span_id, "016x"))

    return span


def end_span(span: trace.Span, status: StatusCode = StatusCode.OK, error: Exception | None = None) -> None:
    """End a span with optional error status."""
    if error:
        span.record_exception(error)
        span.set_status(Status(StatusCode.ERROR, str(error)))
    else:
        span.set_status(Status(status))
    span.end()


def trace_function(
    name: str | None = None,
    kind: SpanKind = SpanKind.INTERNAL,
    attributes: dict[str, Any] | None = None,
):
    """Decorator to trace a function."""
    def decorator(func: Callable) -> Callable:
        span_name = name or f"{func.__module__}.{func.__qualname__}"

        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            span = start_span(span_name, kind=kind, attributes=attributes)
            try:
                result = func(*args, **kwargs)
                end_span(span)
                return result
            except Exception as e:
                end_span(span, error=e)
                raise

        @wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            span = start_span(span_name, kind=kind, attributes=attributes)
            try:
                result = await func(*args, **kwargs)
                end_span(span)
                return result
            except Exception as e:
                end_span(span, error=e)
                raise

        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    return decorator


def add_span_attributes(attributes: dict[str, Any]) -> None:
    """Add attributes to the current span."""
    span = trace.get_current_span()
    if span and span.is_recording():
        for key, value in attributes.items():
            span.set_attribute(key, value)


def add_span_event(name: str, attributes: dict[str, Any] | None = None) -> None:
    """Add an event to the current span."""
    span = trace.get_current_span()
    if span and span.is_recording():
        span.add_event(name, attributes or {})


def get_current_trace_id() -> str | None:
    """Get the current trace ID from context."""
    return current_trace_id.get()


def get_current_span_id() -> str | None:
    """Get the current span ID from context."""
    return current_span_id.get()


def inject_context(carrier: dict[str, str]) -> None:
    """Inject current trace context into a carrier (for propagation)."""
    from opentelemetry.propagate import inject
    inject(carrier)


def extract_context(carrier: dict[str, str]) -> trace.SpanContext:
    """Extract trace context from a carrier."""
    from opentelemetry.propagate import extract
    ctx = extract(carrier)
    return trace.get_current_span(ctx).get_span_context()


# =============================================================================
# Celery Task Tracing
# =============================================================================

class TracedTaskMixin:
    """Mixin to add tracing to Celery tasks."""

    def apply_async(self, args=None, kwargs=None, **options):
        # Inject trace context into task headers
        headers = options.get("headers", {})
        inject_context(headers)
        options["headers"] = headers
        return super().apply_async(args, kwargs, **options)

    def __call__(self, *args, **kwargs):
        # Extract trace context from headers if present
        headers = kwargs.get("headers", {})
        if headers:
            ctx = extract_context(headers)
            # The context is automatically used by the tracer
        return super().__call__(*args, **kwargs)


def trace_celery_task(task_name: str | None = None):
    """Decorator to trace a Celery task."""
    def decorator(func: Callable) -> Callable:
        span_name = task_name or f"celery.task.{func.__name__}"

        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Extract context from headers
            headers = kwargs.pop("headers", {})
            ctx = extract_context(headers)

            tracer = get_tracer()
            with tracer.start_as_current_span(span_name, context=ctx, kind=SpanKind.CONSUMER) as span:
                # Add task metadata
                span.set_attribute("celery.task.name", func.__name__)
                span.set_attribute("celery.task.args_count", len(args))

                try:
                    result = func(*args, **kwargs)
                    span.set_status(Status(StatusCode.OK))
                    return result
                except Exception as e:
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    raise

        return wrapper
    return decorator


# =============================================================================
# Database Tracing
# =============================================================================

def trace_db_operation(operation: str, table: str | None = None):
    """Decorator to trace database operations."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            tracer = get_tracer()
            span_name = f"db.{operation}"
            if table:
                span_name += f".{table}"

            with tracer.start_as_current_span(span_name, kind=SpanKind.CLIENT) as span:
                span.set_attribute("db.operation", operation)
                if table:
                    span.set_attribute("db.table", table)

                try:
                    result = func(*args, **kwargs)
                    span.set_status(Status(StatusCode.OK))
                    return result
                except Exception as e:
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    raise

        @wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            tracer = get_tracer()
            span_name = f"db.{operation}"
            if table:
                span_name += f".{table}"

            with tracer.start_as_current_span(span_name, kind=SpanKind.CLIENT) as span:
                span.set_attribute("db.operation", operation)
                if table:
                    span.set_attribute("db.table", table)

                try:
                    result = await func(*args, **kwargs)
                    span.set_status(Status(StatusCode.OK))
                    return result
                except Exception as e:
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    raise

        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    return decorator


# =============================================================================
# Scan Operation Tracing
# =============================================================================

def trace_scan_operation(operation: str):
    """Decorator to trace scan operations."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            tracer = get_tracer()
            span_name = f"scan.{operation}"

            with tracer.start_as_current_span(span_name, kind=SpanKind.INTERNAL) as span:
                # Add scan metadata from args/kwargs
                if args and hasattr(args[0], "id"):
                    span.set_attribute("scan.id", str(args[0].id))
                if args and hasattr(args[0], "project_id"):
                    span.set_attribute("scan.project_id", str(args[0].project_id))
                if "scan_id" in kwargs:
                    span.set_attribute("scan.id", str(kwargs["scan_id"]))
                if "project_id" in kwargs:
                    span.set_attribute("scan.project_id", str(kwargs["project_id"]))

                try:
                    result = func(*args, **kwargs)
                    span.set_status(Status(StatusCode.OK))
                    return result
                except Exception as e:
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    raise

        @wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            tracer = get_tracer()
            span_name = f"scan.{operation}"

            with tracer.start_as_current_span(span_name, kind=SpanKind.INTERNAL) as span:
                if args and hasattr(args[0], "id"):
                    span.set_attribute("scan.id", str(args[0].id))
                if args and hasattr(args[0], "project_id"):
                    span.set_attribute("scan.project_id", str(args[0].project_id))
                if "scan_id" in kwargs:
                    span.set_attribute("scan.id", str(kwargs["scan_id"]))
                if "project_id" in kwargs:
                    span.set_attribute("scan.project_id", str(kwargs["project_id"]))

                try:
                    result = await func(*args, **kwargs)
                    span.set_status(Status(StatusCode.OK))
                    return result
                except Exception as e:
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    raise

        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    return decorator


def trace_plugin_execution(plugin_name: str):
    """Decorator to trace plugin execution."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            tracer = get_tracer()
            span_name = f"plugin.{plugin_name}"

            with tracer.start_as_current_span(span_name, kind=SpanKind.INTERNAL) as span:
                span.set_attribute("plugin.name", plugin_name)

                try:
                    result = func(*args, **kwargs)
                    span.set_status(Status(StatusCode.OK))
                    return result
                except Exception as e:
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    raise

        @wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            tracer = get_tracer()
            span_name = f"plugin.{plugin_name}"

            with tracer.start_as_current_span(span_name, kind=SpanKind.INTERNAL) as span:
                span.set_attribute("plugin.name", plugin_name)

                try:
                    result = await func(*args, **kwargs)
                    span.set_status(Status(StatusCode.OK))
                    return result
                except Exception as e:
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    raise

        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    return decorator


# =============================================================================
# HTTP Client Tracing
# =============================================================================

def trace_http_request(url: str, method: str):
    """Create a span for an outgoing HTTP request."""
    tracer = get_tracer()
    span_name = f"http.{method}.{url}"

    span = tracer.start_span(span_name, kind=SpanKind.CLIENT)
    span.set_attribute("http.method", method)
    span.set_attribute("http.url", url)
    return span
