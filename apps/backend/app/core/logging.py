"""Structured logging configuration with request ID and trace correlation."""

import logging
import sys
import uuid
from contextvars import ContextVar
from typing import Any

from pythonjsonlogger import jsonlogger

# Context variable to hold request ID across async boundaries
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
# Context variable to hold trace ID across async boundaries
trace_id_var: ContextVar[str | None] = ContextVar("trace_id", default=None)
# Context variable to hold span ID across async boundaries
span_id_var: ContextVar[str | None] = ContextVar("span_id", default=None)


class RequestIdFilter(logging.Filter):
    """Inject request_id, trace_id, and span_id into log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get() or "-"
        record.trace_id = trace_id_var.get() or "-"
        record.span_id = span_id_var.get() or "-"
        return True


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter with consistent fields."""

    def add_fields(self, log_record: dict[str, Any], record: logging.LogRecord, message_dict: dict[str, Any]) -> None:
        super().add_fields(log_record, record, message_dict)
        # Ensure standard fields
        log_record["timestamp"] = self.formatTime(record)
        log_record["level"] = record.levelname
        log_record["logger"] = record.name
        log_record["request_id"] = getattr(record, "request_id", "-")
        log_record["trace_id"] = getattr(record, "trace_id", "-")
        log_record["span_id"] = getattr(record, "span_id", "-")

        # Move message to standard field
        if "message" in log_record:
            log_record["msg"] = log_record.pop("message")


def setup_logging(level: str = "INFO", json_format: bool = False) -> None:
    """Configure application-wide logging.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        json_format: If True, output JSON lines; otherwise human-readable
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))

    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(RequestIdFilter())

    if json_format:
        formatter = CustomJsonFormatter(
            "%(timestamp)s %(level)s %(logger)s %(request_id)s %(trace_id)s %(span_id)s %(msg)s"
        )
    else:
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(request_id)s | %(trace_id)s | %(span_id)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

    # Reduce noise from third-party libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("alembic").setLevel(logging.INFO)
    logging.getLogger("celery").setLevel(logging.INFO)


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the given name."""
    return logging.getLogger(name)


def set_request_id(request_id: str | None = None) -> str:
    """Set the request ID for the current context.

    Returns the request ID that was set (generated if not provided).
    """
    rid = request_id or uuid.uuid4().hex[:12]
    request_id_var.set(rid)
    return rid


def get_request_id() -> str | None:
    """Get the current request ID."""
    return request_id_var.get()


def set_trace_context(trace_id: str | None = None, span_id: str | None = None) -> None:
    """Set trace context for the current context."""
    if trace_id:
        trace_id_var.set(trace_id)
    if span_id:
        span_id_var.set(span_id)


def get_trace_id() -> str | None:
    """Get the current trace ID."""
    return trace_id_var.get()


def get_span_id() -> str | None:
    """Get the current span ID."""
    return span_id_var.get()


class LogContext:
    """Context manager for adding structured context to logs."""

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.old_factory = logging.getLogRecordFactory()

    def __enter__(self) -> "LogContext":
        def record_factory(*args: Any, **kw: Any) -> logging.LogRecord:
            record = self.old_factory(*args, **kw)
            for key, value in self.kwargs.items():
                setattr(record, key, value)
            return record

        logging.setLogRecordFactory(record_factory)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        logging.setLogRecordFactory(self.old_factory)


class StructuredLogger:
    """Structured logger with context support."""

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    def _log(self, level: int, msg: str, **kwargs: Any) -> None:
        """Log with extra fields."""
        extra = {k: v for k, v in kwargs.items() if k not in ("exc_info", "stack_info")}
        self._logger.log(level, msg, extra=extra, **{k: v for k, v in kwargs.items() if k in ("exc_info", "stack_info")})

    def debug(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.DEBUG, msg, **kwargs)

    def info(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.INFO, msg, **kwargs)

    def warning(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.WARNING, msg, **kwargs)

    def error(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.ERROR, msg, **kwargs)

    def critical(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.CRITICAL, msg, **kwargs)

    def exception(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.ERROR, msg, exc_info=True, **kwargs)


def get_structured_logger(name: str) -> StructuredLogger:
    """Get a structured logger with context support."""
    return StructuredLogger(logging.getLogger(name))
