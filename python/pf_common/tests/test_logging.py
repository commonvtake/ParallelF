import io
import json
import logging

from pf_common.logging import bind_context, clear_context, configure_logging


def _records(stream: io.StringIO) -> list[dict[str, object]]:
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def test_records_are_single_line_json_with_service_fields() -> None:
    stream = io.StringIO()
    configure_logging("pf-aid", "1.2.3", "info", stream)

    logging.getLogger("pf.test").info("investigation started", extra={"incident_id": "inc-1"})

    (record,) = _records(stream)
    assert record["msg"] == "investigation started"
    assert record["level"] == "INFO"
    assert record["service"] == "pf-aid"
    assert record["version"] == "1.2.3"
    assert record["incident_id"] == "inc-1"
    assert str(record["ts"]).endswith("+00:00")


def test_bound_context_is_added_and_cleared() -> None:
    stream = io.StringIO()
    configure_logging("svc", "v", "info", stream)
    log = logging.getLogger("pf.test")

    bind_context(request_id="req-1")
    bind_context(subject="user-1")
    log.info("inside request")
    clear_context()
    log.info("after request")

    inside, after = _records(stream)
    assert (inside["request_id"], inside["subject"]) == ("req-1", "user-1")
    assert "request_id" not in after
    assert "subject" not in after


def test_level_filtering_and_warn_name() -> None:
    stream = io.StringIO()
    configure_logging("svc", "v", "warn", stream)
    log = logging.getLogger("pf.test")

    log.info("hidden")
    log.warning("shown")

    (record,) = _records(stream)
    assert record["level"] == "WARN"


def test_exceptions_are_serialised() -> None:
    stream = io.StringIO()
    configure_logging("svc", "v", "info", stream)

    try:
        raise RuntimeError("boom")
    except RuntimeError:
        logging.getLogger("pf.test").exception("failed")

    (record,) = _records(stream)
    assert "RuntimeError: boom" in str(record["exception"])


def test_non_serialisable_extra_does_not_break_logging() -> None:
    stream = io.StringIO()
    configure_logging("svc", "v", "info", stream)

    logging.getLogger("pf.test").info("odd", extra={"payload": object()})

    (record,) = _records(stream)
    assert "object" in str(record["payload"])
