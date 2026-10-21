"""Tests del AuditLogger."""

import pytest

from app.core.audit import AuditLogger, AuditRecord


def test_records_allow_and_deny():
    log = AuditLogger()
    log.allow("recon", "http.probe", destination="api.example.com", program="acme")
    log.deny("recon", "port.scan", reason="FULL_ACTIVE no habilitado")
    assert len(log.events) == 2
    assert log.events[0].decision == "ALLOW"
    assert log.events[1].decision == "DENY"


def test_record_rejects_bad_decision():
    log = AuditLogger()
    with pytest.raises(ValueError):
        log.record("actor", "op", "MAYBE")


def test_sink_is_called():
    captured: list[AuditRecord] = []
    log = AuditLogger(sink=captured.append)
    log.allow("actor", "scope.import")
    assert len(captured) == 1
    assert captured[0].operation == "scope.import"


def test_by_decision_filters():
    log = AuditLogger()
    log.allow("a", "op1")
    log.deny("a", "op2")
    log.deny("a", "op3")
    assert len(log.by_decision("DENY")) == 2
    assert len(log.by_decision("ALLOW")) == 1


def test_by_correlation_groups():
    log = AuditLogger()
    log.allow("a", "op1", correlation_id="run-1")
    log.deny("a", "op2", correlation_id="run-1")
    log.allow("a", "op3", correlation_id="run-2")
    assert len(log.by_correlation("run-1")) == 2
    assert len(log.by_correlation("run-2")) == 1


def test_events_returns_copy():
    log = AuditLogger()
    log.allow("a", "op1")
    snapshot = log.events
    snapshot.clear()
    assert len(log.events) == 1
