"""Tests de RateLimitService, TokenBucket y presupuestos."""

import pytest

from app.core.ratelimit import (
    Budget,
    BudgetTracker,
    RateLimitConfig,
    RateLimitService,
    TokenBucket,
)


class FakeClock:
    def __init__(self, t: float = 0.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def _svc(clock, g=100, p=100, h=100) -> RateLimitService:
    cfg = RateLimitConfig(global_rps=g, per_program_rps=p, per_host_rps=h)
    return RateLimitService(cfg, clock)


# --------------------------------------------------------------------------- #
# TokenBucket
# --------------------------------------------------------------------------- #


def test_bucket_allows_up_to_capacity():
    b = TokenBucket(rate=1.0, capacity=3.0, now=0.0)
    assert b.try_acquire(0.0)
    assert b.try_acquire(0.0)
    assert b.try_acquire(0.0)
    assert not b.try_acquire(0.0)


def test_bucket_refills_over_time():
    b = TokenBucket(rate=2.0, capacity=2.0, now=0.0)
    assert b.try_acquire(0.0)
    assert b.try_acquire(0.0)
    assert not b.try_acquire(0.0)
    # 1 segundo -> +2 tokens
    assert b.try_acquire(1.0)


def test_bucket_capacity_caps_refill():
    b = TokenBucket(rate=100.0, capacity=5.0, now=0.0)
    # Mucho tiempo pero no supera la capacidad.
    assert b.available(1000.0) == 5.0


def test_bucket_rejects_bad_params():
    with pytest.raises(ValueError):
        TokenBucket(rate=0, capacity=1)
    with pytest.raises(ValueError):
        TokenBucket(rate=1, capacity=0)


# --------------------------------------------------------------------------- #
# RateLimitService
# --------------------------------------------------------------------------- #


def test_service_allows_within_limits():
    clock = FakeClock(0.0)
    svc = _svc(clock, g=20, p=10, h=5)
    ok, _ = svc.allow("prog", "host.example.com")
    assert ok is True


def test_service_host_limit_blocks():
    clock = FakeClock(0.0)
    svc = _svc(clock, h=2)
    assert svc.allow("prog", "h")[0] is True
    assert svc.allow("prog", "h")[0] is True
    blocked, reason = svc.allow("prog", "h")
    assert blocked is False
    assert "host" in reason


def test_service_program_limit_blocks():
    clock = FakeClock(0.0)
    svc = _svc(clock, p=2)
    assert svc.allow("prog", "a")[0] is True
    assert svc.allow("prog", "b")[0] is True
    blocked, reason = svc.allow("prog", "c")
    assert blocked is False
    assert "programa" in reason


def test_service_global_limit_blocks():
    clock = FakeClock(0.0)
    svc = _svc(clock, g=2)
    assert svc.allow("p1", "a")[0] is True
    assert svc.allow("p2", "b")[0] is True
    blocked, reason = svc.allow("p3", "c")
    assert blocked is False
    assert "global" in reason


def test_service_recovers_after_time():
    clock = FakeClock(0.0)
    svc = _svc(clock, h=1)
    assert svc.allow("prog", "h")[0] is True
    assert svc.allow("prog", "h")[0] is False
    clock.t = 2.0
    assert svc.allow("prog", "h")[0] is True


# --------------------------------------------------------------------------- #
# Budget / BudgetTracker
# --------------------------------------------------------------------------- #


def test_budget_spends_until_limit():
    b = Budget(limit=3)
    assert b.try_spend()
    assert b.try_spend(2)
    assert not b.try_spend()
    assert b.exhausted
    assert b.remaining == 0


def test_budget_rejects_nonpositive():
    with pytest.raises(ValueError):
        Budget(limit=5).try_spend(0)


def test_tracker_task_budget_blocks():
    t = BudgetTracker(task_limit=2, campaign_limit=100)
    assert t.try_spend("task1")[0] is True
    assert t.try_spend("task1")[0] is True
    ok, reason = t.try_spend("task1")
    assert ok is False
    assert "tarea" in reason


def test_tracker_campaign_budget_blocks():
    t = BudgetTracker(task_limit=100, campaign_limit=3)
    assert t.try_spend("a")[0] is True
    assert t.try_spend("b")[0] is True
    assert t.try_spend("c")[0] is True
    ok, reason = t.try_spend("d")
    assert ok is False
    assert "campaña" in reason


def test_tracker_independent_task_budgets():
    t = BudgetTracker(task_limit=1, campaign_limit=100)
    assert t.try_spend("task1")[0] is True
    assert t.try_spend("task1")[0] is False
    # Otra tarea tiene su propio presupuesto.
    assert t.try_spend("task2")[0] is True
