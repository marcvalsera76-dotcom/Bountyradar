"""Suite del PolicyEngine: modos, aprobaciones graduales y acciones prohibidas."""

from app.core.policy import (
    ExploitType,
    OperationMode,
    PolicyEngine,
    ProgramPolicy,
)

ENGINE = PolicyEngine()


def _pol(**kw) -> ProgramPolicy:
    return ProgramPolicy(name="test", **kw)


# --------------------------------------------------------------------------- #
# PASSIVE: permitido por defecto
# --------------------------------------------------------------------------- #


def test_passive_allowed_by_default():
    assert ENGINE.allowed(_pol(), "recon.passive") is True


def test_scope_import_allowed_by_default():
    assert ENGINE.allowed(_pol(), "scope.import") is True


# --------------------------------------------------------------------------- #
# SAFE_ACTIVE
# --------------------------------------------------------------------------- #


def test_safe_active_denied_when_disabled():
    assert ENGINE.allowed(_pol(), "http.probe") is False


def test_safe_active_allowed_when_enabled():
    assert ENGINE.allowed(_pol(safe_active_enabled=True), "http.probe") is True


def test_dns_resolve_requires_safe_active():
    assert ENGINE.allowed(_pol(), "dns.resolve") is False
    assert ENGINE.allowed(_pol(safe_active_enabled=True), "dns.resolve") is True


# --------------------------------------------------------------------------- #
# FULL_ACTIVE: habilitación + aprobación por tarea
# --------------------------------------------------------------------------- #


def test_full_active_denied_when_disabled():
    assert ENGINE.allowed(_pol(), "content.discovery", task_approved=True) is False


def test_full_active_denied_without_task_approval():
    assert ENGINE.allowed(_pol(full_active_enabled=True), "content.discovery") is False


def test_full_active_allowed_with_enable_and_approval():
    ok = ENGINE.allowed(
        _pol(full_active_enabled=True), "content.discovery", task_approved=True
    )
    assert ok is True


def test_port_scan_is_full_active():
    d = ENGINE.evaluate(_pol(), "port.scan")
    assert d.required_mode is OperationMode.FULL_ACTIVE


# --------------------------------------------------------------------------- #
# EXPLOIT_HUNT: requiere base activa + habilitación + tipo aprobado
# --------------------------------------------------------------------------- #


def test_exploit_hunt_requires_active_base():
    pol = _pol(exploit_hunt_enabled=True, approved_exploit_types=frozenset({ExploitType.IDOR}))
    # sin SAFE_ACTIVE ni FULL_ACTIVE
    d = ENGINE.evaluate(pol, "exploit.validate", exploit_type=ExploitType.IDOR)
    assert d.allowed is False
    assert "SAFE_ACTIVE o FULL_ACTIVE" in d.reason


def test_exploit_hunt_requires_enabled_flag():
    pol = _pol(safe_active_enabled=True, approved_exploit_types=frozenset({ExploitType.IDOR}))
    d = ENGINE.evaluate(pol, "exploit.validate", exploit_type=ExploitType.IDOR)
    assert d.allowed is False
    assert "EXPLOIT_HUNT no habilitado" in d.reason


def test_exploit_hunt_requires_exploit_type():
    pol = _pol(safe_active_enabled=True, exploit_hunt_enabled=True)
    d = ENGINE.evaluate(pol, "exploit.validate")
    assert d.allowed is False
    assert "requiere tipo de exploit" in d.reason


def test_exploit_hunt_requires_type_approved():
    pol = _pol(
        safe_active_enabled=True,
        exploit_hunt_enabled=True,
        approved_exploit_types=frozenset({ExploitType.SSRF}),
    )
    d = ENGINE.evaluate(pol, "exploit.validate", exploit_type=ExploitType.IDOR)
    assert d.allowed is False
    assert "no aprobado" in d.reason


def test_exploit_hunt_allowed_when_all_conditions_met():
    pol = _pol(
        safe_active_enabled=True,
        exploit_hunt_enabled=True,
        approved_exploit_types=frozenset({ExploitType.IDOR}),
    )
    d = ENGINE.evaluate(pol, "exploit.validate", exploit_type=ExploitType.IDOR)
    assert d.allowed is True
    assert "EXPLOIT_HUNT" in d.reason


def test_exploit_hunt_works_with_full_active_base():
    pol = _pol(
        full_active_enabled=True,
        exploit_hunt_enabled=True,
        approved_exploit_types=frozenset({ExploitType.SQLI}),
    )
    assert ENGINE.allowed(pol, "poc.generate", exploit_type=ExploitType.SQLI) is True


# --------------------------------------------------------------------------- #
# Acciones prohibidas: denegadas SIEMPRE
# --------------------------------------------------------------------------- #


def test_dos_always_prohibited_even_full_active():
    pol = _pol(safe_active_enabled=True, full_active_enabled=True, exploit_hunt_enabled=True)
    d = ENGINE.evaluate(pol, "dos", task_approved=True)
    assert d.allowed is False
    assert "prohibida" in d.reason


def test_bruteforce_prohibited():
    assert ENGINE.allowed(_pol(full_active_enabled=True), "bruteforce", task_approved=True) is False


def test_phishing_prohibited():
    assert ENGINE.allowed(_pol(), "phishing") is False


def test_data_destroy_prohibited():
    pol = _pol(full_active_enabled=True)
    assert ENGINE.allowed(pol, "data_destroy", task_approved=True) is False


# --------------------------------------------------------------------------- #
# Deny-by-default para operaciones desconocidas
# --------------------------------------------------------------------------- #


def test_unknown_operation_denied():
    d = ENGINE.evaluate(_pol(safe_active_enabled=True), "magic.exploit")
    assert d.allowed is False
    assert "desconocida" in d.reason


# --------------------------------------------------------------------------- #
# autopilot_modes según habilitaciones
# --------------------------------------------------------------------------- #


def test_autopilot_only_passive_by_default():
    modes = ENGINE.autopilot_modes(_pol())
    assert modes == frozenset({OperationMode.PASSIVE})


def test_autopilot_adds_safe_active():
    modes = ENGINE.autopilot_modes(_pol(safe_active_enabled=True))
    assert OperationMode.SAFE_ACTIVE in modes
    assert OperationMode.PASSIVE in modes


def test_autopilot_exploit_hunt_needs_active_base():
    # exploit_hunt habilitado pero sin base activa -> no se añade
    modes = ENGINE.autopilot_modes(_pol(exploit_hunt_enabled=True))
    assert OperationMode.EXPLOIT_HUNT not in modes


def test_autopilot_full_chain():
    pol = _pol(safe_active_enabled=True, full_active_enabled=True, exploit_hunt_enabled=True)
    modes = ENGINE.autopilot_modes(pol)
    assert modes == frozenset(
        {
            OperationMode.PASSIVE,
            OperationMode.SAFE_ACTIVE,
            OperationMode.FULL_ACTIVE,
            OperationMode.EXPLOIT_HUNT,
        }
    )


# --------------------------------------------------------------------------- #
# Decision expone el modo requerido
# --------------------------------------------------------------------------- #


def test_decision_exposes_required_mode():
    d = ENGINE.evaluate(_pol(), "http.probe")
    assert d.required_mode is OperationMode.SAFE_ACTIVE


def test_allowed_matches_evaluate():
    pol = _pol(safe_active_enabled=True)
    assert ENGINE.allowed(pol, "tech.detect") == ENGINE.evaluate(pol, "tech.detect").allowed
