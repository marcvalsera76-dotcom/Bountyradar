"""Suite del ScopeValidator: deny-by-default, IDNA, anti-sufijo, anti-IP-ambigua."""

import pytest

from app.core.scope import (
    ScopeError,
    ScopeValidator,
    normalize_target,
    parse_rule,
)

# --------------------------------------------------------------------------- #
# Normalización de destinos
# --------------------------------------------------------------------------- #


def test_normalize_lowercases_domain():
    assert str(normalize_target("EXAMPLE.COM")) == "example.com"


def test_normalize_strips_trailing_dot():
    assert str(normalize_target("example.com.")) == "example.com"


def test_normalize_extracts_host_from_url():
    assert str(normalize_target("https://sub.example.com/path?q=1")) == "sub.example.com"


def test_normalize_strips_port_bare_host():
    assert str(normalize_target("example.com:8443")) == "example.com"


def test_normalize_strips_port_from_url():
    assert str(normalize_target("http://example.com:8080/")) == "example.com"


def test_normalize_idna_unicode_domain():
    # bücher.example -> xn--bcher-kva.example
    assert str(normalize_target("bücher.example")) == "xn--bcher-kva.example"


def test_normalize_ipv4():
    assert str(normalize_target("127.0.0.1")) == "127.0.0.1"


def test_normalize_ipv6_bracketed_with_port():
    assert str(normalize_target("[2001:db8::1]:443")) == "2001:db8::1"


def test_normalize_ipv6_plain():
    assert str(normalize_target("2001:db8::1")) == "2001:db8::1"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "singlelabel",
        "http://user:pass@example.com/",
        "user:pass@example.com",
        "exa mple.com",
        "example..com",
        "-example.com",
        "exam_ple.com",
    ],
)
def test_normalize_rejects_malformed(bad):
    with pytest.raises(ScopeError):
        normalize_target(bad)


@pytest.mark.parametrize(
    "ambiguous_ip",
    [
        "127.0.0.01",      # cero a la izquierda
        "2130706433",      # entero
        "0x7f.0.0.1",      # hex
        "0177.0.0.1",      # octal
        "999.0.0.1",       # fuera de rango
    ],
)
def test_normalize_rejects_ambiguous_ip(ambiguous_ip):
    with pytest.raises(ScopeError):
        normalize_target(ambiguous_ip)


# --------------------------------------------------------------------------- #
# Parseo de reglas
# --------------------------------------------------------------------------- #


def test_parse_rule_exact():
    assert parse_rule("example.com").kind == "exact"


def test_parse_rule_wildcard():
    r = parse_rule("*.example.com")
    assert r.kind == "wildcard"
    assert str(r.value) == "example.com"


def test_parse_rule_ip():
    assert parse_rule("10.0.0.5").kind == "ip"


def test_parse_rule_cidr():
    assert parse_rule("10.0.0.0/8").kind == "cidr"


def test_parse_rule_rejects_bad_cidr():
    with pytest.raises(ScopeError):
        parse_rule("10.0.0.0/33")


def test_parse_rule_rejects_empty():
    with pytest.raises(ScopeError):
        parse_rule("   ")


# --------------------------------------------------------------------------- #
# Coincidencia exacta de dominio
# --------------------------------------------------------------------------- #


def test_exact_matches_itself():
    v = ScopeValidator(in_scope=["example.com"])
    assert v.is_in_scope("example.com") is True


def test_exact_does_not_match_subdomain():
    v = ScopeValidator(in_scope=["example.com"])
    assert v.is_in_scope("sub.example.com") is False


def test_exact_anti_suffix_notexample():
    v = ScopeValidator(in_scope=["example.com"])
    assert v.is_in_scope("notexample.com") is False


# --------------------------------------------------------------------------- #
# Comodines
# --------------------------------------------------------------------------- #


def test_wildcard_matches_subdomain():
    v = ScopeValidator(in_scope=["*.example.com"])
    assert v.is_in_scope("api.example.com") is True


def test_wildcard_matches_deep_subdomain():
    v = ScopeValidator(in_scope=["*.example.com"])
    assert v.is_in_scope("a.b.c.example.com") is True


def test_wildcard_does_not_match_apex():
    v = ScopeValidator(in_scope=["*.example.com"])
    assert v.is_in_scope("example.com") is False


def test_wildcard_anti_suffix():
    v = ScopeValidator(in_scope=["*.example.com"])
    assert v.is_in_scope("evilexample.com") is False


def test_wildcard_does_not_match_other_domain():
    v = ScopeValidator(in_scope=["*.example.com"])
    assert v.is_in_scope("api.example.org") is False


# --------------------------------------------------------------------------- #
# IPs y CIDRs
# --------------------------------------------------------------------------- #


def test_ip_exact_match():
    v = ScopeValidator(in_scope=["10.0.0.5"])
    assert v.is_in_scope("10.0.0.5") is True


def test_ip_exact_no_match():
    v = ScopeValidator(in_scope=["10.0.0.5"])
    assert v.is_in_scope("10.0.0.6") is False


def test_cidr_contains_ip():
    v = ScopeValidator(in_scope=["10.0.0.0/24"])
    assert v.is_in_scope("10.0.0.200") is True


def test_cidr_excludes_outside_ip():
    v = ScopeValidator(in_scope=["10.0.0.0/24"])
    assert v.is_in_scope("10.0.1.1") is False


def test_cidr_version_mismatch_is_denied():
    v = ScopeValidator(in_scope=["10.0.0.0/8"])
    assert v.is_in_scope("2001:db8::1") is False


def test_domain_rule_does_not_match_ip():
    v = ScopeValidator(in_scope=["example.com"])
    assert v.is_in_scope("93.184.216.34") is False


# --------------------------------------------------------------------------- #
# Deny-by-default y prioridad out-of-scope
# --------------------------------------------------------------------------- #


def test_deny_by_default_empty_scope():
    v = ScopeValidator()
    assert v.is_in_scope("example.com") is False


def test_deny_by_default_no_match():
    v = ScopeValidator(in_scope=["example.com"])
    assert v.is_in_scope("other.org") is False


def test_out_of_scope_overrides_in_scope():
    v = ScopeValidator(in_scope=["*.example.com"], out_of_scope=["admin.example.com"])
    assert v.is_in_scope("admin.example.com") is False


def test_out_of_scope_cidr_overrides_in_scope():
    v = ScopeValidator(in_scope=["10.0.0.0/8"], out_of_scope=["10.0.0.0/24"])
    assert v.is_in_scope("10.0.0.5") is False
    assert v.is_in_scope("10.1.0.5") is True


def test_in_scope_allowed_when_not_excluded():
    v = ScopeValidator(in_scope=["*.example.com"], out_of_scope=["admin.example.com"])
    assert v.is_in_scope("api.example.com") is True


# --------------------------------------------------------------------------- #
# check() devuelve motivo auditable
# --------------------------------------------------------------------------- #


def test_check_returns_reason_on_allow():
    v = ScopeValidator(in_scope=["example.com"])
    ok, reason = v.check("example.com")
    assert ok is True
    assert "permitido" in reason


def test_check_returns_reason_on_default_deny():
    v = ScopeValidator(in_scope=["example.com"])
    ok, reason = v.check("other.com")
    assert ok is False
    assert "por defecto" in reason


def test_check_returns_reason_on_out_of_scope():
    v = ScopeValidator(in_scope=["*.example.com"], out_of_scope=["admin.example.com"])
    ok, reason = v.check("admin.example.com")
    assert ok is False
    assert "out-of-scope" in reason


def test_check_returns_reason_on_unnormalizable():
    v = ScopeValidator(in_scope=["example.com"])
    ok, reason = v.check("user:pass@example.com")
    assert ok is False
    assert "no normalizable" in reason


def test_check_malformed_input_is_denied_not_raised():
    v = ScopeValidator(in_scope=["example.com"])
    assert v.is_in_scope("") is False
    assert v.is_in_scope("exa mple.com") is False
