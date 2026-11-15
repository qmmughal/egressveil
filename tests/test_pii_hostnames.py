from __future__ import annotations

import pytest

from egressveil.detectors.hostnames import HostnameDetector
from egressveil.detectors.pii import iban_valid, luhn_valid, make_pii_detector

pii = make_pii_detector()


def pii_rules(text: str) -> list[tuple[str, str]]:
    return [(f.rule_id, text[f.start : f.end]) for f in pii.scan(text)]


# ----------------------------------------------------------------- PII positives


@pytest.mark.parametrize(
    ("text", "rule", "value"),
    [
        ("contact jane.doe@acme-corp.io today", "email", "jane.doe@acme-corp.io"),
        ("Signed-off-by: Ann <ann+ci@mail.acme.co.uk>", "email", "ann+ci@mail.acme.co.uk"),
        ("call +44 20 7946 0958 now", "phone_international", "+44 20 7946 0958"),
        ("tel: +1-415-555-0132", "phone_international", "+1-415-555-0132"),
        ("office (212) 555-0147 ext", "phone_nanp", "(212) 555-0147"),
        ("ssn=123-45-6789;", "us_ssn", "123-45-6789"),
        ("card 4111 1111 1111 1111 exp", "payment_card", "4111 1111 1111 1111"),
        ("card 5500-0000-0000-0004", "payment_card", "5500-0000-0000-0004"),
        ("amex 378282246310005", "payment_card", "378282246310005"),
        ("iban GB82 WEST 1234 5698 7654 32 ok", "iban", "GB82 WEST 1234 5698 7654 32"),
        ("DE89370400440532013000", "iban", "DE89370400440532013000"),
    ],
)
def test_pii_detected(text: str, rule: str, value: str) -> None:
    assert (rule, value) in pii_rules(text)


# ----------------------------------------------------------------- PII negatives


@pytest.mark.parametrize(
    "text",
    [
        "user@example.com and admin@test.example.org",
        "Co-Authored-By: Bot <noreply@anthropic.com>",
        "git@github.com:org/repo.git",
        "<img src='logo@2x.png'>",
        "123+qmmughal@users.noreply.github.com",
        "npm i @types/node",
        "version 1.2.3-alpha.4, build 2026-11-16",
        "order id 1234567890123",  # not Luhn / no issuer
        "4111 1111 1111 1112",  # fails Luhn
        "0000 0000 0000 0000",
        "000-12-3456 666-12-3456 900-12-3456 123-00-4567",  # invalid SSN ranges
        "GB82 WEST 1234 5698 7654 33",  # bad IBAN checksum
        "+1 2",  # too short for a phone number
        "timestamp=1731715200000",
        "sha 3f9a1c2b7d4e5f60718293a4b5c6d7e8f9012345",
    ],
)
def test_pii_not_flagged(text: str) -> None:
    assert pii_rules(text) == []


def test_checksum_helpers() -> None:
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")
    assert iban_valid("GB82WEST12345698765432")
    assert not iban_valid("GB82WEST12345698765433")
    assert not iban_valid("GB82")


# ----------------------------------------------------------------- hostnames


def hosts(detector: HostnameDetector, text: str) -> list[tuple[str, str]]:
    return [(f.rule_id, text[f.start : f.end]) for f in detector.scan(text)]


def test_configured_internal_domains() -> None:
    d = HostnameDetector(["corp.example.com", "acme.internal-net.io"])
    text = "ssh db01.corp.example.com; see corp.example.com; api.acme.internal-net.io:8443"
    found = hosts(d, text)
    assert ("internal_domain", "db01.corp.example.com") in found
    assert ("internal_domain", "corp.example.com") in found
    assert ("internal_domain", "api.acme.internal-net.io") in found


def test_common_internal_suffixes() -> None:
    d = HostnameDetector()
    found = hosts(d, "curl http://billing.svc.internal/ and jenkins.corp and nas.home.arpa")
    assert ("internal_suffix", "billing.svc.internal") in found
    assert ("internal_suffix", "jenkins.corp") in found
    assert ("internal_suffix", "nas.home.arpa") in found


@pytest.mark.parametrize(
    "text",
    [
        "connect to host.docker.internal:5432",
        "metadata.google.internal is the GCE metadata server",
        "the corp team uses a lan party",  # bare words, not hostnames
        "example.com and docs.python.org",
        "corp.example.com.evil.net",  # suffix must end the hostname
        "file.internal.txt",
        # Regressions from running `egressveil scan` on this repository:
        "config.detectors.internal_hostnames.enabled",
        'cfg.detectors["internal_hostnames"].internal_domains',
        "self.lan_port and obj._internal and x.corp_id",
    ],
)
def test_hostnames_not_flagged(text: str) -> None:
    assert hosts(HostnameDetector(["corp.example.com"]), text) == []


def test_common_suffixes_can_be_disabled() -> None:
    assert hosts(HostnameDetector(include_common_internal_suffixes=False), "a.internal") == []


def test_private_ips_are_opt_in() -> None:
    text = "db at 10.1.2.3, cache 172.20.0.5, router 192.168.1.1, public 8.8.8.8, bad 10.0.0.300"
    assert hosts(HostnameDetector(), text) == []
    found = [
        v
        for rule, v in hosts(HostnameDetector(include_private_ips=True), text)
        if rule == "private_ipv4"
    ]
    assert found == ["10.1.2.3", "172.20.0.5", "192.168.1.1"]
