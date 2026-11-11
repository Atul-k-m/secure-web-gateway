"""Phase 2: the inspection CA and minted leaf certificates."""

import datetime as dt

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from swg.certs import ISSUING_NAME, ROOT_NAME, CertificateAuthority, LeafCertCache, crl_url_of


def verify(ca: CertificateAuthority, leaf: x509.Certificate, name: str) -> None:
    """Validate leaf -> issuing CA -> root the way a TLS client does
    (RFC 5280 path validation plus host name matching)."""
    verifier = (
        PolicyBuilder()
        .store(Store([ca.root_cert]))
        .time(dt.datetime.now(dt.timezone.utc))
        .build_server_verifier(x509.DNSName(name))
    )
    verifier.verify(leaf, [ca.issuing_cert])


def test_chain_is_root_then_issuing_then_leaf(inspection_ca):
    root, issuing = inspection_ca.root_cert, inspection_ca.issuing_cert
    assert root.subject == root.issuer  # self-signed
    assert ROOT_NAME in root.subject.rfc4514_string()
    assert issuing.issuer == root.subject
    assert ISSUING_NAME in issuing.subject.rfc4514_string()
    root_bc = root.extensions.get_extension_for_class(x509.BasicConstraints).value
    issuing_bc = issuing.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert root_bc.ca and root_bc.path_length == 1
    assert issuing_bc.ca and issuing_bc.path_length == 0


def test_minted_leaf_validates_like_a_browser_would(inspection_ca):
    leaf = inspection_ca.mint_leaf("www.example.com")
    verify(inspection_ca, leaf, "www.example.com")
    with pytest.raises(VerificationError):
        verify(inspection_ca, leaf, "other.example.com")  # wrong name is rejected


def test_leaf_fields(inspection_ca):
    leaf = inspection_ca.mint_leaf("shop.example.org")
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["shop.example.org"]
    assert not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    lifetime = leaf.not_valid_after_utc - leaf.not_valid_before_utc
    assert lifetime <= dt.timedelta(days=31)
    assert leaf.not_valid_before_utc < dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=12)


def test_ip_leaf_uses_ip_san(inspection_ca):
    leaf = inspection_ca.mint_leaf("192.0.2.7")
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert [str(ip) for ip in san.get_values_for_type(x509.IPAddress)] == ["192.0.2.7"]


def test_long_host_name_fits(inspection_ca):
    host = ("a" * 60) + ".example.com"  # longer than the 64-char CN limit
    leaf = inspection_ca.mint_leaf(host)
    verify(inspection_ca, leaf, host)


def test_ca_is_reused_across_restarts(tmp_path):
    first = CertificateAuthority.load_or_create(tmp_path)
    second = CertificateAuthority.load_or_create(tmp_path)
    assert first.fingerprint == second.fingerprint
    assert (tmp_path / "swg-root-ca.crt").exists() and (tmp_path / "swg-root-ca.key").exists()


def test_crl_links_point_back_at_the_gateway(tmp_path):
    ca = CertificateAuthority.load_or_create(tmp_path, "http://gw.test:3128/")
    assert crl_url_of(ca.issuing_cert) == "http://gw.test:3128/crl/root.crl"
    assert crl_url_of(ca.mint_leaf("a.example")) == "http://gw.test:3128/crl/issuing.crl"
    assert crl_url_of(ca.root_cert) is None  # a trust anchor is never revocation-checked

    # A new gateway URL re-issues the intermediate but keeps the root,
    # so clients that already trust the root keep working.
    moved = CertificateAuthority.load_or_create(tmp_path, "http://10.0.0.5:3128")
    assert moved.fingerprint == ca.fingerprint
    assert crl_url_of(moved.issuing_cert) == "http://10.0.0.5:3128/crl/root.crl"


def test_crls_are_empty_and_correctly_signed(tmp_path):
    ca = CertificateAuthority.load_or_create(tmp_path, "http://gw.test:3128")
    for which, issuer in (("root", ca.root_cert), ("issuing", ca.issuing_cert)):
        crl = x509.load_der_x509_crl(ca.crl(which))
        assert crl.issuer == issuer.subject
        assert crl.is_signature_valid(issuer.public_key())
        assert len(crl) == 0  # nothing revoked
        assert crl.next_update_utc > dt.datetime.now(dt.timezone.utc)


def test_cache_mints_once_and_refuses_bad_names(tmp_path):
    cache = LeafCertCache(CertificateAuthority.load_or_create(tmp_path), max_entries=2)
    first = cache.context_for("a.example")
    assert cache.context_for("A.Example.") is first  # normalized: same entry
    assert cache.minted == 1
    cache.context_for("b.example")
    cache.context_for("c.example")  # evicts a.example (least recently used)
    cache.context_for("a.example")
    assert cache.minted == 4
    for bad in ("", "../../etc/passwd", "a b.example", "x" * 300):
        with pytest.raises(ValueError):
            cache.context_for(bad)
