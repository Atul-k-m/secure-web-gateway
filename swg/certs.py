"""The inspection CA, and leaf certificates minted per host on demand.

To read HTTPS traffic the gateway has to *be* the server the browser talks
to, so it needs a certificate for every site, signed by a CA the browser
trusts. The chain it presents looks like this:

    SWG Inspection Root CA        <- installed in the client's trust store
      └─ SWG Inspection Issuing CA   <- sent by the gateway with each leaf
           └─ example.com            <- minted on the fly from the SNI

Commercial SWGs use the same shape: the root goes onto every managed laptop,
and day-to-day signing is done by an intermediate ("issuing") CA, so the root
key is needed only to create or replace the intermediate.

Files in the CA directory (default `ca/`, ignored by git):

    swg-root-ca.crt       root certificate (PEM). This is the one users install.
    swg-root-ca.key       root private key. Anyone holding it can impersonate
                          any website to your clients, so keep it secret.
    swg-issuing-ca.crt/.key   the intermediate
    leaf.key              one key shared by every minted leaf (see below)
    leaf-cache/           minted leaf + intermediate chains, one per host

Revocation: Windows (Schannel) refuses a certificate when it can't find out
whether it was revoked. So when the gateway knows its own URL, every
certificate below the root carries a CRL Distribution Point pointing back at
the gateway, which serves the (empty) revocation lists itself:

    issuing CA  ->  <gateway_url>/crl/root.crl     signed by the root
    leaf        ->  <gateway_url>/crl/issuing.crl  signed by the issuing CA
"""

from __future__ import annotations

import datetime as dt
import hashlib
import time
import ipaddress
import os
import re
import ssl
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT_NAME = "SWG Inspection Root CA"
ISSUING_NAME = "SWG Inspection Issuing CA"
ORGANIZATION = "secure-web-gateway"
ROOT_YEARS = 10
ISSUING_YEARS = 5
LEAF_DAYS = 30
BACKDATE = dt.timedelta(days=1)  # tolerate clients whose clocks run slow

# Characters a host name can contain (after IDNA encoding). Anything else in
# an SNI value is refused instead of minted.
_HOSTNAME = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)*\.?$")


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _ca_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True, key_cert_sign=True, crl_sign=True,
        content_commitment=False, key_encipherment=False, data_encipherment=False,
        key_agreement=False, encipher_only=False, decipher_only=False,
    )


def _leaf_usage() -> x509.KeyUsage:
    # An ECDSA leaf only ever signs (the handshake), it never encrypts.
    return x509.KeyUsage(
        digital_signature=True, key_cert_sign=False, crl_sign=False,
        content_commitment=False, key_encipherment=False, data_encipherment=False,
        key_agreement=False, encipher_only=False, decipher_only=False,
    )


def _write_key(path: Path, key) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    try:
        os.chmod(path, 0o600)  # owner-only on Linux/macOS; ignored on Windows
    except OSError:
        pass


def _read_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def is_valid_hostname(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOSTNAME.match(host))


def _crl_distribution_point(url: str) -> x509.CRLDistributionPoints:
    return x509.CRLDistributionPoints(
        [
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(url)],
                relative_name=None, reasons=None, crl_issuer=None,
            )
        ]
    )


def crl_url_of(cert: x509.Certificate) -> str | None:
    try:
        points = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    except x509.ExtensionNotFound:
        return None
    return points[0].full_name[0].value


@dataclass
class CertificateAuthority:
    directory: Path
    root_cert: x509.Certificate
    root_key: ec.EllipticCurvePrivateKey
    issuing_cert: x509.Certificate
    issuing_key: ec.EllipticCurvePrivateKey
    leaf_key: ec.EllipticCurvePrivateKey
    crl_base_url: str | None = None  # e.g. http://127.0.0.1:3128
    _crl_cache: dict = field(default_factory=dict, repr=False)

    @property
    def root_cert_path(self) -> Path:
        return self.directory / "swg-root-ca.crt"

    @property
    def leaf_key_path(self) -> Path:
        return self.directory / "leaf.key"

    @property
    def fingerprint(self) -> str:
        """SHA-256 of the root, as browsers and certmgr show it."""
        return self.root_cert.fingerprint(hashes.SHA256()).hex(":").upper()

    @classmethod
    def load_or_create(cls, directory: Path, crl_base_url: str | None = None) -> "CertificateAuthority":
        directory = Path(directory)
        crl_base_url = crl_base_url.rstrip("/") if crl_base_url else None
        root_crl_url = f"{crl_base_url}/crl/root.crl" if crl_base_url else None
        root_crt, root_key = directory / "swg-root-ca.crt", directory / "swg-root-ca.key"
        issuing_crt, issuing_key = directory / "swg-issuing-ca.crt", directory / "swg-issuing-ca.key"
        leaf_key = directory / "leaf.key"

        if not (root_crt.exists() and root_key.exists()):
            directory.mkdir(parents=True, exist_ok=True)
            key, cert = cls._make_root()
            _write_key(root_key, key)
            root_crt.write_bytes(_pem(cert))
            # A new root makes the old intermediate, leaves and cache useless.
            for stale in (issuing_crt, issuing_key):
                stale.unlink(missing_ok=True)
            cls._clear_leaf_cache(directory)

        root = x509.load_pem_x509_certificate(root_crt.read_bytes())
        if issuing_crt.exists() and issuing_key.exists():
            existing = x509.load_pem_x509_certificate(issuing_crt.read_bytes())
            if crl_url_of(existing) != root_crl_url:
                # The gateway URL changed, so the intermediate's CRL link is
                # wrong. Re-issue it; the root (what clients trust) stays.
                issuing_crt.unlink()
        if not (issuing_crt.exists() and issuing_key.exists()):
            key, cert = cls._make_issuing(root, _read_key(root_key), root_crl_url)
            _write_key(issuing_key, key)
            issuing_crt.write_bytes(_pem(cert))
            cls._clear_leaf_cache(directory)
        if not leaf_key.exists():
            _write_key(leaf_key, ec.generate_private_key(ec.SECP256R1()))
            cls._clear_leaf_cache(directory)

        return cls(
            directory=directory,
            root_cert=root,
            root_key=_read_key(root_key),
            issuing_cert=x509.load_pem_x509_certificate(issuing_crt.read_bytes()),
            issuing_key=_read_key(issuing_key),
            leaf_key=_read_key(leaf_key),
            crl_base_url=crl_base_url,
        )

    @staticmethod
    def _clear_leaf_cache(directory: Path) -> None:
        cache = directory / "leaf-cache"
        if cache.exists():
            for item in cache.glob("*.pem"):
                item.unlink()

    @staticmethod
    def _make_root():
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, ROOT_NAME),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION),
            ]
        )
        now = _now()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)  # self-signed: subject == issuer
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - BACKDATE)
            .not_valid_after(now + dt.timedelta(days=365 * ROOT_YEARS))
            # path_length=1: one level of CA (the issuing CA) may sit below it.
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(_ca_usage(), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )
        return key, cert

    @staticmethod
    def _make_issuing(root: x509.Certificate, root_key, crl_url: str | None):
        key = ec.generate_private_key(ec.SECP256R1())
        now = _now()
        builder = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, ISSUING_NAME),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION),
                    ]
                )
            )
            .issuer_name(root.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - BACKDATE)
            .not_valid_after(now + dt.timedelta(days=365 * ISSUING_YEARS))
            # path_length=0: it may sign leaves, but not further CAs.
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_ca_usage(), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False
            )
        )
        if crl_url:
            builder = builder.add_extension(_crl_distribution_point(crl_url), critical=False)
        return key, builder.sign(root_key, hashes.SHA256())

    def mint_leaf(self, host: str) -> x509.Certificate:
        """A server certificate for `host`, signed by the issuing CA."""
        try:
            san: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san = x509.DNSName(host)
        now = _now()
        builder = (
            x509.CertificateBuilder()
            # Clients match the host against subjectAltName; the CN is only
            # for people reading the certificate (and is capped at 64 chars).
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
            .issuer_name(self.issuing_cert.subject)
            .public_key(self.leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - BACKDATE)
            .not_valid_after(now + dt.timedelta(days=LEAF_DAYS))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_leaf_usage(), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.issuing_key.public_key()),
                critical=False,
            )
        )
        if self.crl_base_url:
            builder = builder.add_extension(
                _crl_distribution_point(f"{self.crl_base_url}/crl/issuing.crl"), critical=False
            )
        return builder.sign(self.issuing_key, hashes.SHA256())

    def crl(self, which: str) -> bytes:
        """A DER-encoded, empty CRL: "nothing issued by this CA is revoked".

        `which` is "root" (signed by the root, covers the issuing CA) or
        "issuing" (signed by the issuing CA, covers the leaves). Each is
        valid for 7 days and re-signed at most once an hour.
        """
        if which == "root":
            issuer, key = self.root_cert, self.root_key
        elif which == "issuing":
            issuer, key = self.issuing_cert, self.issuing_key
        else:
            raise KeyError(which)
        cached = self._crl_cache.get(which)
        if cached is not None and time.monotonic() - cached[0] < 3600:
            return cached[1]
        now = _now()
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(issuer.subject)
            .last_update(now - dt.timedelta(minutes=5))
            .next_update(now + dt.timedelta(days=7))
            .add_extension(x509.CRLNumber(int(now.timestamp())), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
            )
            .sign(key, hashes.SHA256())
        )
        der = crl.public_bytes(serialization.Encoding.DER)
        self._crl_cache[which] = (time.monotonic(), der)
        return der


class LeafCertCache:
    """Hands out a ready-to-use server SSLContext per host.

    Minting means one ECDSA signature plus loading the result into OpenSSL,
    so contexts are cached (least-recently-used first out). Every leaf reuses
    one key pair. That skips key generation, the slow part, and is what
    mitmproxy does too. The cost: that one key unlocks every minted cert, so
    it is as sensitive as the issuing CA key.
    """

    def __init__(self, ca: CertificateAuthority, max_entries: int = 1024):
        self.ca = ca
        self.max_entries = max_entries
        self.minted = 0  # how many leaves were signed (tests check caching)
        self._contexts: OrderedDict[str, tuple[ssl.SSLContext, dt.datetime]] = OrderedDict()
        self._dir = ca.directory / "leaf-cache"
        self._dir.mkdir(parents=True, exist_ok=True)

    def context_for(self, host: str) -> ssl.SSLContext:
        host = host.lower().rstrip(".")
        cached = self._contexts.get(host)
        if cached is not None and cached[1] - _now() > dt.timedelta(days=1):
            self._contexts.move_to_end(host)
            return cached[0]
        if not is_valid_hostname(host):
            raise ValueError(f"refusing to mint a certificate for {host[:80]!r}")

        leaf = self.ca.mint_leaf(host)
        self.minted += 1
        # OpenSSL loads certificates from files, so write leaf + intermediate.
        # The file name is a hash, so a hostile SNI can't choose a path.
        chain = self._dir / (hashlib.sha256(host.encode()).hexdigest()[:32] + ".pem")
        chain.write_bytes(_pem(leaf) + _pem(self.ca.issuing_cert))

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(chain, self.ca.leaf_key_path)
        # Offer HTTP/1.1 only: the gateway parses HTTP/1.1, so a browser
        # that would normally pick HTTP/2 falls back to 1.1 for this site.
        ctx.set_alpn_protocols(["http/1.1"])
        ctx.sni_callback = self._on_sni
        if os.environ.get("SSLKEYLOGFILE"):
            # Write session keys so Wireshark can decrypt the client side.
            # (The origin side already does this: create_default_context
            # reads the same variable.) For debugging only.
            ctx.keylog_filename = os.environ["SSLKEYLOGFILE"]

        self._contexts[host] = (ctx, leaf.not_valid_after_utc)
        while len(self._contexts) > self.max_entries:
            self._contexts.popitem(last=False)
        return ctx

    def _on_sni(self, ssl_object, server_name, _current_ctx):
        """Runs inside the handshake, right after the ClientHello is read.

        The handshake started with the certificate for the CONNECT host. If
        the client asks for a different name (SNI), switch to a certificate
        for that name before the server answers.
        """
        ssl_object.swg_sni = server_name  # read back later for the access log
        if server_name:
            try:  # usually the same, already-cached context: a dict lookup
                ssl_object.context = self.context_for(server_name)
            except ValueError:
                return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        return None
