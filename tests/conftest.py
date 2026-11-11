import ssl

import pytest

from swg.certs import CertificateAuthority
from swg.policy import Policy
from swg.settings import Settings
from tests.support import GatewayThread, OriginServer, make_test_pki


@pytest.fixture(scope="session")
def pki(tmp_path_factory):
    """(ca, cert, key) for an origin that answers as localhost / 127.0.0.1."""
    return make_test_pki(tmp_path_factory.mktemp("pki"))


@pytest.fixture(scope="session")
def origin():
    with OriginServer() as server:
        yield server


@pytest.fixture(scope="session")
def tls_origin(pki):
    _, cert, key = pki
    with OriginServer(cert, key) as server:
        yield server


@pytest.fixture
def gateway(tmp_path):
    """Phase 1 behaviour: no inspection, allow everything."""
    settings = Settings(listen_port=0, access_log=tmp_path / "access.log", log_to_stdout=False)
    with GatewayThread(settings) as gw:
        yield gw


@pytest.fixture
def client_tls(pki):
    """A client TLS context that trusts the test origin's CA."""
    ca, _, _ = pki
    return ssl.create_default_context(cafile=str(ca))


@pytest.fixture(scope="session")
def inspection_ca(tmp_path_factory):
    """The gateway's own root + issuing CA, created once per test run."""
    return CertificateAuthority.load_or_create(tmp_path_factory.mktemp("swg-ca"))


@pytest.fixture
def trusts_gateway(inspection_ca):
    """A client that has the gateway's root CA installed, like a managed laptop."""
    return ssl.create_default_context(cafile=str(inspection_ca.root_cert_path))


@pytest.fixture
def start_gateway(tmp_path, pki, inspection_ca):
    """Factory: start_gateway(policy=..., inspect=True, trust_origin_ca=True)."""
    started = []

    def start(policy=None, inspect=True, trust_origin_ca=True):
        settings = Settings(
            listen_port=0,
            access_log=tmp_path / f"access-{len(started)}.log",
            log_to_stdout=False,
            inspect_tls=inspect,
            ca_dir=inspection_ca.directory,
            upstream_ca_file=pki[0] if trust_origin_ca else None,
        )
        gw = GatewayThread(settings, policy=policy or Policy(), ca=inspection_ca)
        gw.__enter__()
        started.append(gw)
        return gw

    yield start
    for gw in started:
        gw.__exit__(None, None, None)
