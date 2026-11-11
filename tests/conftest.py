import ssl

import pytest

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
    settings = Settings(listen_port=0, access_log=tmp_path / "access.log", log_to_stdout=False)
    with GatewayThread(settings) as gw:
        yield gw


@pytest.fixture
def client_tls(pki):
    """A client TLS context that trusts the test origin's CA."""
    ca, _, _ = pki
    return ssl.create_default_context(cafile=str(ca))
