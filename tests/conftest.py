import pytest

import pytmv1
from pytmv1.core import Core


def pytest_addoption(parser):
    parser.addoption(
        "--mock-url",
        action="store",
        default="",
        dest="mock-url",
        help="Mock URL for Vision One API",
    )


@pytest.fixture(scope="package")
def url(pytestconfig):
    url = pytestconfig.getoption("mock-url")
    return url if url else "https://dummy-server.com"


@pytest.fixture(scope="package")
def client(pytestconfig, url):
    return pytmv1.client(
        "appname",
        "token",
        url,
    )


@pytest.fixture(scope="package")
def core(pytestconfig, url):
    return Core(
        "appname",
        "token",
        url,
        0,
        0,
        30,
        30,
    )
