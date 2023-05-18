import socket

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
def client(pytestconfig):
    return pytmv1.client(
        "appname",
        "token",
        _default(pytestconfig.getoption("mock-url")),
    )


@pytest.fixture(scope="package")
def core(pytestconfig):
    return Core(
        "appname",
        "token",
        _default(pytestconfig.getoption("mock-url")),
        0,
        0,
        30,
        30,
    )


@pytest.fixture(scope="package")
def ip(pytestconfig):
    url = pytestconfig.getoption("mock-url")
    return socket.gethostbyname(url.split("/")[2]) if url != "" else None


def _default(url: str):
    return url if url else "https://dummy-server.com"
