import pytmv1
from pytmv1.core import API_VERSION


def test_client():
    client = pytmv1.client("dummy_name", "dummy_token", "https://dummy.com")
    assert client._core._appname == "dummy_name"
    assert client._core._token == "dummy_token"
    assert client._core._url == "https://dummy.com/" + API_VERSION
