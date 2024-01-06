from pytmv1 import OperatingSystem, ProductCode, QueryField, QueryOp, utils


def test_b64_encode():
    assert utils._b64_encode("testString") == "dGVzdFN0cmluZw=="


def test_b64_encode_with_none():
    assert utils._b64_encode(None) is None


def test_activity_query():
    assert (
        utils.activity_query(
            QueryOp.AND, dpt="443", endpointHostName="client1"
        ).get("TMV1-Query")
        == 'dpt:"443" and endpointHostName:"client1"'
    )


def test_endpoint_query_field():
    assert utils.endpoint_query_field("client1")[0] == QueryField.ENDPOINT_NAME
    assert utils.endpoint_query_field("client1")[1] == QueryField.LOGIN_ACCOUNT
    assert utils.endpoint_query_field("1.1.1.1")[0] == QueryField.IP
    assert (
        utils.endpoint_query_field("A1-7B-A5-63-16-F8")[0]
        == QueryField.MAC_ADDRESS
    )
    assert (
        utils.endpoint_query_field("35fa11da-a24e-40cf-8b56-baf8828cc151")[0]
        == QueryField.AGENT_GUID
    )
    assert utils.endpoint_query_field("Linux")[0] == QueryField.OS_NAME
    assert utils.endpoint_query_field("sao")[0] == QueryField.PRODUCT_CODE
    assert (
        utils.endpoint_query_field("sao")[1]
        == QueryField.INSTALLED_PRODUCT_CODES
    )


def test_endpoint_query_with_endpoint_name():
    assert (
        utils.endpoint_query(QueryOp.AND, "dummy").get("TMV1-Query")
        == "(endpointName eq 'dummy' or loginAccount eq 'dummy')"
    )


def test_endpoint_query_with_ip():
    assert (
        utils.endpoint_query(QueryOp.AND, "1.1.1.1").get("TMV1-Query")
        == "(ip eq '1.1.1.1')"
    )


def test_endpoint_query_with_login_account():
    assert (
        utils.endpoint_query(QueryOp.AND, "DOMAIN\\Name_Lastname").get(
            "TMV1-Query"
        )
        == "(endpointName eq 'DOMAIN\\Name_Lastname' or"
        " loginAccount eq 'DOMAIN\\Name_Lastname')"
    )


def test_endpoint_query_with_mac_address():
    assert (
        utils.endpoint_query(QueryOp.AND, "A1-7B-A5-63-16-F8").get(
            "TMV1-Query"
        )
        == "(macAddress eq 'A1-7B-A5-63-16-F8')"
    )


def test_endpoint_query_with_multiple_os_name_or_operator():
    assert (
        utils.endpoint_query(
            QueryOp.OR,
            OperatingSystem.WINDOWS.value,
            OperatingSystem.LINUX.value,
        ).get("TMV1-Query")
        == "(osName eq 'Windows') or (osName eq 'Linux')"
    )


def test_endpoint_query_with_product_code_os_name_and_operator():
    assert (
        utils.endpoint_query(
            QueryOp.AND, ProductCode.SAO.value, OperatingSystem.WINDOWS.value
        ).get("TMV1-Query")
        == "(productCode eq 'sao' or installedProductCodes eq 'sao') and"
        " (osName eq 'Windows')"
    )


def test_endpoint_query_with_os_name():
    assert (
        utils.endpoint_query(QueryOp.AND, OperatingSystem.WINDOWS.value).get(
            "TMV1-Query"
        )
        == "(osName eq 'Windows')"
    )


def test_endpoint_query_with_product_code():
    assert (
        utils.endpoint_query(QueryOp.AND, ProductCode.SAO.value).get(
            "TMV1-Query"
        )
        == "(productCode eq 'sao' or installedProductCodes eq 'sao')"
    )


def test_filter_none():
    dictionary = utils.filter_none({"123": None})
    assert len(dictionary) == 0
    dictionary = utils.filter_none({"123": "Value"})
    assert len(dictionary) == 1


def test_is_ip_address():
    assert not utils._is_ip_address("1.1.1")
    assert not utils._is_ip_address("testvalue.com")
    assert not utils._is_ip_address("A1-7B-A5-63-16-F8")
    assert utils._is_ip_address("1.1.1.1")
    assert utils._is_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
