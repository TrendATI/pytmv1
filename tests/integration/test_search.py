from pytmv1 import (
    GetEmailActivityDataCountResp,
    GetEmailActivityDataResp,
    GetEndpointActivityDataCountResp,
    GetEndpointActivityDataResp,
    GetEndpointDataResp,
    QueryOp,
    ResultCode,
)


def test_get_email_activity_data(client):
    result = client.get_email_activity_data(
        mailMsgSubject="spam", mailSenderIp="192.169.1.1"
    )
    assert result.result_code == ResultCode.SUCCESS
    assert isinstance(result.response, GetEmailActivityDataResp)
    assert len(result.response.items) > 0


def test_get_email_activity_data_count(client):
    result = client.get_email_activity_data_count(mailMsgSubject="spam")
    assert result.result_code == ResultCode.SUCCESS
    assert isinstance(result.response, GetEmailActivityDataCountResp)
    assert result.response.total_count > 0


def test_get_endpoint_activity_data(client):
    result = client.get_endpoint_activity_data(dpt="443")
    assert result.result_code == ResultCode.SUCCESS
    assert isinstance(result.response, GetEndpointActivityDataResp)
    assert len(result.response.items) > 0


def test_get_endpoint_activity_count(client):
    result = client.get_endpoint_activity_data_count(dpt="443")
    assert result.result_code == ResultCode.SUCCESS
    assert isinstance(result.response, GetEndpointActivityDataCountResp)
    assert result.response.total_count > 0


def test_get_endpoint_data(client):
    result = client.get_endpoint_data(QueryOp.AND, "client1")
    assert result.result_code == ResultCode.SUCCESS
    assert isinstance(result.response, GetEndpointDataResp)
    assert len(result.response.items) > 0
