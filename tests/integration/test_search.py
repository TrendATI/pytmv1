from pytmv1 import GetEndpointDataResp, QueryOp, ResultCode


def test_get_endpoint_data(client):
    result = client.get_endpoint_data(QueryOp.AND, "client1")
    assert isinstance(result.response, GetEndpointDataResp)
    assert result.result_code == ResultCode.SUCCESS
    assert len(result.response.items) > 0
