from pytmv1 import EndpointTask, FileTask, MultiResp, ProcessTask, ResultCode


def test_collect_file(client):
    result = client.collect_file(
        FileTask(endpointName="client1", filePath="/tmp/dummy.txt")
    )
    assert isinstance(result.response, MultiResp)
    assert result.result_code == ResultCode.SUCCESS
    assert len(result.response.items) > 0
    assert result.response.items[0].status == 202


def test_isolate_endpoint(client):
    result = client.isolate_endpoint(EndpointTask(endpointName="client1"))
    assert isinstance(result.response, MultiResp)
    assert result.result_code == ResultCode.SUCCESS
    assert len(result.response.items) > 0
    assert result.response.items[0].status == 202


def test_restore_endpoint(client):
    result = client.restore_endpoint(EndpointTask(endpointName="client1"))
    assert isinstance(result.response, MultiResp)
    assert result.result_code == ResultCode.SUCCESS
    assert len(result.response.items) > 0
    assert result.response.items[0].status == 202


def test_terminate_process(client):
    result = client.terminate_process(
        ProcessTask(
            endpointName="client1", fileSha1="sha12345", fileName="dummy.exe"
        )
    )
    assert isinstance(result.response, MultiResp)
    assert result.result_code == ResultCode.SUCCESS
    assert len(result.response.items) > 0
    assert result.response.items[0].status == 202
