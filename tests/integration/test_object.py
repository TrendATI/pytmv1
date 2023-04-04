from pytmv1 import (
    GetExceptionListResp,
    GetSuspiciousListResp,
    MultiResp,
    ObjectTask,
    ObjectType,
    ResultCode,
    SuspiciousObjectTask,
)
from pytmv1.model.enums import ScanAction


def test_add_to_exception_list(client):
    result = client.add_to_exception_list(
        ObjectTask(objectType=ObjectType.IP, objectValue="1.1.1.1")
    )
    assert isinstance(result.response, MultiResp)
    assert result.result_code == ResultCode.SUCCESS
    assert len(result.response.items) > 0
    assert result.response.items[0].task_id is None
    assert result.response.items[0].status == 201


def test_add_to_suspicious_list(client):
    result = client.add_to_suspicious_list(
        SuspiciousObjectTask(
            objectType=ObjectType.IP,
            objectValue="1.1.1.1",
            scanAction=ScanAction.BLOCK,
        )
    )
    assert isinstance(result.response, MultiResp)
    assert result.result_code == ResultCode.SUCCESS
    assert len(result.response.items) > 0
    assert result.response.items[0].task_id is None
    assert result.response.items[0].status == 201


def test_remove_from_exception_list(client):
    result = client.remove_from_exception_list(
        ObjectTask(objectType=ObjectType.IP, objectValue="1.1.1.1")
    )
    assert isinstance(result.response, MultiResp)
    assert result.result_code == ResultCode.SUCCESS
    assert len(result.response.items) > 0
    assert result.response.items[0].task_id is None
    assert result.response.items[0].status == 204


def test_remove_from_suspicious_list(client):
    result = client.remove_from_suspicious_list(
        ObjectTask(objectType=ObjectType.IP, objectValue="1.1.1.1")
    )
    assert isinstance(result.response, MultiResp)
    assert result.result_code == ResultCode.SUCCESS
    assert len(result.response.items) > 0
    assert result.response.items[0].task_id is None
    assert result.response.items[0].status == 204


def test_get_exception_list(client):
    result = client.get_exception_list()
    assert isinstance(result.response, GetExceptionListResp)
    assert result.result_code == ResultCode.SUCCESS
    assert len(result.response.items) > 0
    assert result.response.items[0].url
    assert result.response.items[0].type == ObjectType.URL


def test_get_suspicious_list(client):
    result = client.get_suspicious_list()
    assert isinstance(result.response, GetSuspiciousListResp)
    assert result.result_code == ResultCode.SUCCESS
    assert len(result.response.items) > 0
    assert result.response.items[0].url
    assert result.response.items[0].type == ObjectType.URL
