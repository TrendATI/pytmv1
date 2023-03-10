from pytmv1 import (
    BaseTaskResp,
    CollectFileTaskResp,
    EmailMessageUIdTask,
    ResultCode,
    Status,
)


def test_test_connectivity(client):
    assert client.test_connectivity()


def test_get_base_task_result(client):
    result = client.get_base_task_result("00000003", False)
    assert isinstance(result.response, BaseTaskResp)
    assert result.result_code == ResultCode.SUCCESS
    assert result.response.status == Status.SUCCEEDED
    assert result.response.id == "00000003"


def test_collect_file_task_result(client):
    result = client.get_task_result("00000003", CollectFileTaskResp, False)
    assert isinstance(result.response, CollectFileTaskResp)
    assert result.result_code == ResultCode.SUCCESS
    assert result.response.status == Status.SUCCEEDED
    assert result.response.file_sha256
    assert result.response.id == "00000003"


def test_collect_file_task_result_is_failed(client):
    result = client.get_task_result("failed", CollectFileTaskResp, False)
    assert not result.response
    assert result.result_code == ResultCode.ERROR
    assert result.error.code == "InternalServerError"
    assert result.error.status == 500


def test_collect_file_task_result_is_bad_request(client):
    result = client.get_task_result("bad_request", CollectFileTaskResp, False)
    assert not result.response
    assert result.result_code == ResultCode.ERROR
    assert result.error.code == "BadRequest"
    assert result.error.status == 400


def test_multi_status_is_failed(client):
    result = client.delete_email_message(
        EmailMessageUIdTask(uniqueId="multi_failed")
    )
    assert not result.response
    assert result.result_code == ResultCode.ERROR
    assert result.errors[0].code == "InternalServerError"
    assert result.errors[0].status == 500


def test_multi_status_is_bad_request(client):
    result = client.delete_email_message(
        EmailMessageUIdTask(uniqueId="multi_bad_request")
    )
    assert not result.response
    assert result.result_code == ResultCode.ERROR
    assert result.errors[0].code == "BadRequest"
    assert result.errors[0].status == 400


def test_multi_status_is_denied(client):
    result = client.delete_email_message(
        EmailMessageUIdTask(uniqueId="multi_denied")
    )
    assert not result.response
    assert result.result_code == ResultCode.ERROR
    assert result.errors[0].code == "AccessDenied"
    assert result.errors[0].status == 403


def test_multi_status_is_not_supported(client):
    result = client.delete_email_message(
        EmailMessageUIdTask(uniqueId="multi_not_supported")
    )
    assert not result.response
    assert result.result_code == ResultCode.ERROR
    assert result.errors[0].code == "NotSupported"
    assert result.errors[0].status == 400


def test_multi_status_is_task_error(client):
    result = client.delete_email_message(
        EmailMessageUIdTask(uniqueId="multi_task_error")
    )
    assert not result.response
    assert result.result_code == ResultCode.ERROR
    assert result.errors[0].code == "TaskError"
    assert result.errors[0].status == 400
