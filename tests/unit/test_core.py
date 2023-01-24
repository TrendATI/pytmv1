import time

import pytest
from pydantic import ValidationError
from requests import RequestException, Response

from pytmv1 import (
    AddAlertNoteResp,
    BytesResp,
    CollectFileTaskResp,
    Error,
    ExceptionObject,
    GetExceptionListResp,
    MsData,
    MsError,
    MultiResp,
    NoContentResp,
    ResultCode,
    SandboxAnalysisResultResp,
    SandboxSubmissionStatusResp,
    SandboxSuspiciousListResp,
    SandboxSuspiciousObject,
    Status,
    __version__,
)
from pytmv1 import core as core_m
from pytmv1 import results
from pytmv1.core import API_VERSION, USERAGENT_SUFFIX, Core
from pytmv1.exceptions import (
    ParseModelError,
    ServerHtmlError,
    ServerJsonError,
    ServerMultiJsonError,
    ServerTextError,
)
from pytmv1.model.enums import Api
from pytmv1.model.responses import BaseStatusResponse
from tests.data import TextResponse

API_URL = "https://dummy.com/v3.0"


def test_consume_linkable_with_next_link_multiple_items(mocker, core):
    mock_process = mocker.patch.object(
        core,
        "_process",
        side_effect=[
            GetExceptionListResp(
                nextLink="not_empty",
                items=[
                    ExceptionObject.construct(),
                    ExceptionObject.construct(),
                ],
            ),
            GetExceptionListResp(
                items=[
                    ExceptionObject.construct(),
                    ExceptionObject.construct(),
                ]
            ),
        ],
    )
    total = core._consume_linkable(
        lambda: core._process(GetExceptionListResp, Api.GET_EXCEPTION_LIST),
        lambda x: None,
    )
    assert mock_process.call_count == 2
    assert total == 4


def test_consume_linkable_with_next_link_single_item(mocker, core):
    mock_process = mocker.patch.object(
        core,
        "_process",
        side_effect=[
            GetExceptionListResp(
                nextLink="https://host/api/path?skipToken=c2tpcFRva2Vu",
                items=[],
            ),
            GetExceptionListResp(items=[ExceptionObject.construct()]),
        ],
    )
    total = core._consume_linkable(
        lambda: core._process(GetExceptionListResp, Api.GET_EXCEPTION_LIST),
        lambda x: None,
    )
    mock_process.assert_called()
    assert total == 1


def test_consume_linkable_without_next_link(mocker, core):
    mock_process = mocker.patch.object(
        core, "_process", return_value=GetExceptionListResp(items=[])
    )
    total = core._consume_linkable(
        lambda: core._process(GetExceptionListResp, Api.GET_EXCEPTION_LIST),
        lambda x: None,
    )
    mock_process.assert_called()
    assert total == 0


def test_error():
    error = results._error(
        ServerJsonError(
            Error(status=500, code="X12", message="error", number=123)
        )
    )
    assert error.status == 500
    assert error.code == "X12"
    assert error.message == "error"
    assert error.number == 123


def test_errors():
    errors = results._errors(
        ServerMultiJsonError(
            [
                MsError(status=123, code="code", message="message"),
                MsError(status=456, code="code2", message="message2"),
            ]
        )
    )
    assert errors[0].status == 123
    assert errors[0].code == "code"
    assert errors[0].message == "message"
    assert errors[1].status == 456
    assert errors[1].code == "code2"
    assert errors[1].message == "message2"


def test_headers(core):
    assert core._headers["Authorization"] == "Bearer token"
    assert core._headers["User-Agent"] == "appname-{}/{}".format(
        USERAGENT_SUFFIX, __version__
    )


def test_hide_binary():
    raw_response = Response()
    raw_response.headers = {"Content-Type": "application/pdf"}
    assert core_m._hide_binary(raw_response) == "***binary content***"
    raw_response.headers = {"Content-Type": "application/zip"}
    assert core_m._hide_binary(raw_response) == "***binary content***"
    raw_response.headers = {"Content-Type": "application/octet-stream"}
    assert core_m._hide_binary(raw_response) == "***binary content***"


def test_is_http_success():
    assert core_m._is_http_success([200, 400, 600, 500]) is False
    assert core_m._is_http_success([199, 400, 600, 500]) is False
    assert core_m._is_http_success([400]) is False
    assert core_m._is_http_success([200, 300, 398, 204]) is True
    assert core_m._is_http_success([200]) is True


def test_parse_data_with_bytes():
    raw_response = TextResponse("raw")
    raw_response.headers = {"Content-Type": "application/pdf"}
    response = core_m._parse_data(raw_response, BytesResp)
    assert response.content == raw_response.content


def test_parse_data_with_html_is_failed():
    raw_response = Response()
    raw_response.headers = {"Content-Type": "text/html"}
    with pytest.raises(ParseModelError):
        core_m._parse_data(raw_response, NoContentResp)


def test_parse_data_with_json():
    raw_response = Response()
    raw_response.headers = {"Content-Type": "application/json"}
    raw_response.json = lambda: SandboxSuspiciousListResp(
        items=[
            SandboxSuspiciousObject(
                riskLevel="high",
                analysisCompletionDateTime="2021-05-07T03:08:40",
                expiredDateTime="2021-06-07T03:08:40Z",
                rootSha1="fb5608fa03de204a12fe1e9e5275e4a682107471",
                ip="6.6.6.6",
            )
        ]
    )
    response = core_m._parse_data(raw_response, SandboxSuspiciousListResp)
    assert response.items[0].risk_level == "high"
    assert (
        response.items[0].analysis_completion_date_time
        == "2021-05-07T03:08:40"
    )
    assert response.items[0].expired_date_time == "2021-06-07T03:08:40Z"
    assert (
        response.items[0].root_sha1
        == "fb5608fa03de204a12fe1e9e5275e4a682107471"
    )
    assert response.items[0].ip == "6.6.6.6"


def test_parse_data_with_multi_and_wrong_model_is_failed():
    raw_response = Response()
    raw_response.headers = {"Content-Type": "application/json"}
    raw_response.status_code = 207
    raw_response.json = lambda: MultiResp(items=[MsData(status=200)])
    with pytest.raises(ValidationError):
        core_m._parse_data(raw_response, AddAlertNoteResp)


def test_parse_data_with_single_and_wrong_model_is_failed():
    raw_response = Response()
    raw_response.headers = {"Content-Type": "application/json"}
    raw_response.status_code = 200
    raw_response.json = lambda: AddAlertNoteResp(location="test")
    with pytest.raises(ValidationError):
        core_m._parse_data(raw_response, MultiResp)


def test_parse_data_without_content():
    raw_response = Response()
    raw_response.status_code = 204
    response = core_m._parse_data(raw_response, NoContentResp)
    assert isinstance(response, NoContentResp)


def test_parse_html():
    result = core_m._parse_html("<html><div><p>test</p></div></html>")
    assert result == "test"


def test_poll_status_with_rejected_status_is_not_polling():
    start_time = time.time()
    core_m._poll_status(
        lambda: BaseStatusResponse.construct(status=Status.REJECTED),
        20,
    )
    assert time.time() - start_time < 20


def test_poll_status_with_running_status_is_polling():
    start_time = time.time()
    core_m._poll_status(
        lambda: BaseStatusResponse.construct(status=Status.RUNNING),
        2,
    )
    assert time.time() - start_time >= 2


def test_poll_status_with_succeeded_status():
    start_time = time.time()
    core_m._poll_status(
        lambda: BaseStatusResponse.construct(status=Status.SUCCEEDED),
        20,
    )
    assert time.time() - start_time < 20


def test_send(core, mocker):
    raw_response = Response()
    raw_response.status_code = 204
    mock_request = mocker.patch.object(core, "_send_internal")
    mock_request.return_value = raw_response
    result = core.send(NoContentResp, Api.EDIT_ALERT_STATUS)
    mock_request.assert_called()
    assert result.result_code == ResultCode.SUCCESS


def test_send_linkable(mocker, core):
    mock_process = mocker.patch.object(core, "_process")
    mock_process.return_value = GetExceptionListResp(
        items=[ExceptionObject.construct()]
    )
    result = core.send_linkable(
        GetExceptionListResp,
        Api.GET_EXCEPTION_LIST,
        lambda x: None,
    )
    mock_process.assert_called()
    assert result.result_code == ResultCode.SUCCESS
    assert result.response.total_consumed == 1


def test_send_sandbox_result_with_polling(core, mocker):
    mock_poll = mocker.patch.object(core_m, "_poll_status")
    mock_poll.return_value = SandboxSubmissionStatusResp.construct(
        status=Status.SUCCEEDED
    )
    mock_send = mocker.patch.object(core, "_process")
    result = core.send_sandbox_result(
        SandboxAnalysisResultResp,
        Api.GET_SANDBOX_ANALYSIS_RESULT,
        "123",
        True,
        0,
    )
    mock_poll.assert_called()
    mock_send.assert_called()
    assert result.result_code == ResultCode.SUCCESS


def test_send_sandbox_result_with_polling_is_failed(core, mocker):
    mock_poll = mocker.patch.object(
        core_m, "_poll_status", side_effect=RequestException()
    )
    mock_send = mocker.patch.object(core, "_process")
    result = core.send_sandbox_result(
        SandboxAnalysisResultResp,
        Api.GET_SANDBOX_ANALYSIS_RESULT,
        "123",
        True,
        0,
    )
    mock_poll.assert_called()
    mock_send.assert_not_called()
    assert result.result_code == ResultCode.ERROR
    assert result.error.status == 500
    assert result.error.code == "RequestException"


def test_send_sandbox_result_without_polling(core, mocker):
    mock_poll = mocker.patch.object(core_m, "_poll_status")
    mock_send = mocker.patch.object(core, "_process")
    result = core.send_sandbox_result(
        SandboxAnalysisResultResp,
        Api.GET_SANDBOX_ANALYSIS_RESULT,
        "123",
        False,
        0,
    )
    mock_poll.assert_not_called()
    mock_send.assert_called()
    assert result.result_code == ResultCode.SUCCESS


def test_send_sandbox_result_without_polling_is_failed(core, mocker):
    mock_poll = mocker.patch.object(core_m, "_poll_status")
    mock_send = mocker.patch.object(
        core, "_process", side_effect=RequestException()
    )
    result = core.send_sandbox_result(
        SandboxAnalysisResultResp,
        Api.GET_SANDBOX_ANALYSIS_RESULT,
        "123",
        False,
        0,
    )
    mock_poll.assert_not_called()
    mock_send.assert_called()
    assert result.result_code == ResultCode.ERROR
    assert result.error.status == 500
    assert result.error.code == "RequestException"


def test_send_task_result(core, mocker):
    mock_poll = mocker.patch.object(core_m, "_poll_status")
    mock_send = mocker.patch.object(core, "_process")
    result = core.send_task_result(CollectFileTaskResp, "123", False, 0)
    mock_poll.assert_not_called()
    mock_send.assert_called()
    assert result.result_code == ResultCode.SUCCESS


def test_send_task_result_is_failed(core, mocker):
    mock_poll = mocker.patch.object(core_m, "_poll_status")
    mock_send = mocker.patch.object(
        core, "_process", side_effect=RequestException()
    )
    result = core.send_task_result(CollectFileTaskResp, "123", False, 0)
    mock_poll.assert_not_called()
    mock_send.assert_called()
    assert result.result_code == ResultCode.ERROR
    assert result.error.status == 500
    assert result.error.code == "RequestException"


def test_send_task_result_with_poll(core, mocker):
    mock_poll = mocker.patch.object(core_m, "_poll_status")
    mock_send = mocker.patch.object(core, "_process")
    result = core.send_task_result(CollectFileTaskResp, "123", True, 0)
    mock_poll.assert_called()
    mock_send.assert_called()
    assert result.result_code == ResultCode.SUCCESS


def test_send_task_result_with_poll_is_failed(core, mocker):
    mock_poll = mocker.patch.object(
        core_m, "_poll_status", side_effect=RequestException()
    )
    mock_send = mocker.patch.object(core, "_process")
    result = core.send_task_result(CollectFileTaskResp, "123", True, 0)
    mock_poll.assert_called()
    mock_send.assert_not_called()
    assert result.result_code == ResultCode.ERROR
    assert result.error.status == 500
    assert result.error.code == "RequestException"


def test_send_with_request_exception_is_failed(core, mocker):
    mocker.patch.object(core, "_send_internal", side_effect=RequestException())
    result = core.send(GetExceptionListResp, Api.GET_EXCEPTION_LIST)
    assert result.result_code == ResultCode.ERROR
    assert result.error.status == 500
    assert result.error.code == "RequestException"


def test_send_with_runtime_error_is_failed(core, mocker):
    mocker.patch.object(core, "_send_internal", side_effect=RuntimeError())
    result = core.send(GetExceptionListResp, Api.GET_EXCEPTION_LIST)
    assert result.result_code == ResultCode.ERROR
    assert result.error.status == 500
    assert result.error.code == "RuntimeError"


def test_send_with_validation_error_is_failed(core, mocker):
    mocker.patch.object(
        core,
        "_send_internal",
        side_effect=ValidationError([], NoContentResp),
    )
    result = core.send(GetExceptionListResp, Api.GET_EXCEPTION_LIST)
    assert result.result_code == ResultCode.ERROR
    assert result.error.status == 500
    assert result.error.code == "ValidationError"


def test_status():
    status = results._status(ServerTextError(450, "error"))
    assert status == 450


def test_url_with_trailing_slash():
    test_core = Core("", "", "https://dummy/", 0, 0)
    assert test_core._url == "https://dummy/" + API_VERSION


def test_url_without_trailing_slash(core):
    test_core = Core("", "", "https://dummy", 0, 0)
    assert test_core._url == "https://dummy/" + API_VERSION


def test_validate_with_html_is_failed():
    raw_response = Response()
    raw_response.status_code = 200
    raw_response.headers = {"Content-Type": "text/html"}
    with pytest.raises(ServerHtmlError):
        core_m._validate(raw_response)


def test_validate_with_json_error_is_failed():
    raw_response = Response()
    raw_response.headers = {"Content-Type": "application/json"}
    raw_response.status_code = 500
    raw_response.json = lambda: {
        "error": {"code": "CODE", "message": "some error", "number": 1}
    }
    with pytest.raises(ServerJsonError, match="some error"):
        core_m._validate(raw_response)


def test_validate_with_text_error_is_failed():
    raw_response = TextResponse("some text")
    raw_response.status_code = 500
    with pytest.raises(ServerTextError, match="some text"):
        core_m._validate(raw_response)


def test_validate_multi_with_multi_data_is_failed():
    raw_response = Response()
    raw_response.status_code = 207
    raw_response.json = lambda: [
        {"status": "400", "code": "code", "message": "message"},
        {"status": "403", "code": "code", "message": "message"},
    ]
    with pytest.raises(ServerMultiJsonError, match="400.*403"):
        core_m._validate(raw_response)


def test_validate_multi_with_single_data_is_failed():
    raw_response = Response()
    raw_response.status_code = 207
    raw_response.json = lambda: [
        {
            "status": "400",
            "headers": [
                {
                    "name": "Operation-Location",
                    "value": "https://dummy-test.com/task/000004",
                }
            ],
            "code": "code",
            "message": "message",
        }
    ]
    with pytest.raises(ServerMultiJsonError, match="400"):
        core_m._validate(raw_response)
