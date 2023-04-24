from pytmv1 import (
    BytesResp,
    ResultCode,
    SandboxAnalysisResultResp,
    SandboxSubmissionStatusResp,
    SandboxSuspiciousListResp,
    SubmitFileToSandboxResp,
)


def test_submit_file_to_sandbox(client):
    result = client.submit_file_to_sandbox(
        bytes("content", "utf-8"), "fileName.txt"
    )
    assert isinstance(result.response, SubmitFileToSandboxResp)
    assert result.result_code == ResultCode.SUCCESS
    assert result.response.id


def test_submit_file_to_sandbox_is_too_large_file(client):
    result = client.submit_file_to_sandbox(
        bytes("content", "utf-8"), "tooBig.txt"
    )
    assert result.result_code == ResultCode.ERROR
    assert result.error.code == "RequestEntityTooLarge"
    assert result.error.status == 413


def test_submit_file_to_sandbox_is_too_many_request(client):
    result = client.submit_file_to_sandbox(
        bytes("content", "utf-8"), "tooMany.txt"
    )
    assert result.result_code == ResultCode.ERROR
    assert result.error.code == "TooManyRequests"
    assert result.error.status == 429


def test_submit_urls_to_sandbox_with_multi_url(client):
    result = client.submit_urls_to_sandbox(
        "https://trendmicro.com", "https://trendmicro2.com"
    )
    assert result.result_code == ResultCode.SUCCESS
    assert result.response.items[0].url == "https://www.trendmicro.com"
    assert result.response.items[0].status == 202
    assert result.response.items[0].task_id == "00000005"
    assert (
        result.response.items[0].id == "012e4eac-9bd9-4e89-95db-77e02f75a6f5"
    )
    assert (
        result.response.items[0].digest.md5
        == "f3a2e1227de8d5ae7296665c1f34b28d"
    )
    assert result.response.items[1].url == "https://www.trendmicro2.com"
    assert result.response.items[1].status == 202
    assert result.response.items[1].task_id == "00000006"
    assert (
        result.response.items[1].id
        == "01232cs823-9bd9-4e89-95db-77e02f75a6f34"
    )
    assert (
        result.response.items[1].digest.md5
        == "x23s2sd11227de8d5ae7296665c1f34b3212"
    )


def test_submit_urls_to_sandbox_is_bad_request(client):
    result = client.submit_urls_to_sandbox("bad_request")
    assert result.result_code == ResultCode.ERROR
    assert result.errors[0].extra["url"] == "https://www.trendmicro.com"
    assert result.errors[0].status == 202
    assert result.errors[0].task_id == "00000005"
    assert result.errors[1].extra["url"] == "test"
    assert result.errors[1].status == 400
    assert result.errors[1].code == "BadRequest"
    assert result.errors[1].message == "URL format is not right"


def test_get_sandbox_submission_status(client):
    result = client.get_sandbox_submission_status("123")
    assert isinstance(result.response, SandboxSubmissionStatusResp)
    assert result.result_code == ResultCode.SUCCESS
    assert result.response.id == "123"


def test_get_sandbox_analysis_result(client):
    result = client.get_sandbox_analysis_result("123", False)
    assert isinstance(result.response, SandboxAnalysisResultResp)
    assert result.result_code == ResultCode.SUCCESS
    assert result.response.id == "123"


def test_get_sandbox_suspicious_list(client):
    result = client.get_sandbox_suspicious_list("1", False)
    assert isinstance(result.response, SandboxSuspiciousListResp)
    assert result.result_code == ResultCode.SUCCESS
    assert len(result.response.items) > 0
    assert result.response.items[0].type == "ip"
    assert result.response.items[0].value == "6.6.6.6"


def test_download_sandbox_analysis_result(client):
    result = client.download_sandbox_analysis_result("1", False)
    assert isinstance(result.response, BytesResp)
    assert result.result_code == ResultCode.SUCCESS
    assert result.response.content


def test_download_sandbox_investigation_package(client):
    result = client.download_sandbox_investigation_package("1", False)
    assert isinstance(result.response, BytesResp)
    assert result.result_code == ResultCode.SUCCESS
    assert result.response.content
