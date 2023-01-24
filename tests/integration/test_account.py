from pytmv1 import AccountTask, ResultCode


def test_disable_account(client):
    result = client.disable_account(AccountTask(accountName="test"))
    assert result.result_code == ResultCode.SUCCESS
    assert len(result.response.items) > 0
    assert result.response.items[0].status == 202
    assert result.response.items[0].task_id == "00000009"


def test_enable_account(client):
    result = client.enable_account(AccountTask(accountName="test"))
    assert result.result_code == ResultCode.SUCCESS
    assert len(result.response.items) > 0
    assert result.response.items[0].status == 202
    assert result.response.items[0].task_id == "00000010"


def test_reset_password_account(client):
    result = client.reset_password_account(AccountTask(accountName="test"))
    assert result.result_code == ResultCode.SUCCESS
    assert len(result.response.items) > 0
    assert result.response.items[0].status == 202
    assert result.response.items[0].task_id == "00000011"


def test_sign_out_account(client):
    result = client.sign_out_account(AccountTask(accountName="test"))
    assert result.result_code == ResultCode.SUCCESS
    assert len(result.response.items) > 0
    assert result.response.items[0].status == 202
    assert result.response.items[0].task_id == "00000012"
