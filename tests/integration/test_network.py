from threading import Thread

import psutil
import pytest


def test_conn_opened_with_single_call_single_client_is_one(client, ip):
    client.get_exception_list()
    assert len(list_tcp_conn(ip)) == 1


@pytest.mark.parametrize("execution_number", range(10))
def test_conn_opened_with_multi_call_single_client_is_one(
    execution_number, client, ip
):
    client.get_exception_list()
    assert len(list_tcp_conn(ip)) == 1


def test_conn_opened_with_multi_processing_single_client_is_one(client, ip):
    threads = thread_list(lambda: client.get_exception_list())
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(list_tcp_conn(ip)) == 1


def test_conn_opened_with_multi_processing_multi_client_is_one(
    pytestconfig, client, ip
):
    threads = thread_list(lambda: client.get_exception_list())
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(list_tcp_conn(ip)) == 1


def list_tcp_conn(ipaddr):
    return list(
        filter(
            lambda sc: len(sc[4]) > 0
            and sc[4][0] == ipaddr
            and sc[5] == "ESTABLISHED",
            psutil.net_connections("tcp"),
        )
    )


def thread_list(func):
    return [Thread(target=func) for _ in range(10)]
