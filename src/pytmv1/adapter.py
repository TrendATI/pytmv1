import typing
from typing import Any

from requests.adapters import DEFAULT_POOLBLOCK
from requests.adapters import HTTPAdapter as AdapterUrllib
from urllib3.connectionpool import HTTPConnectionPool as HTTPUrllib
from urllib3.connectionpool import HTTPSConnectionPool as HTTPSUrllib
from urllib3.poolmanager import PoolManager as ManagerUrllib


class HTTPConnectionPool(HTTPUrllib):
    @typing.no_type_check
    def urlopen(
        self,
        method,
        url,
        body=None,
        headers=None,
        retries=None,
        redirect=True,
        assert_same_host=True,
        timeout=30,
        pool_timeout=10,
        release_conn=True,
        chunked=False,
        body_pos=None,
        preload_content=True,
        decode_content=True,
        **response_kw,
    ):
        return super().urlopen(
            method,
            url,
            body,
            headers,
            retries,
            redirect,
            assert_same_host,
            timeout,
            pool_timeout,
            release_conn,
            chunked,
            body_pos,
            preload_content,
            decode_content,
            **response_kw,
        )


class HTTPSConnectionPool(HTTPSUrllib, HTTPConnectionPool):
    ...


class PoolManager(ManagerUrllib):
    def __init__(
        self,
        num_pools: Any = 10,
        headers: Any = None,
        **connection_pool_kw: Any,
    ):
        super().__init__(num_pools, headers, **connection_pool_kw)
        self.pool_classes_by_scheme = {
            "http": HTTPConnectionPool,
            "https": HTTPSConnectionPool,
        }


class HTTPAdapter(AdapterUrllib):
    @typing.no_type_check
    def init_poolmanager(
        self, connections, maxsize, block=DEFAULT_POOLBLOCK, **pool_kwargs
    ) -> None:
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )
