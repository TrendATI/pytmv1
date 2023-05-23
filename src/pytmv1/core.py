import logging
import re
import time
from logging import Logger
from typing import Any, Callable, Dict, List, Type
from urllib.parse import SplitResult, urlsplit

from bs4 import BeautifulSoup
from pydantic import AnyHttpUrl, parse_obj_as
from requests import PreparedRequest, Request, Response
from requests.adapters import HTTPAdapter

from .__about__ import __version__
from .exceptions import (
    ParseModelError,
    ServerHtmlError,
    ServerJsonError,
    ServerMultiJsonError,
    ServerTextError,
)
from .model.commons import (
    Error,
    MsData,
    MsDataUrl,
    MsError,
    MsStatus,
    SaeAlert,
    TiAlert,
)
from .model.enums import Api, HttpMethod, Provider, Status
from .model.requests import EndpointTask
from .model.responses import (
    MR,
    AddAlertNoteResp,
    BaseLinkableResp,
    BaseMultiResponse,
    BytesResp,
    C,
    ConsumeLinkableResp,
    GetAlertDetailsResp,
    MultiResp,
    MultiUrlResp,
    NoContentResp,
    R,
    S,
    SandboxSubmissionStatusResp,
)
from .results import multi_result, result

USERAGENT_SUFFIX: str = "PyTMV1"
API_VERSION: str = "v3.0"

log: Logger = logging.getLogger(__name__)


class Core:
    def __init__(
        self,
        appname: str,
        token: str,
        url: str,
        pool_connections: int,
        pool_maxsize: int,
        connect_timeout: int,
        read_timeout: int,
    ):
        self._adapter = HTTPAdapter(pool_connections, pool_maxsize, 0, True)
        self._c_timeout = connect_timeout
        self._r_timeout = read_timeout
        self._appname = appname
        self._token = token
        self._url = parse_obj_as(AnyHttpUrl, _format(url))
        self._headers: Dict[str, str] = {
            "Authorization": f"Bearer {self._token}",
            "User-Agent": f"{self._appname}-{USERAGENT_SUFFIX}/{__version__}",
        }

    @result
    def send(
        self,
        class_: Type[R],
        api: str,
        method: HttpMethod = HttpMethod.GET,
        **kwargs: Any,
    ) -> R:
        return self._process(
            class_,
            api,
            method,
            **kwargs,
        )

    @multi_result
    def send_endpoint(
        self,
        api: Api,
        *tasks: EndpointTask,
    ) -> MultiResp:
        return self._process(
            MultiResp,
            api,
            HttpMethod.POST,
            json=[
                task.dict(by_alias=True, exclude_none=True) for task in tasks
            ],
        )

    @result
    def send_linkable(
        self,
        class_: Type[BaseLinkableResp[C]],
        api: str,
        consumer: Callable[[C], None],
        **kwargs: Any,
    ) -> ConsumeLinkableResp:
        return ConsumeLinkableResp(
            total_consumed=self._consume_linkable(
                lambda: self._process(
                    class_,
                    api,
                    **kwargs,
                ),
                consumer,
            )
        )

    @multi_result
    def send_multi(
        self,
        class_: Type[MR],
        api: str,
        **kwargs: Any,
    ) -> MR:
        return self._process(
            class_,
            api,
            HttpMethod.POST,
            **kwargs,
        )

    @result
    def send_sandbox_result(
        self,
        class_: Type[R],
        api: Api,
        submit_id: str,
        poll: bool,
        poll_time_sec: float,
    ) -> R:
        if poll:
            _poll_status(
                lambda: self._process(
                    SandboxSubmissionStatusResp,
                    Api.GET_SANDBOX_SUBMISSION_STATUS.value.format(submit_id),
                ),
                poll_time_sec,
            )
        return self._process(class_, api.value.format(submit_id))

    @result
    def send_task_result(
        self, class_: Type[S], task_id: str, poll: bool, poll_time_sec: float
    ) -> S:
        status_call: Callable[[], S] = lambda: self._process(
            class_,
            Api.GET_TASK_RESULT.value.format(task_id),
        )
        if poll:
            _poll_status(
                status_call,
                poll_time_sec,
            )
        return status_call()

    def _consume_linkable(
        self,
        api_call: Callable[[], BaseLinkableResp[C]],
        consumer: Callable[[C], None],
        count: int = 0,
    ) -> int:
        total_count: int = count
        response: BaseLinkableResp[C] = api_call()
        for item in response.items:
            consumer(item)
            total_count += 1
        if response.next_link:
            sr: SplitResult = urlsplit(response.next_link)
            log.info("Found nextLink")
            return self._consume_linkable(
                lambda: self._process(
                    type(response),
                    sr.path[5:] + f"?skipToken={sr.query.split('=')[-1]}",
                ),
                consumer,
                total_count,
            )
        log.info(
            "Records consumed: [Total=%s, Type=%s]",
            total_count,
            type(
                response.items[0] if len(response.items) > 0 else response
            ).__name__,
        )
        return total_count

    def _process(
        self,
        class_: Type[R],
        uri: str,
        method: HttpMethod = HttpMethod.GET,
        **kwargs: Any,
    ) -> R:
        log.info(
            "Processing request [Method=%s, Class=%s, Api=%s, Options=%s]",
            method.value,
            class_.__name__,
            uri,
            kwargs,
        )
        raw_response: Response = self._send_internal(
            self._prepare(uri, method, **kwargs)
        )
        _validate(raw_response)
        return _parse_data(raw_response, class_)

    def _prepare(
        self, uri: str, method: HttpMethod, **kwargs: Any
    ) -> PreparedRequest:
        return Request(
            method.value,
            self._url + uri,
            headers={**self._headers, **kwargs.pop("headers", {})},
            **kwargs,
        ).prepare()

    def _send_internal(self, request: PreparedRequest) -> Response:
        log.info(
            "Sending request [Method=%s, URL=%s, Headers=%s, Body=%s]",
            request.method,
            request.url,
            re.sub("Bearer [^\\s']+", "*****", str(request.headers)),
            (
                request.body.decode("utf-8")
                if type(request.body) == bytes
                else request.body
            ),
        )
        response: Response = self._adapter.send(
            request, timeout=(self._c_timeout, self._r_timeout)
        )
        log.info(
            "Received response [Status=%s, Headers=%s, Body=%s]",
            response.status_code,
            response.headers,
            _hide_binary(response),
        )
        return response


def _format(url: str) -> str:
    return (url if url.endswith("/") else url + "/") + API_VERSION


def _hide_binary(response: Response) -> str:
    content_type = response.headers.get("Content-Type", "")
    if "json" not in content_type and "application" in content_type:
        return "***binary content***"
    return response.text


def _is_http_success(status_codes: List[int]) -> bool:
    return len(list(filter(lambda s: not 200 <= s < 399, status_codes))) == 0


def _parse_data(raw_response: Response, class_: Type[R]) -> R:
    content_type = raw_response.headers.get("Content-Type", "")
    if "json" in content_type:
        if issubclass(class_, BaseMultiResponse):
            log.info("Parsing json multi response [Class=%s]", class_.__name__)
            class_d: Type[List[Any]]
            if issubclass(class_, MultiUrlResp):
                class_d = List[MsDataUrl]
            else:
                class_d = List[MsData]
            return class_(
                items=parse_obj_as(
                    class_d,
                    raw_response.json(),
                )
            )
        log.info("Parsing json response [Class=%s]", class_.__name__)
        if class_ == GetAlertDetailsResp:
            response_json: Dict[str, str] = raw_response.json()
            return class_(
                alert=parse_obj_as(
                    (
                        SaeAlert
                        if response_json.get("alertProvider") == Provider.SAE
                        else TiAlert
                    ),
                    response_json,
                ),
                etag=raw_response.headers.get("ETag", ""),
            )
        return class_.parse_obj(raw_response.json())
    if "application" in content_type and class_ == BytesResp:
        log.info("Parsing binary response")
        return class_(content=raw_response.content)
    if raw_response.status_code == 201 and class_ == AddAlertNoteResp:
        return class_.parse_obj(raw_response.headers)
    if raw_response.status_code == 204 and class_ == NoContentResp:
        return class_()
    raise ParseModelError(class_.__name__, raw_response)


def _parse_html(html: str) -> str:
    log.info("Parsing html response [Html=%s]", html)
    soup = BeautifulSoup(html, "html.parser")
    return "\n".join(
        line.strip() for line in soup.text.split("\n") if line.strip()
    )


def _poll_status(
    status_call: Callable[[], S],
    poll_time_sec: float,
) -> None:
    start_time: float = time.time()
    elapsed_time: float = 0
    response: S = status_call()
    while elapsed_time < poll_time_sec:
        if response.status in [Status.QUEUED, Status.RUNNING]:
            response = status_call()
            elapsed_time = time.time() - start_time
        else:
            break


def _validate(raw_response: Response) -> None:
    log.info("Validating response [%s]", raw_response)
    content_type: str = raw_response.headers.get("Content-Type", "")
    if "text/html" in content_type:
        raise ServerHtmlError(
            raw_response.status_code, _parse_html(raw_response.text)
        )
    if not _is_http_success([raw_response.status_code]):
        if "application/json" in content_type:
            error: Dict[str, Any] = raw_response.json().get("error")
            error["status"] = raw_response.status_code
            raise ServerJsonError(
                Error.parse_obj(error),
            )
        raise ServerTextError(raw_response.status_code, raw_response.text)
    if raw_response.status_code == 207:
        if not _is_http_success(
            MsStatus.parse_obj(raw_response.json()).values()
        ):
            raise ServerMultiJsonError(
                parse_obj_as(List[MsError], raw_response.json())
            )
