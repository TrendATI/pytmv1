from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from logging import Logger
from typing import Any, Callable, Generic, List, Optional, TypeVar

from pydantic import ValidationError
from requests import RequestException

from .exceptions import ServerCustError, ServerJsonError, ServerMultiJsonError
from .model.commons import Error, MsError
from .model.responses import MR, R

E = TypeVar("E", bound=Error)
F = TypeVar("F", bound=Callable[..., Any])

log: Logger = logging.getLogger(__name__)


def multi_result(func: F) -> Callable[..., MultiResult[MR]]:
    @wraps(func)
    def _multi_result(*args: Any, **kwargs: Any) -> MultiResult[MR]:
        obj: MR | Exception = _wrapper(func, *args, **kwargs)
        return (
            MultiResult.success(obj)
            if not isinstance(obj, Exception)
            else MultiResult.failed(obj)
        )

    return _multi_result


def result(func: F) -> Callable[..., Result[R]]:
    @wraps(func)
    def _result(*args: Any, **kwargs: Any) -> Result[R]:
        obj: R | Exception = _wrapper(func, *args, **kwargs)
        return (
            Result.success(obj)
            if not isinstance(obj, Exception)
            else Result.failed(obj)
        )

    return _result


def _wrapper(func: F, *args: Any, **kwargs: Any) -> R | Exception:
    try:
        start_time: float = time.time()
        log.debug(
            "Execution started [%s, %s]",
            args,
            kwargs,
        )
        response: R = func(*args, **kwargs)
        log.debug(
            "Execution finished [Elapsed=%s, %s]",
            time.time() - start_time,
            response,
        )
        return response
    except (
        ServerCustError,
        ServerJsonError,
        ServerMultiJsonError,
        ValidationError,
        RequestException,
        RuntimeError,
    ) as exc:
        log.exception("Unexpected issue occurred [%s]", exc)
        return exc


def _error(exc: Exception) -> Error:
    if isinstance(exc, ServerJsonError):
        return exc.error
    return Error(
        status=_status(exc), code=type(exc).__name__, message=str(exc)
    )


def _errors(exc: Exception) -> List[MsError]:
    if isinstance(exc, ServerMultiJsonError):
        return exc.errors
    if isinstance(exc, ServerJsonError):
        return [
            MsError(
                status=exc.error.status,
                code=exc.error.code,
                message=exc.error.message,
                number=exc.error.number,
            )
        ]
    return [
        MsError(status=_status(exc), code=type(exc).__name__, message=str(exc))
    ]


def _status(exc: Exception) -> int:
    return exc.status if isinstance(exc, ServerCustError) else 500


@dataclass
class BaseResult(Generic[R]):
    result_code: ResultCode
    response: Optional[R] = None


@dataclass
class Result(BaseResult[R]):
    error: Optional[Error] = None

    @classmethod
    def success(cls, response: R) -> Result[R]:
        return cls(ResultCode.SUCCESS, response)

    @classmethod
    def failed(cls, exc: Exception) -> Result[R]:
        return cls(
            ResultCode.ERROR,
            None,
            _error(exc),
        )


@dataclass
class MultiResult(BaseResult[MR]):
    errors: List[MsError] = field(default_factory=list)

    @classmethod
    def success(cls, response: MR) -> MultiResult[MR]:
        return cls(ResultCode.SUCCESS, response)

    @classmethod
    def failed(cls, exc: Exception) -> MultiResult[MR]:
        return cls(
            ResultCode.ERROR,
            None,
            _errors(exc),
        )


class ResultCode(str, Enum):
    SUCCESS = "SUCCESS"
    ERROR = "ERROR"
