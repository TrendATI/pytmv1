from __future__ import annotations

from typing import List

from requests import Response

from .model.commons import Error, MsError


class ServerCustError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class ServerJsonError(Exception):
    def __init__(self, error: Error):
        super().__init__(
            f"Error response received from Vision One. [Error={error}]"
        )
        self.error = error


class ServerMultiJsonError(Exception):
    def __init__(self, errors: List[MsError]):
        super().__init__(
            (
                "Multi error response received from Vision One."
                f" [Errors={errors}]"
            ),
        )
        self.errors = errors


class ServerHtmlError(ServerCustError):
    def __init__(self, status: int, html: str):
        super().__init__(
            status,
            html,
        )


class ServerTextError(ServerCustError):
    def __init__(self, status: int, text: str):
        super().__init__(
            status,
            text,
        )


class ParseModelError(ServerCustError):
    def __init__(self, model: str, raw_response: Response):
        super().__init__(
            500,
            (
                "Could not parse response from Vision One.\n"
                f"Conditions unmet [Model={model}, {raw_response}]"
            ),
        )
