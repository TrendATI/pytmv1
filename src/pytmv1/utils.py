import base64
import re
from typing import Any, Dict, List, Optional, Pattern, Tuple

from pydantic import IPvAnyAddress, IPvAnyAddressError

from .model.enums import OperatingSystem, ProductCode, QueryField, QueryOp
from .model.requests import ObjectTask, SuspiciousObjectTask

MAC_ADDRESS_PATTERN: Pattern[str] = re.compile(
    "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
)
GUID_PATTERN: Pattern[str] = re.compile("^(\\w+-+){1,5}\\w+$")


def build_object_request(*tasks: ObjectTask) -> List[Dict[str, str]]:
    return [
        filter_none(
            {
                task.object_type.value: task.object_value,
                "description": task.description,
            }
        )
        for task in tasks
    ]


def build_sandbox_file_request(
    document_password: Optional[str],
    archive_password: Optional[str],
    arguments: Optional[str],
) -> Dict[str, str]:
    return filter_none(
        {
            "documentPassword": _b64_encode(document_password),
            "archivePassword": _b64_encode(archive_password),
            "arguments": _b64_encode(arguments),
        }
    )


def build_suspicious_request(
    *tasks: SuspiciousObjectTask,
) -> List[Dict[str, Any]]:
    return [
        filter_none(
            {
                task.object_type.value: task.object_value,
                "description": task.description,
                "riskLevel": (
                    task.risk_level.value if task.risk_level else None
                ),
                "scanAction": (
                    task.scan_action.value if task.scan_action else None
                ),
                "daysToExpiration": task.days_to_expiration,
            }
        )
        for task in tasks
    ]


def endpoint_query(op: QueryOp, *values: str) -> Dict[str, str]:
    return {
        "TMV1-Query": op.join(
            "("
            + QueryOp.OR.join(
                f"{qt.value} eq '{value}'"
                for qt in endpoint_query_field(value)
            )
            + ")"
            for value in values
        )
    }


def endpoint_query_field(value: str) -> Tuple[QueryField, ...]:
    if _is_ip_address(value):
        return (QueryField.IP,)
    if bool(MAC_ADDRESS_PATTERN.match(value)):
        return (QueryField.MAC_ADDRESS,)
    if bool(GUID_PATTERN.match(value)):
        return (QueryField.AGENT_GUID,)
    if next(filter(lambda os: os.value == value, OperatingSystem), None):
        return (QueryField.OS_NAME,)
    if next(filter(lambda pc: pc.value == value, ProductCode), None):
        return QueryField.PRODUCT_CODE, QueryField.INSTALLED_PRODUCT_CODES
    return QueryField.ENDPOINT_NAME, QueryField.LOGIN_ACCOUNT


def filter_none(dictionary: Dict[str, Optional[Any]]) -> Dict[str, Any]:
    return {k: v for k, v in dictionary.items() if v}


def _b64_encode(value: Optional[str]) -> Optional[str]:
    return base64.b64encode(value.encode()).decode() if value else None


def _is_ip_address(endpoint_value: str) -> bool:
    try:
        return bool(IPvAnyAddress.validate(endpoint_value))
    except IPvAnyAddressError:
        return False
