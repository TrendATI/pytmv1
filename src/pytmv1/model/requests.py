from typing import Optional

from .commons import BaseModel
from .enums import ObjectType, RiskLevel, ScanAction


class AccountTask(BaseModel):
    account_name: str
    """User account name."""
    description: Optional[str] = None
    """Description of a response task."""


class EndpointTask(BaseModel):
    endpoint_name: Optional[str]
    """Endpoint name."""
    agent_guid: Optional[str] = None
    """Agent guid"""
    description: Optional[str] = None
    """Description of a response task."""


class EmailMessageIdTask(BaseModel):
    message_id: str
    """Email message id."""
    mail_box: Optional[str]
    """Email address."""
    description: Optional[str] = None
    """Description of a response task."""


class EmailMessageUIdTask(BaseModel):
    unique_id: str
    """Email unique message id."""
    description: Optional[str] = None
    """Description of a response task."""


class ObjectTask(BaseModel):
    object_type: ObjectType
    """Type of object."""
    object_value: str
    """Value of an object."""
    description: Optional[str] = None
    """Description of an object."""


class SuspiciousObjectTask(ObjectTask):
    scan_action: Optional[ScanAction] = None
    """Action applied after detecting a suspicious object."""
    risk_level: Optional[RiskLevel] = None
    """Risk level of a suspicious object."""
    days_to_expiration: Optional[int] = None
    """Number of days before the object expires."""


class FileTask(EndpointTask):
    file_path: str
    """File path of the file to be collected from the target."""


class ProcessTask(EndpointTask):
    file_sha1: str
    """SHA1 hash of the terminated process's executable file."""
    file_name: Optional[str] = None
    """File name of the target."""
