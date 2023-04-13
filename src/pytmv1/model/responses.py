from typing import Any, Dict, Generic, List, Optional, Tuple, TypeVar, Union

from pydantic import Field
from pydantic.generics import GenericModel

from .commons import (
    Account,
    BaseConsumable,
    BaseModel,
    Digest,
    EmailMessage,
    Endpoint,
    ExceptionObject,
    MsData,
    MsDataUrl,
    SaeAlert,
    SandboxSuspiciousObject,
    SuspiciousObject,
    TiAlert,
)
from .enums import (
    ObjectType,
    RiskLevel,
    SandboxAction,
    SandboxObjectType,
    Status,
    TaskAction,
)

C = TypeVar("C", bound=BaseConsumable)
M = TypeVar("M", bound=MsData)


class BaseResponse(BaseModel):
    ...


class BaseLinkableResp(BaseResponse, GenericModel, Generic[C]):
    next_link: Optional[str]
    items: List[C] = []


class BaseMultiResponse(BaseResponse, GenericModel, Generic[M]):
    items: List[M] = []


class BaseStatusResponse(BaseResponse):
    id: str
    status: Status
    created_date_time: str
    last_action_date_time: str


class BaseTaskResp(BaseStatusResponse):
    action: TaskAction
    description: Optional[str]
    account: Optional[str]


MR = TypeVar("MR", bound=BaseMultiResponse[Any])
R = TypeVar("R", bound=BaseResponse)
S = TypeVar("S", bound=BaseStatusResponse)


class AccountTaskResp(BaseTaskResp):
    tasks: List[Account]


class AddAlertNoteResp(BaseResponse):
    location: str = Field(alias="Location")

    def note_id(self) -> str:
        return self.location.split("/")[-1]


class BlockListTaskResp(BaseTaskResp):
    type: ObjectType
    value: str

    def __init__(self, **data: str) -> None:
        obj: Tuple[str, str] = self._map(data)
        super().__init__(type=obj[0], value=obj[1], **data)

    @staticmethod
    def _map(args: Dict[str, str]) -> Tuple[str, str]:
        return {
            (k, v)
            for k, v in args.items()
            if k in map(lambda ot: ot.value, ObjectType)
        }.pop()


class BytesResp(BaseResponse):
    content: bytes


class CollectFileTaskResp(BaseTaskResp):
    agent_guid: str
    endpoint_name: str
    file_path: str
    file_sha1: Optional[str]
    file_sha256: Optional[str]
    file_size: Optional[int]
    resource_location: Optional[str]
    expired_date_time: Optional[str]
    password: Optional[str]


class ConnectivityResp(BaseResponse):
    status: str


class ConsumeLinkableResp(BaseResponse, alias_generator=None):
    total_consumed: int


class EndpointTaskResp(BaseTaskResp):
    agent_guid: str
    endpoint_name: str


class GetAlertDetailsResp(BaseResponse):
    alert: Union[SaeAlert, TiAlert]
    etag: str


class GetAlertListResp(BaseLinkableResp[Union[SaeAlert, TiAlert]]):
    total_count: int
    count: int


class GetEndpointDataResp(BaseLinkableResp[Endpoint]):
    ...


class GetExceptionListResp(BaseLinkableResp[ExceptionObject]):
    ...


class GetSuspiciousListResp(BaseLinkableResp[SuspiciousObject]):
    ...


class MultiResp(BaseMultiResponse[MsData]):
    ...


class MultiUrlResp(BaseMultiResponse[MsDataUrl]):
    ...


class NoContentResp(BaseResponse):
    ...


class EmailMessageTaskResp(BaseTaskResp):
    tasks: List[EmailMessage]


class SubmitFileToSandboxResp(BaseResponse):
    id: str
    digest: Digest
    arguments: Optional[str]


class SandboxAnalysisResultResp(BaseResponse):
    id: str
    type: SandboxObjectType
    analysis_completion_date_time: str
    risk_level: RiskLevel
    true_file_type: Optional[str]
    digest: Optional[Digest]
    arguments: Optional[str]
    detection_names: List[str] = Field(default=List)
    threat_types: List[str] = Field(default=List)


class SandboxSubmissionStatusResp(BaseStatusResponse):
    action: SandboxAction
    resource_location: Optional[str]
    is_cached: Optional[bool]
    digest: Optional[Digest]
    arguments: Optional[str]


class SandboxSuspiciousListResp(BaseResponse):
    items: List[SandboxSuspiciousObject]


class SandboxSubmitUrlTaskResp(BaseTaskResp):
    url: str
    sandbox_task_id: str


class TerminateProcessTaskResp(BaseTaskResp):
    agent_guid: str
    endpoint_name: str
    file_sha1: str
    file_name: Optional[str]
