from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, Union

from pydantic import BaseModel as PydanticBaseModel
from pydantic import Field
from pydantic.utils import to_lower_camel

from .enums import (
    EntityType,
    EventID,
    EventSubID,
    Iam,
    IntegrityLevel,
    InvestigationStatus,
    ObjectType,
    OperatingSystem,
    ProductCode,
    Provider,
    RiskLevel,
    ScanAction,
    Severity,
    Status,
)


class BaseModel(PydanticBaseModel):
    class Config:
        alias_generator = to_lower_camel
        allow_population_by_field_name = True


class BaseConsumable(BaseModel):
    ...


def _get_task_id(headers: List[Dict[str, str]]) -> Optional[str]:
    task_id: str = next(
        (
            h.get("value", "")
            for h in headers
            if "Operation-Location" == h.get("name", "")
        ),
        "",
    ).split("/")[-1]
    return task_id if task_id != "" else None


class Account(BaseModel):
    account_name: str
    iam: Iam
    last_action_date_time: str
    status: Status


class Alert(BaseConsumable):
    id: str
    schema_version: str
    investigation_status: InvestigationStatus
    workbench_link: str
    alert_provider: Provider
    model: str
    score: int
    severity: Severity
    impact_scope: ImpactScope
    created_date_time: str
    updated_date_time: str
    indicators: List[Indicator]


class Digest(BaseModel):
    md5: str
    sha1: str
    sha256: str


class EmailMessage(BaseModel):
    last_action_date_time: str
    message_id: Optional[str] = None
    mail_box: Optional[str] = None
    message_subject: Optional[str] = None
    unique_id: Optional[str] = None
    organization_id: Optional[str] = None
    status: Status


class Value(BaseModel):
    updated_date_time: str
    value: str


class ValueList(BaseModel):
    updated_date_time: str
    value: List[str]


class Endpoint(BaseConsumable):
    agent_guid: str
    login_account: ValueList
    endpoint_name: Value
    mac_address: ValueList
    ip: ValueList
    os_name: OperatingSystem
    os_version: str
    os_description: str
    product_code: ProductCode
    installed_product_codes: List[ProductCode]


class EmailActivity(BaseConsumable):
    mail_msg_subject: Optional[str] = None
    mail_msg_id: Optional[str] = None
    msg_uuid: Optional[str] = None
    mailbox: Optional[str] = None
    mail_sender_ip: Optional[str] = None
    mail_from_addresses: List[str] = Field(default=[])
    mail_whole_header: List[str] = Field(default=[])
    mail_to_addresses: List[str] = Field(default=[])
    mail_source_domain: Optional[str] = None
    search_d_l: Optional[str] = None
    scan_type: Optional[str] = None
    event_time: Optional[int] = None
    org_id: Optional[str] = None
    mail_urls_visible_link: List[str] = Field(default=[])
    mail_urls_real_link: List[str] = Field(default=[])


class EndpointActivity(BaseConsumable):
    dpt: Optional[int] = None
    dst: Optional[str] = None
    endpoint_guid: Optional[str] = None
    endpoint_host_name: Optional[str] = None
    endpoint_ip: List[str] = Field(default=[])
    event_id: Optional[EventID] = None
    event_sub_id: Optional[EventSubID] = None
    object_integrity_level: Optional[IntegrityLevel] = None
    object_true_type: Optional[int] = None
    object_sub_true_type: Optional[int] = None
    win_event_id: Optional[int] = None
    event_time: Optional[int] = None
    event_time_d_t: Optional[str] = None
    host_name: Optional[str] = None
    logon_user: List[str] = Field(default=[])
    object_cmd: Optional[str] = None
    object_file_hash_sha1: Optional[str] = None
    object_file_path: Optional[str] = None
    object_host_name: Optional[str] = None
    object_ip: Optional[str] = None
    object_ips: List[str] = Field(default=[])
    object_port: Optional[int] = None
    object_registry_data: Optional[str] = None
    object_registry_key_handle: Optional[str] = None
    object_registry_value: Optional[str] = None
    object_signer: List[str] = Field(default=[])
    object_signer_valid: List[bool] = Field(default=[])
    object_user: Optional[str] = None
    os: Optional[str] = None
    parent_cmd: Optional[str] = None
    parent_file_hash_sha1: Optional[str] = None
    parent_file_path: Optional[str] = None
    process_cmd: Optional[str] = None
    process_file_hash_sha1: Optional[str] = None
    process_file_path: Optional[str] = None
    request: Optional[str] = None
    search_d_l: Optional[str] = None
    spt: Optional[int] = None
    src: Optional[str] = None
    src_file_hash_sha1: Optional[str] = None
    src_file_path: Optional[str] = None
    tags: List[str] = Field(default=[])
    uuid: Optional[str] = None


class HostInfo(BaseModel):
    name: str
    ips: List[str]
    guid: str


class Entity(BaseModel):
    entity_id: str
    entity_type: EntityType
    entity_value: Union[str, HostInfo]
    related_entities: List[str]
    related_indicator_ids: List[int]
    provenance: List[str]


class Error(BaseModel):
    status: int
    code: Optional[str] = None
    message: Optional[str] = None
    number: Optional[int] = None


class ExceptionObject(BaseConsumable):
    value: str
    type: ObjectType
    last_modified_date_time: str
    description: Optional[str]

    def __init__(self, **data: str) -> None:
        super().__init__(value=self._obj_value(data), **data)

    @staticmethod
    def _obj_value(args: Dict[str, str]) -> str:
        obj_value: Optional[str] = args.get(args.get("type", ""))
        if obj_value is None:
            raise ValueError("Object value not found")
        return obj_value


class ImpactScope(BaseModel):
    desktop_count: int
    server_count: int
    account_count: int
    email_address_count: int
    entities: List[Entity]


class Indicator(BaseModel):
    id: int
    type: str
    value: Union[str, HostInfo]
    related_entities: List[str]
    provenance: List[str]


class MatchedEvent(BaseModel):
    uuid: str
    matched_date_time: str
    type: str


class MatchedFilter(BaseModel):
    id: str
    name: str
    matched_date_time: str
    mitre_technique_ids: List[str]
    matched_events: List[MatchedEvent]


class MatchedIndicatorPattern(BaseModel):
    id: str
    pattern: str
    tags: List[str]
    matched_logs: List[str] = Field(default=[])


class MatchedRule(BaseModel):
    id: str
    name: str
    matched_filters: List[MatchedFilter]


class MsData(BaseModel):
    status: int
    task_id: Optional[str] = None

    def __init__(self, **data: Any):
        super().__init__(
            taskId=_get_task_id(data.pop("headers", {})),
            **data,
        )


class MsDataUrl(MsData):
    url: str
    id: Optional[str]
    digest: Optional[Digest]

    def __init__(self, **data: Any):
        data.update(data.pop("body", {}))
        super().__init__(**data)


class MsError(Error):
    extra: Dict[str, str] = {}
    task_id: Optional[str]

    def __init__(self, **data: Any):
        data.update(data.pop("body", {}))
        data.update(data.pop("error", {}))
        super().__init__(
            extra={"url": data.pop("url", "")},
            taskId=_get_task_id(data.pop("headers", {})),
            **data,
        )


class MsStatus(BaseModel):
    __root__: List[int]

    def __init__(self, **data: Any):
        super().__init__(
            root=[int(d.get("status", 500)) for d in data.get("__root__", [])]
        )

    def values(self) -> List[int]:
        return self.__root__


class SaeAlert(Alert):
    description: str
    matched_rules: List[MatchedRule]


class SaeIndicator(Indicator):
    field: str
    filter_ids: List[str]


class SandboxSuspiciousObject(BaseModel):
    risk_level: RiskLevel
    analysis_completion_date_time: str
    expired_date_time: str
    root_sha1: str
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


class SuspiciousObject(ExceptionObject):
    scan_action: ScanAction
    risk_level: RiskLevel
    in_exception_list: bool
    expired_date_time: str


class TiAlert(Alert):
    campaign: Optional[str]
    industry: Optional[str]
    region_and_country: Optional[str]
    created_by: str
    total_indicator_count: int
    matched_indicator_count: int
    report_link: str
    matched_indicator_patterns: List[MatchedIndicatorPattern]


class TiIndicator(Indicator):
    fields: List[List[str]]
    matched_indicator_pattern_ids: List[str]
    first_seen_date_times: List[str]
    last_seen_date_times: List[str]
