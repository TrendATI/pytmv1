from typing import Dict, List

from pydantic.utils import to_lower_camel

from .model.commons import (
    Alert,
    Entity,
    HostInfo,
    Indicator,
    SaeAlert,
    TiAlert,
)

INDICATOR_CEF_MAP: Dict[str, str] = {
    "command_line": "dproc",
    "url": "request",
    "domain": "sntdom",
    "ip": "src",
    "email_sender": "suser",
    "fullpath": "filePath",
    "filename": "fname",
    "file_sha1": "fileHash",
    "user_account": "suser",
    "host": "shost",
    "port": "spt",
    "process_id": "dpid",
    "registry_key": "TrendMicroVoRegistryKeyHandle",
    "registry_value": "TrendMicroVoRegistryValue",
    "registry_value_data": "TrendMicroVoRegistryData",
    "file_sha256": "TrendMicroVoFileHashSha256",
    "email_message_id": "TrendMicroVoEmailMessageId",
    "email_message_unique_id": "TrendMicroVoEmailMessageUniqueId",
}


def map_cef(alert: Alert) -> Dict[str, str]:
    data: Dict[str, str] = _map_common(alert)
    _map_entities(data, alert.impact_scope.entities)
    _map_indicators(data, alert.indicators)
    if isinstance(alert, SaeAlert):
        _map_sae(data, alert)
    if isinstance(alert, TiAlert):
        _map_ti(data, alert)
    return data


def _map_common(alert: Alert) -> Dict[str, str]:
    return dict(
        externalId=alert.id,
        act=alert.investigation_status,
        cat=alert.model,
        Severity=alert.severity,
        rt=alert.created_date_time,
        sourceServiceName=alert.alert_provider,
        msg="Workbench Link: " + alert.workbench_link,
        cnt=str(alert.score),
        cn1=str(alert.impact_scope.desktop_count),
        cn1Label="Desktop Count",
        cn2=str(alert.impact_scope.server_count),
        cn2Label="Server Count",
        cn3=str(alert.impact_scope.account_count),
        cn3Label="Account Count",
        cn4=str(alert.impact_scope.email_address_count),
        cn4Label="Email Address Count",
        cs1=", ".join(alert.indicators[0].provenance),
        cs1Label="Provenance",
    )


def _map_entities(data: Dict[str, str], entities: List[Entity]) -> None:
    for entity in entities:
        if isinstance(entity.entity_value, HostInfo):
            data["dhost"] = entity.entity_value.name
            data["dst"] = ", ".join(entity.entity_value.ips)
        else:
            data["duser"] = entity.entity_value


def _map_indicators(data: Dict[str, str], indicators: List[Indicator]) -> None:
    for indicator in indicators:
        if isinstance(indicator.value, HostInfo):
            data["shost"] = indicator.value.name
            data["src"] = ", ".join(indicator.value.ips)
        else:
            data[
                INDICATOR_CEF_MAP.get(
                    indicator.type, to_lower_camel(indicator.type)
                )
            ] = indicator.value


def _map_sae(data: Dict[str, str], alert: SaeAlert) -> None:
    data["cs2"] = alert.matched_rules[0].matched_filters[0].name
    data["cs2Label"] = "Matched Filter"
    data["cs3"] = ", ".join(
        alert.matched_rules[0].matched_filters[0].mitre_technique_ids
    )
    data["cs3Label"] = "Matched Techniques"
    data["reason"] = alert.matched_rules[0].name
    data["msg"] = data.get("msg", "") + f"\nDescription: {alert.description}"


def _map_ti(data: Dict[str, str], alert: TiAlert) -> None:
    data["cs2"] = ", ".join(alert.matched_indicator_patterns[0].tags)
    data["cs2Label"] = "Matched Pattern Tags"
    data["cs3"] = alert.matched_indicator_patterns[0].pattern
    data["cs3Label"] = "Matched Pattern"
    data["msg"] = data.get("msg", "") + f"\nReport Link: {alert.report_link}"
    data["createdBy"] = alert.created_by
    if alert.campaign:
        data["campaign"] = alert.campaign
    if alert.industry:
        data["industry"] = alert.industry
    if alert.region_and_country:
        data["regionAndCountry"] = alert.region_and_country
