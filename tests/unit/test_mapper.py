from pytmv1 import (
    Entity,
    HostInfo,
    Indicator,
    InvestigationStatus,
    Severity,
    mapper,
)
from tests import data


def test_map_cef_with_sae_alert(mocker):
    mock_mapper = mocker.patch.object(mapper, "_map_sae")
    mapper.map_cef(data.sae_alert())
    mock_mapper.assert_called()


def test_map_cef_with_ti_alert(mocker):
    mock_mapper = mocker.patch.object(mapper, "_map_ti")
    mapper.map_cef(data.ti_alert())
    mock_mapper.assert_called()


def test_map_common():
    dictionary = mapper._map_common(data.sae_alert())
    assert dictionary["externalId"] == "1"
    assert dictionary["act"] == InvestigationStatus.NEW.value
    assert dictionary["cat"] == "Possible Credential Dumping via Registry"
    assert dictionary["Severity"] == Severity.HIGH.value
    assert dictionary["rt"] == "2022-09-06T02:49:33Z"
    assert dictionary["sourceServiceName"] == "SAE"
    assert dictionary["msg"] == "Workbench Link: https://THE_WORKBENCH_URL"
    assert dictionary["cnt"] == "64"
    assert dictionary["cn1"] == "1"
    assert dictionary["cn1Label"] == "Desktop Count"
    assert dictionary["cn2"] == "0"
    assert dictionary["cn2Label"] == "Server Count"
    assert dictionary["cn3"] == "1"
    assert dictionary["cn3Label"] == "Account Count"
    assert dictionary["cn4"] == "0"
    assert dictionary["cn4Label"] == "Email Address Count"
    assert dictionary["cs1"] == "Alert"
    assert dictionary["cs1Label"] == "Provenance"


def test_map_entities_with_type_email():
    entities = [Entity.construct(entity_value="email@email.com")]
    dictionary = {}
    mapper._map_entities(dictionary, entities)
    assert dictionary["duser"] == "email@email.com"


def test_map_entities_with_type_host_info():
    entities = [
        Entity.construct(
            entity_value=HostInfo.construct(
                name="host", ips=["1.1.1.1", "2.2.2.2"]
            )
        )
    ]
    dictionary = {}
    mapper._map_entities(dictionary, entities)
    assert dictionary["dhost"] == "host"
    assert dictionary["dst"] == "1.1.1.1, 2.2.2.2"


def test_map_entities_with_type_user():
    entities = [Entity.construct(entity_value="username")]
    dictionary = {}
    mapper._map_entities(dictionary, entities)
    assert dictionary["duser"] == "username"


def test_map_indicators_with_type_command_line():
    indicators = [Indicator.construct(type="command_line", value="cmd.exe")]
    dictionary = {}
    mapper._map_indicators(dictionary, indicators)
    assert dictionary["dproc"] == "cmd.exe"


def test_map_indicators_with_type_host_info():
    indicators = [
        Indicator.construct(
            value=HostInfo.construct(name="host", ips=["1.1.1.1", "2.2.2.2"])
        )
    ]
    dictionary = {}
    mapper._map_indicators(dictionary, indicators)
    assert dictionary["shost"] == "host"
    assert dictionary["src"] == "1.1.1.1, 2.2.2.2"


def test_map_indicators_with_unknown_type():
    indicators = [Indicator.construct(type="unknown_type", value="unknown")]
    dictionary = {}
    mapper._map_indicators(dictionary, indicators)
    assert dictionary["unknownType"] == "unknown"


def test_map_sae():
    alert = data.sae_alert()
    dictionary = mapper._map_common(alert)
    mapper._map_sae(dictionary, alert)
    assert dictionary["cs2"] == "Possible Credential Dumping via Registry Hive"
    assert dictionary["cs2Label"] == "Matched Filter"
    assert dictionary["cs3"] == "V9.T1003.004, V9.T1003.002, T1003"
    assert dictionary["cs3Label"] == "Matched Techniques"
    assert dictionary["reason"] == "Potential Credential Dumping via Registry"
    assert (
        dictionary["msg"]
        == "Workbench Link: https://THE_WORKBENCH_URL\nDescription:"
        " description"
    )


def test_map_ti():
    alert = data.ti_alert()
    dictionary = mapper._map_common(alert)
    mapper._map_ti(dictionary, alert)
    assert dictionary["cs2"] == "STIX2.malicious-activity"
    assert dictionary["cs2Label"] == "Matched Pattern Tags"
    assert dictionary["cs3"] == "[file:name = 'goog-phish-proto-1.vlpset']"
    assert dictionary["cs3Label"] == "Matched Pattern"
    assert (
        dictionary["msg"]
        == "Workbench Link: https://THE_WORKBENCH_URL\nReport Link:"
        " https://THE_TI_REPORT_URL"
    )
    assert dictionary["createdBy"] == "n/a"
    assert dictionary["campaign"] == "campaign"
    assert dictionary["industry"] == "industry"
    assert dictionary["regionAndCountry"] == "regionAndCountry"
