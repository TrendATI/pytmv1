from requests import Response

from pytmv1 import (
    Entity,
    HostInfo,
    ImpactScope,
    Indicator,
    InvestigationStatus,
    MatchedFilter,
    MatchedIndicatorPattern,
    MatchedRule,
    SaeAlert,
    Severity,
    TiAlert,
)


class TextResponse(Response):
    def __init__(self, value: str):
        super().__init__()
        self.value = value

    @property
    def content(self) -> bytes:
        return self.value.encode("utf-8")

    @property
    def text(self) -> str:
        return self.value


def sae_alert():
    return SaeAlert.construct(
        id="1",
        investigationStatus=InvestigationStatus.NEW,
        model="Possible Credential Dumping via Registry",
        severity=Severity.HIGH,
        createdDateTime="2022-09-06T02:49:33Z",
        alertProvider="SAE",
        description="description",
        workbenchLink="https://THE_WORKBENCH_URL",
        score=64,
        impactScope=ImpactScope.construct(
            desktopCount=1,
            serverCount=0,
            accountCount=1,
            emailAddressCount=0,
            entities=[
                Entity.construct(
                    entity_value=HostInfo.construct(
                        name="host", ips=["1.1.1.1", "2.2.2.2"]
                    )
                )
            ],
        ),
        indicators=[
            Indicator.construct(
                provenance=["Alert"],
                value=HostInfo.construct(
                    name="host", ips=["1.1.1.1", "2.2.2.2"]
                ),
            )
        ],
        matchedRules=[
            MatchedRule.construct(
                name="Potential Credential Dumping via Registry",
                matchedFilters=[
                    MatchedFilter.construct(
                        name="Possible Credential Dumping via Registry Hive",
                        mitreTechniqueIds=[
                            "V9.T1003.004",
                            "V9.T1003.002",
                            "T1003",
                        ],
                    )
                ],
            )
        ],
    )


def ti_alert():
    return TiAlert.construct(
        id="1",
        investigationStatus=InvestigationStatus.NEW,
        model="Threat Intelligence Sweeping",
        campaign="campaign",
        industry="industry",
        regionAndCountry="regionAndCountry",
        severity=Severity.MEDIUM,
        createdDateTime="2022-09-06T02:49:33Z",
        alertProvider="TI",
        workbenchLink="https://THE_WORKBENCH_URL",
        reportLink="https://THE_TI_REPORT_URL",
        createdBy="n/a",
        score=42,
        impactScope=ImpactScope.construct(
            desktopCount=1,
            serverCount=0,
            accountCount=1,
            emailAddressCount=0,
            entities=[
                Entity.construct(
                    entity_value=HostInfo.construct(
                        name="host", ips=["1.1.1.1", "2.2.2.2"]
                    )
                )
            ],
        ),
        indicators=[
            Indicator.construct(
                provenance=["Alert"],
                value=HostInfo.construct(
                    name="host", ips=["1.1.1.1", "2.2.2.2"]
                ),
            )
        ],
        matchedIndicatorPatterns=[
            MatchedIndicatorPattern.construct(
                tags=["STIX2.malicious-activity"],
                pattern="[file:name = 'goog-phish-proto-1.vlpset']",
            )
        ],
        matchedRules=[
            MatchedRule.construct(
                name="Potential Credential Dumping via Registry",
                matchedFilters=[
                    MatchedFilter.construct(
                        name="Possible Credential Dumping via Registry Hive",
                        mitreTechniqueIds=[
                            "V9.T1003.004",
                            "V9.T1003.002",
                            "T1003",
                        ],
                    )
                ],
            )
        ],
    )
