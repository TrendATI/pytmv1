from enum import Enum


class Api(str, Enum):
    ADD_ALERT_NOTE = "/workbench/alerts/{0}/notes"
    ADD_TO_BLOCK_LIST = "/response/suspiciousObjects"
    ADD_TO_EXCEPTION_LIST = "/threatintel/suspiciousObjectExceptions"
    ADD_TO_SUSPICIOUS_LIST = "/threatintel/suspiciousObjects"
    COLLECT_ENDPOINT_FILE = "/response/endpoints/collectFile"
    CONNECTIVITY = ("/healthcheck/connectivity",)
    DELETE_EMAIL_MESSAGE = "/response/emails/delete"
    DISABLE_ACCOUNT = "/response/domainAccounts/disable"
    DOWNLOAD_SANDBOX_ANALYSIS_RESULT = "/sandbox/analysisResults/{0}/report"
    DOWNLOAD_SANDBOX_INVESTIGATION_PACKAGE = (
        "/sandbox/analysisResults/{0}/investigationPackage"
    )
    EDIT_ALERT_STATUS = "/workbench/alerts/{0}"
    ENABLE_ACCOUNT = "/response/domainAccounts/enable"
    ISOLATE_ENDPOINT = "/response/endpoints/isolate"
    GET_ALERT_DETAILS = "/workbench/alerts/{0}"
    GET_ALERT_LIST = "/workbench/alerts"
    GET_ENDPOINT_DATA = "/eiqs/endpoints"
    GET_EXCEPTION_LIST = "/threatintel/suspiciousObjectExceptions"
    GET_SANDBOX_SUBMISSION_STATUS = "/sandbox/tasks/{0}"
    GET_SANDBOX_ANALYSIS_RESULT = "/sandbox/analysisResults/{0}"
    GET_SANDBOX_SUSPICIOUS_LIST = (
        "/sandbox/analysisResults/{0}/suspiciousObjects"
    )
    GET_SUSPICIOUS_LIST = "/threatintel/suspiciousObjects"
    GET_TASK_RESULT = "/response/tasks/{0}"
    QUARANTINE_EMAIL_MESSAGE = "/response/emails/quarantine"
    REMOVE_FROM_BLOCK_LIST = "/response/suspiciousObjects/delete"
    REMOVE_FROM_EXCEPTION_LIST = (
        "/threatintel/suspiciousObjectExceptions/delete"
    )
    REMOVE_FROM_SUSPICIOUS_LIST = "/threatintel/suspiciousObjects/delete"
    RESET_PASSWORD = "/response/domainAccounts/resetPassword"
    RESTORE_EMAIL_MESSAGE = "/response/emails/restore"
    RESTORE_ENDPOINT = "/response/endpoints/restore"
    SIGN_OUT_ACCOUNT = "/response/domainAccounts/signOut"
    SUBMIT_FILE_TO_SANDBOX = "/sandbox/files/analyze"
    SUBMIT_URLS_TO_SANDBOX = "/sandbox/urls/analyze"
    TERMINATE_ENDPOINT_PROCESS = "/response/endpoints/terminateProcess"


class Iam(str, Enum):
    AAD = "Azure AD"
    OPAD = "On-premise AD"


class InvestigationStatus(str, Enum):
    BENIGN_TRUE_POSITIVE = "Benign True Positive"
    CLOSED = "Closed"
    FALSE_POSITIVE = "False Positive"
    IN_PROGRESS = "In Progress"
    NEW = "New"
    TRUE_POSITIVE = "True Positive"


class EntityType(str, Enum):
    HOST = "host"
    ACCOUNT = "account"
    EMAIL_ADDRESS = "emailAddress"


class HttpMethod(str, Enum):
    GET = "GET"
    PATCH = "PATCH"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"


class ObjectType(str, Enum):
    IP = "ip"
    URL = "url"
    DOMAIN = "domain"
    FILE_SHA1 = "fileSha1"
    FILE_SHA256 = "fileSha256"
    SENDER_MAIL_ADDRESS = "senderMailAddress"


class OperatingSystem(str, Enum):
    LINUX = "Linux"
    WINDOWS = "Windows"
    MACOS = "macOS"
    MACOSX = "macOSX"


class ProductCode(str, Enum):
    SAO = "sao"
    SDS = "sds"
    XES = "xes"


class Provenance(str, Enum):
    ALERT = "Alert"
    SWEEPING = "Sweeping"
    NETWORK_ANALYTICS = "Network Analytics"


class Provider(str, Enum):
    SAE = "SAE"
    TI = "TI"


class QueryField(str, Enum):
    AGENT_GUID = "agentGuid"
    LOGIN_ACCOUNT = "loginAccount"
    ENDPOINT_NAME = "endpointName"
    MAC_ADDRESS = "macAddress"
    IP = "ip"
    OS_NAME = "osName"
    PRODUCT_CODE = "productCode"
    INSTALLED_PRODUCT_CODES = "installedProductCodes"


class QueryOp(str, Enum):
    AND = " and "
    OR = " or "


class RiskLevel(str, Enum):
    NO_RISK = "noRisk"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SandboxAction(str, Enum):
    ANALYZE_FILE = "analyzeFile"
    ANALYZE_URL = "analyzeUrl"


class SandboxObjectType(str, Enum):
    URL = "url"
    FILE = "file"


class ScanAction(str, Enum):
    BLOCK = "block"
    LOG = "log"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Status(str, Enum):
    FAILED = "failed"
    QUEUED = "queued"
    REJECTED = "rejected"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    WAIT_FOR_APPROVAL = "waitForApproval"


class TaskAction(str, Enum):
    COLLECT_FILE = ("collectFile",)
    ISOLATE_ENDPOINT = ("isolate",)
    RESTORE_ENDPOINT = ("restoreIsolate",)
    TERMINATE_PROCESS = ("terminateProcess",)
    QUARANTINE_MESSAGE = "quarantineMessage"
    DELETE_MESSAGE = ("deleteMessage",)
    RESTORE_MESSAGE = ("restoreMessage",)
    BLOCK_SUSPICIOUS = ("block",)
    REMOVE_SUSPICIOUS = ("restoreBlock",)
    RESET_PASSWORD = "resetPassword"
    SUBMIT_SANDBOX = ("submitSandbox",)
    ENABLE_ACCOUNT = ("enableAccount",)
    DISABLE_ACCOUNT = ("disableAccount",)
    FORCE_SIGN_OUT = "forceSignOut"
