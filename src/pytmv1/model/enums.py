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
    GET_EMAIL_ACTIVITY_DATA = "/search/emailActivities"
    GET_ENDPOINT_ACTIVITY_DATA = "/search/endpointActivities"
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
    # Azure AD
    AAD = "AAD"
    # On-premise AD
    OPAD = "OPAD"


class IntegrityLevel(int, Enum):
    UNTRUSTED = 0
    LOW = 4096
    MEDIUM = 8192
    HIGH = 12288
    SYSTEM = 16384


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


class EventID(str, Enum):
    EVENT_PROCESS = "1"
    EVENT_FILE = "2"
    EVENT_CONNECTIO = "3"
    EVENT_DNS = "4"
    EVENT_REGISTRY = "5"
    EVENT_ACCOUNT = "6"
    EVENT_INTERNET = "7"
    XDR_EVENT_MODIFIED_PROCESS = "8"
    EVENT_WINDOWS_HOOK = "9"
    EVENT_WINDOWS_EVENT = "10"
    EVENT_AMSI = "11"
    EVENT_WMI = "12"
    TELEMETRY_MEMORY = "13"
    TELEMETRY_BM = "14"


class EventSubID(int, Enum):
    TELEMETRY_NONE = 0
    XDR_PROCESS_OPEN = 1
    XDR_PROCESS_CREATE = 2
    XDR_PROCESS_TERMINATE = 3
    XDR_PROCESS_LOAD_IMAGE = 4
    TELEMETRY_PROCESS_EXECUTE = 5
    TELEMETRY_PROCESS_CONNECT = 6
    TELEMETRY_PROCESS_TRACME = 7
    XDR_FILE_CREATE = 101
    XDR_FILE_OPEN = 102
    XDR_FILE_DELETE = 103
    XDR_FILE_SET_SECURITY = 104
    XDR_FILE_COPY = 105
    XDR_FILE_MOVE = 106
    XDR_FILE_CLOSE = 107
    TELEMETRY_FILE_MODIFY_TIMESTAMP = 108
    TELEMETRY_FILE_MODIFY = 109
    XDR_CONNECTION_CONNECT = 201
    XDR_CONNECTION_LISTEN = 202
    XDR_CONNECTION_CONNECT_INBOUND = 203
    XDR_CONNECTION_CONNECT_OUTBOUND = 204
    XDR_DNS_QUERY = 301
    XDR_REGISTRY_CREATE = 401
    XDR_REGISTRY_SET = 402
    XDR_REGISTRY_DELETE = 403
    XDR_REGISTRY_RENAME = 404
    XDR_ACCOUNT_ADD = 501
    XDR_ACCOUNT_DELETE = 502
    XDR_ACCOUNT_IMPERSONATE = 503
    XDR_ACCOUNT_MODIFY = 504
    XDR_INTERNET_OPEN = 601
    XDR_INTERNET_CONNECT = 602
    XDR_INTERNET_DOWNLOAD = 603
    XDR_MODIFIED_PROCESS_CREATE_REMOTETHREAD = 701
    XDR_MODIFIED_PROCESS_WRITE_MEMORY = 702
    TELEMETRY_MODIFIED_PROCESS_WRITE_PROCESS = 703
    TELEMETRY_MODIFIED_PROCESS_READ_PROCESS = 704
    TELEMETRY_MODIFIED_PROCESS_WRITE_PROCESS_NAME = 705
    XDR_WINDOWS_HOOK_SET = 801
    XDR_AMSI_EXECUTE = 901
    TELEMETRY_MEMORY_MODIFY = 1001
    TELEMETRY_MEMORY_MODIFY_PERMISSION = 1002
    TELEMETRY_MEMORY_READ = 1003
    TELEMETRY_BM_INVOKE = 1101
    TELEMETRY_BM_INVOKE_API = 1102


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


class SearchMode(str, Enum):
    DEFAULT = "default"
    COUNT_ONLY = "countOnly"


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
