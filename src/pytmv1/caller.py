from __future__ import annotations

import logging
from functools import lru_cache
from logging import Logger
from typing import Callable, Optional, Type, Union

from . import utils
from .core import Core
from .model.commons import (
    Endpoint,
    ExceptionObject,
    SaeAlert,
    SuspiciousObject,
    TiAlert,
)
from .model.enums import Api, HttpMethod, InvestigationStatus, QueryOp
from .model.requests import (
    AccountTask,
    EmailMessageIdTask,
    EmailMessageUIdTask,
    EndpointTask,
    FileTask,
    ObjectTask,
    ProcessTask,
    SuspiciousObjectTask,
)
from .model.responses import (
    AddAlertNoteResp,
    BaseTaskResp,
    BytesResp,
    ConnectivityResp,
    ConsumeLinkableResp,
    GetAlertDetailsResp,
    GetAlertListResp,
    GetEndpointDataResp,
    GetExceptionListResp,
    GetSuspiciousListResp,
    MultiResp,
    MultiUrlResp,
    NoContentResp,
    S,
    SandboxAnalysisResultResp,
    SandboxSubmissionStatusResp,
    SandboxSuspiciousListResp,
    SubmitFileToSandboxResp,
)
from .results import MultiResult, Result

log: Logger = logging.getLogger(__name__)


def client(
    name: str,
    token: str,
    url: str,
    pool_connections: int = 1,
    pool_maxsize: int = 1,
    connect_timeout: int = 30,
    read_timeout: int = 30,
) -> Client:
    """Helper function to initialize a :class:`Client`.

    :param name: Identify the application using this library.
    :type name: str
    :param token: Authentication token created for your account.
    :type token: str
    :param url: Vision One API url this client connects to.
    :type url: str
    :param pool_connections: (optional) Number of connection to cache.
    :type pool_connections: int
    :param pool_maxsize: (optional) Maximum size of the pool.
    :type pool_maxsize: int
    :param connect_timeout: (optional) Seconds before connection timeout.
    :type connect_timeout: int
    :param read_timeout: (optional) Seconds before read timeout.
    :type connect_timeout: int
    :rtype: Client
    """
    log.debug(
        "Initializing new client with [Appname=%s, Token=*****, URL=%s]",
        name,
        url,
    )
    return Client(
        Core(
            name,
            token,
            url,
            pool_connections,
            pool_maxsize,
            connect_timeout,
            read_timeout,
        )
    )


@lru_cache(maxsize=None)
class Client:
    def __init__(self, core: Core):
        self._core = core

    def add_alert_note(
        self, alert_id: str, note: str
    ) -> Result[AddAlertNoteResp]:
        """Adds a note to the specified Workbench alert.

        :param alert_id: Workbench alert id.
        :type alert_id: str
        :param note: Value of the note.
        :type note: str
        :rtype: Result[AddAlertNoteResp]:
        """
        return self._core.send(
            AddAlertNoteResp,
            Api.ADD_ALERT_NOTE.value.format(alert_id),
            HttpMethod.POST,
            json={"content": note},
        )

    def add_to_block_list(
        self, *objects: ObjectTask
    ) -> MultiResult[MultiResp]:
        """Adds object(s) to the Suspicious Object List,
        which blocks the objects on subsequent detections.

        :param objects: Object(s) to add.
        :type objects: Tuple[ObjectTask, ...]
        :rtype: MultiResult[MultiResp]
        """
        return self._core.send_multi(
            MultiResp,
            Api.ADD_TO_BLOCK_LIST,
            json=utils.build_object_request(*objects),
        )

    def add_to_exception_list(
        self, *objects: ObjectTask
    ) -> MultiResult[MultiResp]:
        """Adds object(s) to the Exception List.

        :param objects: Object(s) to add.
        :type objects: Tuple[ObjectTask, ...]
        :rtype: MultiResult[MultiResp]
        """
        return self._core.send_multi(
            MultiResp,
            Api.ADD_TO_EXCEPTION_LIST,
            json=utils.build_object_request(*objects),
        )

    def add_to_suspicious_list(
        self, *objects: SuspiciousObjectTask
    ) -> MultiResult[MultiResp]:
        """Adds object(s) to the Suspicious Object List.

        :param objects: Object(s) to add.
        :type objects: Tuple[SuspiciousObjectTask, ...]
        :rtype: MultiResult[MultiResp]
        """
        return self._core.send_multi(
            MultiResp,
            Api.ADD_TO_SUSPICIOUS_LIST,
            json=utils.build_suspicious_request(*objects),
        )

    def collect_file(self, *files: FileTask) -> MultiResult[MultiResp]:
        """Collects a file from one or more endpoints and then sends the files
        to Vision One in a password-protected archive.

        :param files: File(s) to collect.
        :type files: Tuple[FileTask, ...]
        :rtype: MultiResult[MultiResp]
        """
        return self._core.send_endpoint(Api.COLLECT_ENDPOINT_FILE, *files)

    def consume_alert_list(
        self,
        consumer: Callable[[Union[SaeAlert, TiAlert]], None],
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> Result[ConsumeLinkableResp]:
        """Retrieves and consume workbench alerts.

        :param start_time: Date that indicates the start of the data retrieval
        time range (yyyy-MM-ddThh:mm:ssZ in UTC).
        Defaults to 24 hours before the request is made.
        :type start_time: Optional[str]
        :param end_time: Date that indicates the end of the data retrieval
        time range (yyyy-MM-ddThh:mm:ssZ in UTC).
        Defaults to the time the request is made.
        :type end_time: Optional[str]
        :param consumer: Function which will consume every record in result.
        :type consumer: Callable[[Union[SaeAlert, TiAlert]], None]
        :rtype: Result[ConsumeLinkableResp]:
        """
        return self._core.send_linkable(
            GetAlertListResp,
            Api.GET_ALERT_LIST,
            consumer,
            params=utils.filter_none(
                {"startDateTime": start_time, "endDateTime": end_time}
            ),
        )

    def consume_endpoint_data(
        self,
        consumer: Callable[[Endpoint], None],
        op: QueryOp,
        *values: str,
    ) -> Result[ConsumeLinkableResp]:
        """Retrieves and consume endpoints.

        :param consumer: Function which will consume every record in result.
        :type consumer: Callable[[Endpoint], None]
        :param op: Query operator to apply.
        :type op: QueryOp
        :param values: Agent guid, login account, endpoint name, ip address,
        mac address, operating system, product code.
        :type values: Tuple[str, ...]
        :rtype: Result[ConsumeLinkableResp]:
        """
        return self._core.send_linkable(
            GetEndpointDataResp,
            Api.GET_ENDPOINT_DATA,
            consumer,
            headers=utils.endpoint_query(op, *values),
        )

    def consume_exception_list(
        self, consumer: Callable[[ExceptionObject], None]
    ) -> Result[ConsumeLinkableResp]:
        """Retrieves and consume exception objects.

        :param consumer: Function which will consume every record in result.
        :type consumer: Callable[[ExceptionObject], None]
        :rtype: Result[ConsumeLinkableResp]:
        """
        return self._core.send_linkable(
            GetExceptionListResp, Api.GET_EXCEPTION_LIST, consumer
        )

    def consume_suspicious_list(
        self, consumer: Callable[[SuspiciousObject], None]
    ) -> Result[ConsumeLinkableResp]:
        """Retrieves and consume suspicious objects.

        :param consumer: Function which will consume every record in result.
        :type consumer: Callable[[SuspiciousObject], None]
        :rtype: Result[ConsumeLinkableResp]:
        """
        return self._core.send_linkable(
            GetSuspiciousListResp, Api.GET_SUSPICIOUS_LIST, consumer
        )

    def delete_email_message(
        self, *messages: Union[EmailMessageUIdTask, EmailMessageIdTask]
    ) -> MultiResult[MultiResp]:
        """Deletes a message from one or more mailboxes.

        :param messages: Message(s) to delete.
        :type messages: Tuple[EmailUIdTask, EmailMsgIdTask, ...]
        :rtype: MultiResult[MultiResp]
        """
        return self._core.send_multi(
            MultiResp,
            Api.DELETE_EMAIL_MESSAGE,
            json=[
                task.dict(by_alias=True, exclude_none=True)
                for task in messages
            ],
        )

    def disable_account(
        self, *accounts: AccountTask
    ) -> MultiResult[MultiResp]:
        """Signs the user out of all active application and browser sessions,
        and prevents the user from signing in any new session.

        :param accounts: Account(s) to disable.
        :type accounts: Tuple[AccountTask, ...]
        :rtype: MultiResult[MultiResp]
        """
        return self._core.send_multi(
            MultiResp,
            Api.DISABLE_ACCOUNT,
            json=[
                task.dict(by_alias=True, exclude_none=True)
                for task in accounts
            ],
        )

    def download_sandbox_analysis_result(
        self,
        submit_id: str,
        poll: bool = True,
        poll_time_sec: float = 1800,
    ) -> Result[BytesResp]:
        """Downloads the analysis results of the specified object as PDF.

        :param submit_id: Sandbox submission id.
        :type submit_id: str
        :param poll: If we should wait until the task is finished before
        to return the result.
        :type poll: bool
        :param poll_time_sec: Maximum time to wait for the result to
         be available.
        :type poll_time_sec: float
        :rtype: Result[BytesResp]:
        """
        return self._core.send_sandbox_result(
            BytesResp,
            Api.DOWNLOAD_SANDBOX_ANALYSIS_RESULT,
            submit_id,
            poll,
            poll_time_sec,
        )

    def download_sandbox_investigation_package(
        self,
        submit_id: str,
        poll: bool = True,
        poll_time_sec: float = 1800,
    ) -> Result[BytesResp]:
        """Downloads the Investigation Package of the specified object.

        :param submit_id: Sandbox submission id.
        :type submit_id: str
        :param poll: If we should wait until the task is finished before
        to return the result.
        :type poll: bool
        :param poll_time_sec: Maximum time to wait for the result to
         be available.
        :type poll_time_sec: float
        :rtype: Result[BytesResp]:
        """
        return self._core.send_sandbox_result(
            BytesResp,
            Api.DOWNLOAD_SANDBOX_INVESTIGATION_PACKAGE,
            submit_id,
            poll,
            poll_time_sec,
        )

    def edit_alert_status(
        self,
        alert_id: str,
        status: InvestigationStatus,
        if_match: str,
    ) -> Result[NoContentResp]:
        """Edit the status of an alert or investigation triggered in Workbench.

        :param alert_id: Workbench alert id.
        :type alert_id: str
        :param status: Status to be updated.
        :type status: InvestigationStatus
        :param if_match: Target resource will be updated only if
         it matches ETag of the target one.
        :type if_match: str
        :rtype: Result[NoContentResp]:
        """
        return self._core.send(
            NoContentResp,
            Api.EDIT_ALERT_STATUS.value.format(alert_id),
            HttpMethod.PATCH,
            json={"investigationStatus": status},
            headers={
                "If-Match": (
                    if_match
                    if if_match.startswith('"')
                    else '"' + if_match + '"'
                )
            },
        )

    def enable_account(self, *accounts: AccountTask) -> MultiResult[MultiResp]:
        """Allows the user to sign in to new application and browser sessions.

        :param accounts: Account(s) to enable.
        :type accounts: Tuple[AccountTask, ...]
        :rtype: MultiResult[MultiResp]
        """
        return self._core.send_multi(
            MultiResp,
            Api.ENABLE_ACCOUNT,
            json=[
                task.dict(by_alias=True, exclude_none=True)
                for task in accounts
            ],
        )

    def get_alert_details(self, alert_id: str) -> Result[GetAlertDetailsResp]:
        """Displays information about the specified alert.

        :param alert_id: Workbench alert id.
        :type alert_id: str
        :rtype: Result[GetAlertDetailsResp]:
        """
        return self._core.send(
            GetAlertDetailsResp,
            Api.GET_ALERT_DETAILS.value.format(alert_id),
        )

    def get_alert_list(
        self, start_time: Optional[str] = None, end_time: Optional[str] = None
    ) -> Result[GetAlertListResp]:
        """Retrieves workbench alerts in a paginated list.

        :param start_time: Date that indicates the start of the data retrieval
        time range (yyyy-MM-ddThh:mm:ssZ in UTC).
        Defaults to 24 hours before the request is made.
        :type start_time: Optional[str]
        :param end_time: Date that indicates the end of the data retrieval
        time range (yyyy-MM-ddThh:mm:ssZ in UTC).
        Defaults to the time the request is made.
        :type end_time: Optional[str]
        :rtype: Result[GetAlertListResp]:
        """
        return self._core.send(
            GetAlertListResp,
            Api.GET_ALERT_LIST,
            params=utils.filter_none(
                {"startDateTime": start_time, "endDateTime": end_time}
            ),
        )

    def get_base_task_result(
        self,
        task_id: str,
        poll: bool = True,
        poll_time_sec: float = 1800,
    ) -> Result[BaseTaskResp]:
        """Retrieves the result of a response task.

        :param task_id: Task id.
        :type task_id: str
        :param poll: If we should wait until the task is finished before
         to return the result.
        :type poll: bool
        :param poll_time_sec: Maximum time to wait for the result
        to be available.
        :type poll_time_sec: float
        :rtype: Result[BaseTaskResultResp]:
        """
        return self._core.send_task_result(
            BaseTaskResp, task_id, poll, poll_time_sec
        )

    def get_endpoint_data(
        self, op: QueryOp, *values: str
    ) -> Result[GetEndpointDataResp]:
        """Retrieves endpoints in a paginated list filtered by provided values.

        :param op: Query operator to apply.
        :type op: QueryOp
        :param values: Agent guid, login account, endpoint name, ip address,
        mac address, operating system, product code.
        :type values: Tuple[str, ...]
        :rtype: Result[GetEndpointDataResp]:
        """
        return self._core.send(
            GetEndpointDataResp,
            Api.GET_ENDPOINT_DATA,
            headers=utils.endpoint_query(op, *values),
        )

    def get_exception_list(self) -> Result[GetExceptionListResp]:
        """Retrieves exception objects in a paginated list.

        :rtype: Result[GetExceptionListResp]:
        """
        return self._core.send(GetExceptionListResp, Api.GET_EXCEPTION_LIST)

    def get_sandbox_analysis_result(
        self,
        submit_id: str,
        poll: bool = True,
        poll_time_sec: float = 1800,
    ) -> Result[SandboxAnalysisResultResp]:
        """Retrieves the analysis results of the specified object.

        :param submit_id: Sandbox submission id.
        :type submit_id: str
        :param poll: If we should wait until the task is finished before
         to return the result.
        :type poll: bool
        :param poll_time_sec: Maximum time to wait for the result
         to be available.
        :type poll_time_sec: float
        :rtype: Result[SandboxAnalysisResultResp]:
        """
        return self._core.send_sandbox_result(
            SandboxAnalysisResultResp,
            Api.GET_SANDBOX_ANALYSIS_RESULT,
            submit_id,
            poll,
            poll_time_sec,
        )

    def get_sandbox_submission_status(
        self, submit_id: str
    ) -> Result[SandboxSubmissionStatusResp]:
        """Retrieves the submission status of the specified object.

        :param submit_id: Sandbox submission id.
        :type submit_id: str
        :rtype: Result[SandboxSubmissionStatusResp]:
        """
        return self._core.send(
            SandboxSubmissionStatusResp,
            Api.GET_SANDBOX_SUBMISSION_STATUS.value.format(submit_id),
        )

    def get_sandbox_suspicious_list(
        self,
        submit_id: str,
        poll: bool = True,
        poll_time_sec: float = 1800,
    ) -> Result[SandboxSuspiciousListResp]:
        """Retrieves the suspicious object list associated to the
        specified object.

        :param submit_id: Sandbox submission id.
        :type submit_id: str
        :param poll: If we should wait until the task is finished before
         to return the result.
        :type poll: bool
        :param poll_time_sec: Maximum time to wait for the result
         to be available.
        :type poll_time_sec: float
        :rtype: Result[SandboxSuspiciousListResp]:
        """
        return self._core.send_sandbox_result(
            SandboxSuspiciousListResp,
            Api.GET_SANDBOX_SUSPICIOUS_LIST,
            submit_id,
            poll,
            poll_time_sec,
        )

    def get_suspicious_list(
        self,
    ) -> Result[GetSuspiciousListResp]:
        """Retrieves suspicious objects in a paginated list.

        :rtype: Result[GetSuspiciousListResp]:
        """
        return self._core.send(GetSuspiciousListResp, Api.GET_SUSPICIOUS_LIST)

    def get_task_result(
        self,
        task_id: str,
        class_: Type[S],
        poll: bool = True,
        poll_time_sec: float = 1800,
    ) -> Result[S]:
        """Retrieves the result of a response task.

        :param task_id: Task id.
        :type task_id: str
        :param class_: Expected task result class.
        :type class_: Type[S]
        :param poll: If we should wait until the task is finished before
         to return the result.
        :type poll: bool
        :param poll_time_sec: Maximum time to wait for the result
        to be available.
        :type poll_time_sec: float
        :rtype: Result[BaseTaskResultResp]:
        """
        return self._core.send_task_result(
            class_, task_id, poll, poll_time_sec
        )

    def isolate_endpoint(
        self, *endpoints: EndpointTask
    ) -> MultiResult[MultiResp]:
        """Disconnects one or more endpoints from the network
        but allows communication with the managing Trend Micro server product.

        :param endpoints: Endpoint(s) to isolate.
        :type endpoints: Tuple[EndpointTask, ...]
        :rtype: MultiResult[MultiResp]
        """
        return self._core.send_endpoint(Api.ISOLATE_ENDPOINT, *endpoints)

    def quarantine_email_message(
        self, *messages: Union[EmailMessageUIdTask, EmailMessageIdTask]
    ) -> MultiResult[MultiResp]:
        """Quarantine a message from one or more mailboxes.

        :param messages: Message(s) to quarantine.
        :type messages: Tuple[EmailUIdTask, EmailMsgIdTask, ...]
        :rtype: MultiResult[MultiResp]
        """
        return self._core.send_multi(
            MultiResp,
            Api.QUARANTINE_EMAIL_MESSAGE,
            json=[
                task.dict(by_alias=True, exclude_none=True)
                for task in messages
            ],
        )

    def remove_from_block_list(
        self, *objects: ObjectTask
    ) -> MultiResult[MultiResp]:
        """Removes object(s) that was added to the Suspicious Object List
          using the "Add to block list" action

        :param objects: Object(s) to remove.
        :type objects: Tuple[ObjectTask, ...]
        :rtype: MultiResult[MultiResp]
        """
        return self._core.send_multi(
            MultiResp,
            Api.REMOVE_FROM_BLOCK_LIST,
            json=utils.build_object_request(*objects),
        )

    def remove_from_exception_list(
        self, *objects: ObjectTask
    ) -> MultiResult[MultiResp]:
        """Removes object(s) from the Exception List.

        :param objects: Object(s) to remove.
        :type objects: Tuple[ObjectTask, ...]
        :rtype: MultiResult[MultiResp]
        """
        return self._core.send_multi(
            MultiResp,
            Api.REMOVE_FROM_EXCEPTION_LIST,
            json=utils.build_object_request(*objects),
        )

    def remove_from_suspicious_list(
        self, *objects: ObjectTask
    ) -> MultiResult[MultiResp]:
        """Removes object(s) from the Suspicious List.

        :param objects: Object(s) to remove.
        :type objects: Tuple[ObjectTask, ...]
        :rtype: MultiResult[MultiResp]
        """
        return self._core.send_multi(
            MultiResp,
            Api.REMOVE_FROM_SUSPICIOUS_LIST,
            json=utils.build_object_request(*objects),
        )

    def reset_password_account(
        self, *accounts: AccountTask
    ) -> MultiResult[MultiResp]:
        """Signs the user out of all active application and browser sessions,
        and forces the user to create a new password during the next sign-in
        attempt.

        :param accounts: Account(s) to reset.
        :type accounts: Tuple[AccountTask, ...]
        :rtype: MultiResult[MultiResp]
        """
        return self._core.send_multi(
            MultiResp,
            Api.RESET_PASSWORD,
            json=[
                task.dict(by_alias=True, exclude_none=True)
                for task in accounts
            ],
        )

    def restore_endpoint(
        self, *endpoints: EndpointTask
    ) -> MultiResult[MultiResp]:
        """Restores network connectivity to one or more endpoints that applied
        the "Isolate endpoint" action.

        :param endpoints: Endpoint(s) to restore.
        :type endpoints: Tuple[EndpointTask, ...]
        :rtype: MultiResult[MultiResp]
        """
        return self._core.send_endpoint(Api.RESTORE_ENDPOINT, *endpoints)

    def restore_email_message(
        self, *messages: Union[EmailMessageUIdTask, EmailMessageIdTask]
    ) -> MultiResult[MultiResp]:
        """Restore quarantined email message(s).

        :param messages: Message(s) to restore.
        :type messages: Tuple[EmailUIdTask, EmailMsgIdTask, ...]
        :rtype: MultiResult[MultiResp]
        """
        return self._core.send_multi(
            MultiResp,
            Api.RESTORE_EMAIL_MESSAGE,
            json=[
                task.dict(by_alias=True, exclude_none=True)
                for task in messages
            ],
        )

    def sign_out_account(
        self, *accounts: AccountTask
    ) -> MultiResult[MultiResp]:
        """Signs the user out of all active application and browser sessions.

        :param accounts: Account(s) to sign out.
        :type accounts: Tuple[AccountTask, ...]
        :rtype: MultiResult[MultiResp]
        """
        return self._core.send_multi(
            MultiResp,
            Api.SIGN_OUT_ACCOUNT,
            json=[
                task.dict(by_alias=True, exclude_none=True)
                for task in accounts
            ],
        )

    def submit_file_to_sandbox(
        self,
        file: bytes,
        file_name: str,
        document_password: Optional[str] = None,
        archive_password: Optional[str] = None,
        arguments: Optional[str] = None,
    ) -> Result[SubmitFileToSandboxResp]:
        """Submits a file to the sandbox for analysis.

        :param file: Raw content in bytes.
        :type file: bytes
        :param file_name: Name of the file.
        :type file_name: str
        :param document_password: Password used to
         decrypt the submitted file sample.
        :type document_password: Optional[str]
        :param archive_password: Password encoded in Base64 used to decrypt
         the submitted archive.
        :type archive_password: Optional[str]
        :param arguments: Command line arguments to run the submitted file.
         Only available for Portable Executable (PE) files and script files.
        :type arguments: Optional[str]
        :rtype: Result[SubmitFileToSandboxResp]:
        """
        return self._core.send(
            SubmitFileToSandboxResp,
            Api.SUBMIT_FILE_TO_SANDBOX,
            HttpMethod.POST,
            data=utils.build_sandbox_file_request(
                document_password, archive_password, arguments
            ),
            files={"file": (file_name, file, "application/octet-stream")},
        )

    def submit_urls_to_sandbox(self, *urls: str) -> MultiResult[MultiUrlResp]:
        """Submits URLs to the sandbox for analysis.

        :param urls: URL(s) to be submitted.
        :type urls: Tuple[str, ...]
        :rtype: MultiResult[MultiUrlResp]
        """
        return self._core.send_multi(
            MultiUrlResp,
            Api.SUBMIT_URLS_TO_SANDBOX,
            json=[{"url": url} for url in urls],
        )

    def terminate_process(
        self, *processes: ProcessTask
    ) -> MultiResult[MultiResp]:
        """Terminates a process that is running on one or more endpoints.

        :param processes: Process(es) to terminate.
        :type processes: Tuple[ProcessTask, ...]
        :rtype: MultiResult[MultiResp]
        """
        return self._core.send_endpoint(
            Api.TERMINATE_ENDPOINT_PROCESS, *processes
        )

    def check_connectivity(self) -> Result[ConnectivityResp]:
        """Checks the connection to the API service
        and verifies if your authentication token is valid.

        :rtype: Result[ConnectivityResp]
        """
        return self._core.send(ConnectivityResp, Api.CONNECTIVITY)
