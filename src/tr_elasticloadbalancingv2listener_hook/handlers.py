import logging
from typing import Any, MutableMapping, Optional

from cloudformation_cli_python_lib import (
    BaseHookHandlerRequest,
    HandlerErrorCode,
    Hook,
    HookInvocationPoint,
    OperationStatus,
    ProgressEvent,
    SessionProxy,
    exceptions,
)

from .models import HookHandlerRequest, TypeConfigurationModel

# Use this logger to forward log messages to CloudWatch Logs.
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)
TYPE_NAME = "TR::elasticloadbalancingv2listener::Hook"

hook = Hook(TYPE_NAME, TypeConfigurationModel)
test_entrypoint = hook.test_entrypoint

def _validate_weak_ciphers(progress, target_name, resource_properties, secureSSLPolicies, insecureSSLPolicies):

    LOG.info("Starting Validation")
    try:
        if resource_properties.get("SslPolicy") not in secureSSLPolicies:
            progress.status = OperationStatus.FAILED
            progress.message = f"Failed Hook due to insecure policy on {target_name} resource."
            LOG.debug("Validation Failed. Listener policy has weak Ciphers!")
        else:
            progress.status = OperationStatus.SUCCESS
            progress.message = f"Successfully invoked HookHandler for target {target_name}. Resource has secure policy attached"
            LOG.debug("Validation Successful!")

    except TypeError as e:
        # catch all exception and mark Hook status as failure
        progress.status = OperationStatus.FAILED
        progress.message = f"was not expecting type {e}."

    LOG.info(f"Results Message: {progress.message}")

    return progress

@hook.handler(HookInvocationPoint.CREATE_PRE_PROVISION)
def pre_create_handler(
        session: Optional[SessionProxy],
        request: HookHandlerRequest,
        callback_context: MutableMapping[str, Any],
        type_configuration: TypeConfigurationModel
) -> ProgressEvent:
    target_model = request.hookContext.targetModel
    target_name = request.hookContext.targetName
    progress: ProgressEvent = ProgressEvent(
        status=OperationStatus.IN_PROGRESS
    )
    # TODO: put code here
    LOG.info("Starting Execution of pre_create_handler")
    

    # Example:
    try:
        # Reading the Resource Hook's target properties
        resource_properties = target_model.get("resourceProperties")
        if 'HTTPS' == resource_properties.get("Protocol") or 'TLS' == resource_properties.get("Protocol"):
            return _validate_weak_ciphers(progress, target_name, resource_properties, type_configuration.secureSSLPolicies, type_configuration.insecureSSLPolicies)
        else:
            LOG.info("Listener protocol is not HTTPS/TLS")
            progress.status = OperationStatus.SUCCESS
        LOG.info("resource_properties: "+str(resource_properties))
    except TypeError as e:
        # exceptions module lets CloudFormation know the type of failure that occurred
        raise exceptions.InternalFailure(f"was not expecting type {e}")
        # this can also be done by returning a failed progress event
        # return ProgressEvent.failed(HandlerErrorCode.InternalFailure, f"was not expecting type {e}")

    return progress


@hook.handler(HookInvocationPoint.UPDATE_PRE_PROVISION)
def pre_update_handler(
        session: Optional[SessionProxy],
        request: BaseHookHandlerRequest,
        callback_context: MutableMapping[str, Any],
        type_configuration: TypeConfigurationModel
) -> ProgressEvent:
    target_model = request.hookContext.targetModel
    target_name = request.hookContext.targetName
    progress: ProgressEvent = ProgressEvent(
        status=OperationStatus.IN_PROGRESS
    )
    # TODO: put code here
    LOG.info("Starting Execution of pre_update_handler")

    # Example:
    try:
        # A Hook that does not allow a resource's encryption algorithm to be modified
        # Reading the Resource Hook's target current properties and previous properties
        resource_properties = target_model.get("resourceProperties")
        previous_properties = target_model.get("previousResourceProperties")

        if ('HTTPS' == previous_properties.get("Protocol") and 'HTTPS' != resource_properties.get("Protocol")) or ('TLS' == previous_properties.get("Protocol") and 'TLS' != resource_properties.get("Protocol")):
            progress.status = OperationStatus.FAILED
            progress.message = f"Failed Hook on {target_name} resource. Listener TLS/HTTPS Protocol cannot be modified to insecure."
            progress.errorCode = HandlerErrorCode.NonCompliant
        elif 'HTTPS' == resource_properties.get("Protocol") or 'TLS' == resource_properties.get("Protocol"):
            return _validate_weak_ciphers(progress, target_name, resource_properties, type_configuration.secureSSLPolicies, type_configuration.insecureSSLPolicies)
        else:
            LOG.info("Listener protocol is not HTTPS/TLS")
            progress.status = OperationStatus.SUCCESS
    except TypeError as e:
        progress = ProgressEvent.failed(HandlerErrorCode.InternalFailure, f"was not expecting type {e}")
    return progress


@hook.handler(HookInvocationPoint.DELETE_PRE_PROVISION)
def pre_delete_handler(
        session: Optional[SessionProxy],
        request: BaseHookHandlerRequest,
        callback_context: MutableMapping[str, Any],
        type_configuration: TypeConfigurationModel
) -> ProgressEvent:
    # TODO: put code here
    LOG.info("Starting Execution of pre_delete_handler")
    return ProgressEvent(
        status=OperationStatus.SUCCESS
    )
