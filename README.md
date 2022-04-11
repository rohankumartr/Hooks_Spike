# TR::elasticloadbalancingv2listener::Hook

This AWS CloudFormation Hook validates the Listener security policies of load balancer. If an unsecure policy is attached to the listener, the hook will cause stack failure. List of secure policies are put in the Hook configuration as below.

{
  "CloudFormationConfiguration": {
    "HookConfiguration": {
      "TargetStacks": "ALL",
      "FailureMode": "FAIL",
      "Properties": {
        "secureSSLPolicies": [
          "ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
          "ELBSecurityPolicy-TLS-1-2-2017-01",
          "ELBSecurityPolicy-FS-1-2-Res-2019-08",
          "ELBSecurityPolicy-FS-1-2-Res-2020-10",
          "ELBSecurityPolicy-FS-1-2-2019-08"
        ],
		"insecureSSLPolicies": ["ELBSecurityPolicy-TLS-1-0-2015-04"]
      }
    }
  }
}

Below is snippet from CloudFormation template resource section that will trigger the hook. This happens as "AWS::ElasticLoadBalancingV2::Listener" is defined as target in the  schema in file tr-elasticloadbalancingv2listener-hook.json

  listener1:
    Properties:
      LoadBalancerArn: !Ref TestHookNLB
      Port: 22
      Protocol: TCP
      DefaultActions:
        - TargetGroupArn: !Ref TestNLBTargetGroup
          Type: forward
    Type: 'AWS::ElasticLoadBalancingV2::Listener'
  listener2:
    Properties:
      LoadBalancerArn: !Ref TestHookNLB
      Port: 443
      Protocol: TLS
      Certificates: 
        - CertificateArn: arn:aws:acm:us-east-1:168321507030:certificate/0c5b1160-f095-4760-89d9-035e79c84f84
      SslPolicy: ELBSecurityPolicy-TLS-1-0-2015-04
      DefaultActions:
        - TargetGroupArn: !Ref TestNLBTargetGroup
          Type: forward
    Type: 'AWS::ElasticLoadBalancingV2::Listener'

Hook executes with the role created (Validate once)

Registration of the hook needed following privileges to be added to poweruser2 role 

IAM CreateRole privilege
IAM UpdateRole privilege
IAM PutRolePolicy privilege
IAM CreatePolicy privilege
S3 PutObject privilege
S3 CreateBucket privilege
Cloudformation RegisterType
Cloudformation SetTypeDefaultVersion
Cloudformation DeregisterType

```python
ProgressEvent(
    # Required
    # Must be one of OperationStatus.IN_PROGRESS, OperationStatus.FAILED, OperationStatus.SUCCESS
    status=OperationStatus.IN_PROGRESS,
    # Required on SUCCESS (except for LIST where resourceModels is required)
    # The current resource model after the operation; instance of ResourceModel class
    resourceModel=model,
    resourceModels=None,
    # Required on FAILED
    # Customer-facing message, displayed in e.g. CloudFormation stack events
    message="",
    # Required on FAILED: a HandlerErrorCode
    errorCode=HandlerErrorCode.InternalFailure,
    # Optional
    # Use to store any state between re-invocation via IN_PROGRESS
    callbackContext={},
    # Required on IN_PROGRESS
    # The number of seconds to delay before re-invocation
    callbackDelaySeconds=0,
)
```

Failures can be passed back to CloudFormation by either raising an exception from `cloudformation_cli_python_lib.exceptions`, or setting the ProgressEvent's `status` to `OperationStatus.FAILED` and `errorCode` to one of `cloudformation_cli_python_lib.HandlerErrorCode`. There is a static helper function, `ProgressEvent.failed`, for this common case.

## What's with the type hints?

We hope they'll be useful for getting started quicker with an IDE that support type hints. Type hints are optional - if your code doesn't use them, it will still work.
