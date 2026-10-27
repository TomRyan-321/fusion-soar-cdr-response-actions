import json

AUTO = {"sg-revoke-ingress", "remove-public-snapshot", "ami-make-private", "iam-detach-user-policy",
        "iam-detach-role-policy", "iam-detach-group-policy", "s3-block-public-access",
        "efs-remove-public-access", "rds-snapshot-private", "cloudtrail-start-logging", "guardduty-enable-detector",
        "guardduty-delete-ipset"}
PUBLIC = ("0.0.0.0/0", "::/0")
# Some Store actions have no account input (generic AWS IAM), or neither account nor region
# (CloudTrail, GuardDuty): they act in their config's account and region, and an {account_id}
# config doesn't work for them. deploy.py fills in which accounts (IAM) or account:region pairs
# have their own config; anywhere else use the fallback instead.
BOUND = r'''__BOUND_CONFIGS__'''
BOUND = None if BOUND.startswith("__") else json.loads(BOUND)
ACCOUNT_BOUND = {"iam-detach-user-policy": ("IAM", "iam-apply-deny-policy-user"),
                 "iam-delete-user-policy": ("IAM", "iam-apply-deny-policy-user"),
                 "iam-delete-login-profile": ("IAM", "iam-apply-deny-policy-user"),
                 "iam-detach-role-policy": ("IAM", "iam-role-apply-deny-policy"),
                 "iam-delete-role-policy": ("IAM", "iam-role-apply-deny-policy"),
                 "iam-detach-group-policy": ("IAM", "escalate-human"), "iam-delete-group-policy": ("IAM", "escalate-human"),
                 "cloudtrail-start-logging": ("CLOUDTRAIL", "escalate-human"),
                 "guardduty-enable-detector": ("GUARDDUTY", "escalate-human"),
                 "guardduty-delete-ipset": ("GUARDDUTY", "escalate-human")}

e = json.loads(r'''${Trigger.Detection.FCS.RawEvent}''')
rp = e.get("requestParameters") or {}
re_ = e.get("responseElements") or {}
ui = e.get("userIdentity") or {}
caller = ui.get("arn") or ""
name = e.get("eventName") or ""
source = e.get("eventSource") or ""
# Lambda event names carry an API version: AddPermission20150331v2.
api = name.rstrip("0123456789v") if source == "lambda.amazonaws.com" else name
severity = "${Trigger.Detection.SeverityDisplayName}"
detection = "${Trigger.Detection.Name}"
account = "${Trigger.Detection.FCS.CloudAccountId}"


def items(x):
    return (x or {}).get("items") or []


def public_port():
    for perm in items(rp.get("ipPermissions")):
        cidrs = [r.get("cidrIp") for r in items(perm.get("ipRanges"))] + [r.get("cidrIpv6") for r in items(perm.get("ipv6Ranges"))]
        if any(c in PUBLIC for c in cidrs):
            return perm.get("fromPort") or 0
    return None


def added_all(attr):
    return any(i.get("group") == "all" for i in items((rp.get(attr) or {}).get("add")))


# Weakens a control but leaves nothing to undo or contain: record it, no LLM needed.
MONITOR = {"PutBucketVersioning", "PutBucketLogging", "DeleteBucketLogging", "DeleteFlowLogs",
           "StopConfigurationRecorder", "DeleteConfigurationRecorder", "UpdateTrail", "PutEventSelectors"}
# Exposes a resource or disables a control that no configured Store action can undo:
# a person undoes it in AWS. Value: the request parameter naming the resource.
NO_ACTION = {"DeleteTrail": "name", "DeleteDetector": "detectorId", "UpdateIPSet": "ipSetId", "SetRepositoryPolicy": "repositoryName",
             "PutResourcePolicy": "policyName", "PutIdentityPolicy": "identity",
             "PutApplicationPolicy": "applicationId", "AddLayerVersionPermission": "layerName",
             "PutAccountPublicAccessBlock": "accountId", "DeleteAccountPublicAccessBlock": "accountId",
             "DeleteAccountPasswordPolicy": "", "EnableSerialConsoleAccess": ""}
# Done with the caller's own credentials and never routine: deny the caller.
CONTAIN_CALLER = {"GetFederationToken", "LeaveOrganization", "TransferDomainToAnotherAwsAccount"}
# Rules on the caller's client, not the call (any API call can fire them; matched on the detection name).
# Attack OS or tooling: deny the caller after approval.
SUSPECT_CLIENT = ("hacking-related operating system", "Tool usage: ScoutSuite", "Tool usage: CloudBerry")
# Recon, informational by default: let the LLM judge whether to contain the caller.
JUDGE = ("Potential discovery of Admin accounts",)
# An admin role on an instance: often deliberate, and stopping the instance or removing the role
# could break a workload. Open a case instead of skipping it.
REVIEW = ("EC2 Instance Associated with Admin Role", "EC2 Instance Created with Admin Role")


def contain_caller():
    """Deny the IAM user or role that made the call. Never a shared SSO role."""
    if ui.get("type") == "IAMUser":
        return "iam-apply-deny-policy-user", ui.get("userName"), "", 0
    role = caller.split("/")[-2] if ui.get("type") == "AssumedRole" else ""
    if role.startswith("AWSReservedSSO_"):
        return "escalate-human", "-", f"{name} by shared SSO role {role}", 0
    if role:
        return "iam-role-apply-deny-policy", role, "", 0
    return None


def undo():
    """The exact undo of a successful API call, else None."""
    if name == "AuthorizeSecurityGroupIngress" and public_port() is not None:
        return "sg-revoke-ingress", rp.get("groupId"), "", public_port()
    if name == "ModifySnapshotAttribute" and added_all("createVolumePermission"):
        return "remove-public-snapshot", rp.get("snapshotId"), "", 0
    if name == "ModifyImageAttribute" and added_all("launchPermission"):
        return "ami-make-private", rp.get("imageId"), "", 0
    if name == "ModifyDBSnapshotAttribute" and "all" in (rp.get("valuesToAdd") or []):
        return "rds-snapshot-private", rp.get("dBSnapshotIdentifier"), "", 0
    if name in ("PutBucketAcl", "PutBucketPolicy", "DeleteBucketPublicAccessBlock"):
        return "s3-block-public-access", rp.get("bucketName"), "", 0
    if name == "PutFileSystemPolicy":
        return "efs-remove-public-access", rp.get("fileSystemId"), "", 0
    if api == "AddPermission" and source == "lambda.amazonaws.com" and rp.get("principal") == "*":
        return "lambda-disable", rp.get("functionName"), "", 0
    # SNS: put back the default owner-only topic policy (the old one is on the case).
    if (name == "SetTopicAttributes" and rp.get("attributeName") == "Policy") or (name == "AddPermission" and source == "sns.amazonaws.com"):
        return "sns-reset-topic-policy", rp.get("topicArn"), "", 0
    if name == "StopLogging":
        return "cloudtrail-start-logging", rp.get("name"), "", 0
    if name == "UpdateDetector" and rp.get("enable") is False:
        return "guardduty-enable-detector", rp.get("detectorId"), "", 0
    if name == "CreateIPSet":
        return "guardduty-delete-ipset", rp.get("detectorId"), re_.get("ipSetId"), 0
    for kind in ("User", "Role", "Group"):
        if name == f"Attach{kind}Policy":
            return f"iam-detach-{kind.lower()}-policy", rp.get(f"{kind.lower()}Name"), rp.get("policyArn"), 0
        if name == f"Put{kind}Policy":
            return f"iam-delete-{kind.lower()}-policy", rp.get(f"{kind.lower()}Name"), rp.get("policyName"), 0
    # A root user's own key can't be disabled through IAM (no userName in the request).
    if name == "CreateAccessKey" and (rp.get("userName") or ui.get("type") != "Root"):
        key = re_.get("accessKey") or {}
        return "iam-disable-access-key", key.get("userName"), key.get("accessKeyId"), 0
    if name in ("CreateLoginProfile", "UpdateLoginProfile"):
        return "iam-delete-login-profile", rp.get("userName"), "", 0
    if name == "UpdateAssumeRolePolicy":
        return "iam-role-apply-deny-policy", rp.get("roleName"), "", 0
    return None


def table():
    """(action, target, detail, port) for API calls with one obvious response, else None."""
    if name in MONITOR:
        return "monitor-only", "-", "", 0
    if api in NO_ACTION:
        return "escalate-human", "-", f"{name} {rp.get(NO_ACTION[api]) or ''}".strip(), 0
    if any(s in detection for s in SUSPECT_CLIENT):
        return contain_caller() or ("escalate-human", "-", f"{detection}: {name} by {ui.get('type')}", 0)
    if any(s in detection for s in REVIEW):
        return "monitor-only", "-", "", 0
    if name in CONTAIN_CALLER:
        return contain_caller()
    fixed = None if e.get("errorCode") else undo()  # a failed call left nothing to undo
    if fixed:
        return fixed
    if ui.get("type") == "Root":
        return "escalate-human", "-", f"{name} by the root user", 0
    # Instance credentials used for IAM or console activity: contain the instance role.
    session = caller.rsplit("/", 1)[-1]
    if ui.get("type") == "AssumedRole" and session.startswith("i-"):
        return "iam-role-apply-deny-policy", caller.split("/")[-2], "", 0
    return None


trimmed = {"eventName": name, "eventSource": e.get("eventSource"), "awsRegion": e.get("awsRegion"),
           "sourceIPAddress": e.get("sourceIPAddress"), "errorCode": e.get("errorCode"),
           "userIdentity": {k: ui.get(k) for k in ("type", "arn", "userName", "accessKeyId") if ui.get(k)},
           "requestParameters": rp or None, "responseElements": re_ or None}
event = json.dumps({k: v for k, v in trimmed.items() if v}, separators=(",", ":"))

fixed = table()
note = ""
region = e.get("awsRegion") or "us-east-1"
if fixed and fixed[0] in ACCOUNT_BOUND and BOUND is not None:
    app, fallback = ACCOUNT_BOUND[fixed[0]]
    where = account if app == "IAM" else f"{account}:{region}"
    if where not in BOUND.get(app, []):
        app_name = {"IAM": "AWS IAM", "CLOUDTRAIL": "AWS CloudTrail", "GUARDDUTY": "AWS GuardDuty"}[app]
        note = f"; {fixed[0]} needs an {app_name} config for {where.replace(':', ' ')}, so {fallback} instead"
        fixed = (fallback, fixed[1] if fallback != "escalate-human" else "-", "" if fallback != "escalate-human" else f"{name} {fixed[1]}", 0)
if "CrowdStrikeAutomatedResponse" in caller:
    route, fixed, check = "skip", None, "made by the CrowdStrike response role"
elif fixed and fixed[0] == "escalate-human":
    route, check = "table", f"a person needs to act on {name}" + (note or ": no safe response action")
elif fixed and fixed[1]:
    route, check = "table", f"target read from the {name} event{note}"
elif severity == "Informational" and not any(s in detection for s in JUDGE):
    route, check = "skip", "informational detection with no fixed response"
else:
    route, fixed, check = "llm", None, ""
action, target, detail, port = fixed or ("", "", "", 0)
auto = "yes" if route == "table" and action in AUTO else "no"
fields = [route, action, target or "", detail or "", port or 0, region, auto, check]
print("|".join(str(f).replace("|", "") for f in fields) + "#EVENT#" + event, end="")
