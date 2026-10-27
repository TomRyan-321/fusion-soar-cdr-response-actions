#!/usr/bin/env python3
"""Generate workflows/*.yaml from scripts/workflow/*.py and the action table below.

Edit this file (or the two Python step scripts), run it, then deploy. The main workflow triages
the detection and opens the case; it hands the chosen action to one of four on-demand child
workflows (IAM, EC2, data stores, logging and detection), which run it and comment on the case. Every response action
gets one condition, one AWS step and one case comment in its child workflow.

It also writes workflows/self-contained/cdr-triage-and-respond.yaml: the same workflow with every
response action inline, for tenants that want one workflow. Deploy one version or the other.

Usage: scripts/build-workflow.py
"""
import os
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "workflows")
V = "${WorkflowCustomVariable.%s}"
I = "${data['%s']}"  # a child workflow's input
ACCOUNT = I % "account_id"
# Group: (child workflow name, node key in the main workflow, file name, what it covers).
GROUPS = {"IAM": ("CDR respond - IAM", "RespondIAM", "cdr-respond-iam", "IAM"),
          "EC2": ("CDR respond - EC2", "RespondEC2", "cdr-respond-ec2", "EC2"),
          "DATA": ("CDR respond - data stores", "RespondData", "cdr-respond-data", "S3, Lambda, EFS, RDS or SNS"),
          "CONTROLS": ("CDR respond - logging and detection", "RespondControls", "cdr-respond-controls", "CloudTrail or GuardDuty")}
GROUP_OF = {"IAM": "IAM", "EC2": "EC2", "S3": "DATA", "LAMBDA": "DATA", "EFS": "DATA", "RDS": "DATA", "SNS": "DATA",
            "CLOUDTRAIL": "CONTROLS", "GUARDDUTY": "CONTROLS"}
# The default SNS topic policy: only the owning account. Replaces a public one.
SNS_POLICY = ('{"Version":"2008-10-17","Id":"__default_policy_ID","Statement":[{"Sid":"__default_statement_ID","Effect":"Allow",'
              '"Principal":{"AWS":"*"},"Action":["SNS:GetTopicAttributes","SNS:SetTopicAttributes","SNS:AddPermission",'
              '"SNS:RemovePermission","SNS:DeleteTopic","SNS:Subscribe","SNS:ListSubscriptionsByTopic","SNS:Publish"],'
              '"Resource":"${data[\'target\']}","Condition":{"StringEquals":{"AWS:SourceOwner":"${data[\'account_id\']}"}}}]}')

# action: (node key, Fusion action id, config placeholder, properties, result to quote in the case comment)
ACTIONS = {
    "iam-disable-access-key": ("DisableAccessKey", "eeb9436ccc5c4023bfb8088877370ae3_b0aafd30f462b2f49cad6efa3ba53bbe", "IAM",
        {"account_id": ACCOUNT, "region": "us-east-1", "user_name": I % "target", "access_key_id": I % "detail", "status": "Inactive"}, "message"),
    "iam-apply-deny-policy-user": ("DenyUser", "eeb9436ccc5c4023bfb8088877370ae3_2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e", "IAM",
        {"account_id": ACCOUNT, "region": "us-east-1", "user_name_or_arn": I % "target", "policy_name": "arn:aws:iam::aws:policy/AWSDenyAll"}, "message"),
    "iam-role-apply-deny-policy": ("DenyRole", "eeb9436ccc5c4023bfb8088877370ae3_3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f", "IAM",
        {"account_id": ACCOUNT, "region": "us-east-1", "role_name_or_arn": I % "target", "policy_name_or_arn": "arn:aws:iam::aws:policy/AWSDenyAll"}, "message"),
    "iam-detach-user-policy": ("DetachUserPolicy", "675b021ab2964b2fa6b00c854beaa1b1", "IAM",
        {"params.query.UserName": I % "target", "params.query.PolicyArn": I % "detail"}, None),
    "iam-detach-role-policy": ("DetachRolePolicy", "309d3be02c6b40088f84fc72dff870ce", "IAM",
        {"params.query.RoleName": I % "target", "params.query.PolicyArn": I % "detail"}, None),
    "iam-detach-group-policy": ("DetachGroupPolicy", "976c0eccc2214a5a906c8202845c6188", "IAM",
        {"params.query.GroupName": I % "target", "params.query.PolicyArn": I % "detail"}, None),
    "iam-delete-user-policy": ("DeleteUserPolicy", "6515b9e0e78f426f8b11e1c3fd798ac2", "IAM",
        {"params.query.UserName": I % "target", "params.query.PolicyName": I % "detail"}, None),
    "iam-delete-role-policy": ("DeleteRolePolicy", "a2a1ef8756694189bd5591a29718eea3", "IAM",
        {"params.query.RoleName": I % "target", "params.query.PolicyName": I % "detail"}, None),
    "iam-delete-group-policy": ("DeleteGroupPolicy", "f176714733eb4f66b6802310ff918ebd", "IAM",
        {"params.query.GroupName": I % "target", "params.query.PolicyName": I % "detail"}, None),
    "iam-delete-login-profile": ("DeleteLoginProfile", "4f4f4074009140ab977f37069b7d298a", "IAM",
        {"params.query.UserName": I % "target"}, None),
    "sg-revoke-ingress": ("RevokeIngress", "c77fa1c6a29f47b3ad7bc282d6ea0fd6_f95438be914a49fba3aa12f6ff9c27da", "EC2",
        {"account_id": ACCOUNT, "region": I % "region", "security_group_id": I % "target", "ports": [I % "port"]}, "removed_rules"),
    "remove-public-snapshot": ("SnapshotPrivate", "c77fa1c6a29f47b3ad7bc282d6ea0fd6_fe8d16164b8741689f672b8970243e0c", "EC2",
        {"account_id": ACCOUNT, "region": I % "region", "snapshot_id": I % "target"}, "message"),
    "ami-make-private": ("AmiPrivate", "c77fa1c6a29f47b3ad7bc282d6ea0fd6_b0944cbf8d4148debd7fdb7416d7b85f", "EC2",
        {"account_id": ACCOUNT, "region": I % "region", "image_id": I % "target", "attribute": "launchPermission",
         "operation_type": "remove", "user_groups": ["all"]}, "return"),
    "s3-block-public-access": ("S3BlockPublicAccess", "16342d87a8814cb99bbff645223debf2_7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b", "S3",
        {"account_id": ACCOUNT, "region": I % "region", "bucket_name": I % "target", "block_public_acls": True,
         "ignore_public_acls": True, "block_public_policy": True, "restrict_public_buckets": True}, "message"),
    "lambda-disable": ("LambdaDisable", "39ce6588340c4a088456435818f09964~89fcc1c3f947e500697807b4ac98759a", "LAMBDA",
        {"params.path.account_id": ACCOUNT, "params.path.region": I % "region", "params.path.FunctionName": I % "target",
         "json.ReservedConcurrentExecutions": 0}, "status_code"),
    "efs-remove-public-access": ("EfsRemovePublicAccess", "e9116778cd844626a69f79878832a7f0_e289fbe37ee448ceb206253257eb3c63", "EFS",
        {"account_id": ACCOUNT, "region": I % "region", "file_system_id": I % "target"}, "policy_modified"),
    "rds-snapshot-private": ("RdsSnapshotPrivate", "05a8390613994d3bbf228b1ab4188bce_af149b3f9b204da485d71948b2c73455", "RDS",
        {"account_id": ACCOUNT, "region": I % "region", "db_snapshot_identifier": I % "target", "attribute_name": "restore",
         "values_to_remove": ["all"]}, None),
    "sns-reset-topic-policy": ("SnsResetTopicPolicy", "608d0bc8e44048e4a8c17c3f4a636fcc", "SNS",
        {"params.path.account_id": ACCOUNT, "params.path.region": I % "region", "params.query.TopicArn": I % "target",
         "params.query.AttributeName": "Policy", "params.query.AttributeValue": SNS_POLICY, "params.query.Version": "2010-03-31"}, None),
    # No account or region input: they act in their config's account and region (see BOUND in route.py).
    "cloudtrail-start-logging": ("CloudTrailStartLogging", "50e74f864c43403095deb7bbf4b945ab_a9529ebba5a041debcd38f73c4dc8d85",
        "CLOUDTRAIL", {"Name": I % "target"}, None),
    "guardduty-enable-detector": ("GuardDutyEnableDetector", "304b89c6ae6742b5a8809fdaaa929617", "GUARDDUTY",
        {"params.path.detectorId": I % "target", "json.enable": True}, None),
    "guardduty-delete-ipset": ("GuardDutyDeleteIpSet", "45378d57139046a9afc6a99c4a12e92b", "GUARDDUTY",
        {"params.path.detectorId": I % "target", "params.path.ipSetId": I % "detail"}, None),
}

PROMPT = """Pick ONE response for this CrowdStrike cloud detection in AWS. An analyst approves it before it runs.
iam-disable-access-key [user owning the abused access key; also give access_key_id]
iam-apply-deny-policy-user [IAM user acting maliciously]
iam-role-apply-deny-policy [IAM role acting maliciously or being abused]
monitor-only [low risk, or nothing to contain]
escalate-human [unclear target, or needs investigation first]
Copy the target exactly from the event.

Detection: ${Trigger.Detection.Name}
Event: ${WorkflowCustomVariable.Event}

Reply with only JSON: {"action":"","target":"","access_key_id":"","confidence":"high|medium|low","why":"<=15 words"}"""

SEVERITY = ("${{'Critical': '90', 'High': '70', 'Medium': '50', 'Low': '30', 'Informational': '10'}"
            "[data['Trigger.Detection.SeverityDisplayName']]}")
MODE = "${data['WorkflowCustomVariable.AutoRun'] == 'yes' ? 'Ran automatically' : 'Approved by an analyst'}"


def script(name):
    return open(os.path.join(HERE, "workflow", name)).read()


def split(node, i, cast=""):
    expr = f"data['{node}.output_stdout'].split('#EVENT#')[0].split('|')[{i}]" if node == "Route" else \
        f"data['{node}.output_stdout'].split('|')[{i}]"
    return f"${{{cast}({expr})}}" if cast else f"${{{expr}}}"


def update(name, values, nxt):
    return {"id": "6c6eab39063fa3b72d98c82af60deb8a", "class": "UpdateVariable", "name": name, "version_constraint": "~1",
            "next": nxt, "properties": {"WorkflowCustomVariable": values}}


def python(name, body, nxt):
    return {"id": "7fb9eb10b23943efaf1e6082b0ac0338", "name": name, "version_constraint": "~1", "next": nxt,
            "properties": {"runtime": "py0313general", "script": body}}


def comment(text, case="${data['CreateCase.id']}"):
    return {"id": "a16f4fdd1b244b0bfeecd47e25dbe0e0", "name": "Add Comment to Case", "version_constraint": "~1",
            "properties": {"case_id": case, "comment": text}}


group_conditions = [f"is_{g.lower()}_response" for g in GROUPS]
actions = {
    "CreateVariable": {"id": "702d15788dbbffdf0b68d8e2f3599aa4", "class": "CreateVariable", "name": "Create variable",
                       "version_constraint": "~1", "next": ["Route"], "properties": {"variable_schema": {"type": "object", "properties": {
                           **{k: {"type": "string"} for k in ("Route", "Action", "Target", "Detail", "Region", "AutoRun", "Check",
                                                              "Event", "Confidence", "Why")},
                           "Port": {"type": "integer"}}}}},
    "Route": python("Route detection", script("route.py"), ["SetRoute"]),
    "SetRoute": update("Set route", {"Route": split("Route", 0), "Action": split("Route", 1), "Target": split("Route", 2),
                                     "Detail": split("Route", 3), "Port": split("Route", 4, "int"), "Region": split("Route", 5),
                                     "AutoRun": split("Route", 6), "Check": split("Route", 7), "Confidence": "high",
                                     "Why": "Fixed response for this API call",
                                     "Event": "${data['Route.output_stdout'].split('#EVENT#')[1]}"},
                       ["is_table", "is_llm"]),
    "RecommendAction": {"id": "bdfecafafdb44919a458fcf51d6b93a7_98dec86072334d24b37dd798098cfd63", "name": "Charlotte AI - LLM Completion",
                        "version_constraint": "~0", "next": ["ParseRecommendation"],
                        "properties": {"model_name": "Claude Latest", "temperature": 0, "user_prompt": PROMPT}},
    "ParseRecommendation": python("Parse and check recommendation", script("parse_llm.py"), ["SetRecommendation"]),
    "SetRecommendation": update("Set recommendation", {"Action": split("ParseRecommendation", 0), "Target": split("ParseRecommendation", 1),
                                                       "Detail": split("ParseRecommendation", 2), "Confidence": split("ParseRecommendation", 3),
                                                       "Why": split("ParseRecommendation", 4), "Check": split("ParseRecommendation", 5),
                                                       "AutoRun": "no"}, ["CreateCase"]),
    "CreateCase": {"id": "4918bf9d85ecc06388eca16543bdbbdc", "name": "Create a new Case", "version_constraint": "~1",
                   "next": ["is_auto", "is_needs_approval"],
                   "properties": {"name": "CDR ${Trigger.Detection.Name}: ${WorkflowCustomVariable.Action} ${WorkflowCustomVariable.Target}",
                                  "severity": SEVERITY, "status": "new", "detections": ["${Trigger.Detection.DetectionID}"], "tags": ["cdr-soar"],
                                  "description": (
                                      "## Response\n\n"
                                      "**Action:** ${WorkflowCustomVariable.Action}\n\n"
                                      "**Target:** ${WorkflowCustomVariable.Target} ${WorkflowCustomVariable.Detail}\n\n"
                                      "**Decided by:** ${WorkflowCustomVariable.Route} (confidence ${WorkflowCustomVariable.Confidence}). "
                                      "${WorkflowCustomVariable.Why}\n\n"
                                      "**Check:** ${WorkflowCustomVariable.Check}\n\n"
                                      "**Runs:** ${data['WorkflowCustomVariable.AutoRun'] == 'yes' ? 'automatically' : 'after approval by __APPROVER_EMAIL__ (containment actions only)'}\n\n"
                                      "Account ${Trigger.Detection.FCS.CloudAccountId}, region ${WorkflowCustomVariable.Region}.\n\n"
                                      "## Event\n\n```json\n${WorkflowCustomVariable.Event}\n```")}},
    "RequestApproval": {"id": "d6731c10b24834e2e0f4bd9d390a29c8", "name": "Request human input - Send email", "version_constraint": "~1",
                        "next": ["is_approved", "is_declined"],
                        "properties": {"to": ["__APPROVER_EMAIL__"], "responders": ["__APPROVER_EMAIL__"], "user_input_timeout": "24h",
                                       "allowed_responses": ["Approve", "Decline"], "msg_type": "text",
                                       "subject": "Approve CDR response: ${WorkflowCustomVariable.Action} on ${WorkflowCustomVariable.Target}",
                                       "msg": ("Falcon Cloud Security detected \"${Trigger.Detection.Name}\" in AWS account "
                                               "${Trigger.Detection.FCS.CloudAccountId}.\n\n"
                                               "Action: ${WorkflowCustomVariable.Action}\nTarget: ${WorkflowCustomVariable.Target} "
                                               "${WorkflowCustomVariable.Detail}\nRegion: ${WorkflowCustomVariable.Region}\n"
                                               "Decided by: ${WorkflowCustomVariable.Route} (${WorkflowCustomVariable.Confidence}). "
                                               "${WorkflowCustomVariable.Why}\nCheck: ${WorkflowCustomVariable.Check}\n\n"
                                               "Approve to run it now. Details are on case ${data['CreateCase.id']}.")}},
    "CommentNotApproved": comment("Recommended ${WorkflowCustomVariable.Action} was not run: declined by "
                                  "${data['RequestApproval.result.responder']}. ${data['RequestApproval.result.note']}"),
}
conditions = {
    "is_aws_cloud_ioa": {"next": ["CreateVariable"], "expression": "Trigger.Detection.FCS.DetectType:'cloud-ioa'+Trigger.Detection.FCS.ServiceProvider:'aws'",
                         "display": ["AWS cloud IOA detection"]},
    "is_table": {"next": ["CreateCase"], "expression": "WorkflowCustomVariable.Route:'table'", "display": ["Fixed response for this API call"]},
    "is_llm": {"next": ["RecommendAction"], "expression": "WorkflowCustomVariable.Route:'llm'", "display": ["Needs a judgment call"]},
    "is_auto": {"next": group_conditions, "expression": "WorkflowCustomVariable.AutoRun:'yes'", "display": ["Safe to run automatically"]},
    "is_needs_approval": {"next": ["RequestApproval"],
                          "expression": "WorkflowCustomVariable.AutoRun:'no'+WorkflowCustomVariable.Action:!'monitor-only'+WorkflowCustomVariable.Action:!'escalate-human'",
                          "display": ["Containment action that needs approval"]},
    "is_approved": {"next": group_conditions, "expression": "RequestApproval.result.user_response:'Approve'", "display": ["Approved"]},
    "is_declined": {"next": ["CommentNotApproved"], "expression": "RequestApproval.result.user_response:'Decline'", "display": ["Declined"]},
}
def nest(props):
    """Fusion wants params.query.UserName as nested objects, not a dotted key."""
    out = {}
    for path, value in props.items():
        *parents, leaf = path.split(".")
        node = out
        for part in parents:
            node = node.setdefault(part, {})
        node[leaf] = value
    return out


CHILD_INPUTS = {"action": "string", "target": "string", "detail": "string", "region": "string", "port": "integer",
                "account_id": "string", "case_id": "string", "mode": "string"}
# The same inputs inside the main workflow, for the self-contained version.
INLINE = {"action": V % "Action", "target": V % "Target", "detail": V % "Detail", "region": V % "Region", "port": V % "Port",
          "account_id": "${Trigger.Detection.FCS.CloudAccountId}", "case_id": "${data['CreateCase.id']}", "mode": MODE}


def inline(value):
    """Swap child-workflow inputs for the main workflow's own variables."""
    if isinstance(value, dict):
        return {k: inline(v) for k, v in value.items()}
    if isinstance(value, list):
        return [inline(v) for v in value]
    if isinstance(value, str):
        for name, expr in INLINE.items():
            value = value.replace(I % name, expr)
    return value


def response_nodes(members, field):
    """One condition (on `field`), AWS step and case comment per action."""
    nodes, conds = {}, {}
    for action in members:
        key, aid, config, props, result = ACTIONS[action]
        nodes[key] = {"id": aid, "name": key, "next": [f"Comment{key}"],
                      "properties": {"config_id": f"__{config}_CONFIG_ID__", **nest(props)}}
        detail = f": ${{data['{key}.{result}']}}" if result else ""
        nodes[f"Comment{key}"] = comment(f"${{data['mode']}}: {action} on ${{data['target']}} ${{data['detail']}}{detail}",
                                         case="${data['case_id']}")
        conds[f"is_{action.replace('-', '_')}"] = {"next": [key], "expression": f"{field}:'{action}'", "display": [action]}
    return nodes, conds


DESCRIPTION = ("On an AWS Falcon Cloud Security (CDR) cloud IOA detection, pick a response: a fixed response for API calls "
               "with one obvious fix (target read straight from the CloudTrail event), otherwise a Charlotte AI LLM judgment "
               "whose target must appear in the event. Open a case. Exact undos of exposure and policy changes run "
               "automatically; other containment runs after email approval. Results are commented on the case.")
TRIGGER = {"next": ["is_aws_cloud_ioa"], "event": "Investigatable", "name": "Detection > FCS Detection", "type": "Signal",
           "version_constraint": "~1"}

# Self-contained: every response action inline in the one workflow.
nodes, conds = response_nodes(ACTIONS, "WorkflowCustomVariable.Action")
self_contained = {"name": "CDR triage and respond", "description": DESCRIPTION, "trigger": TRIGGER,
                  "actions": {**actions, **inline(nodes)},
                  "conditions": {**conditions, **conds,
                                 "is_auto": {**conditions["is_auto"], "next": list(conds)},
                                 "is_approved": {**conditions["is_approved"], "next": list(conds)}}}

# Split (default): the main workflow calls one child workflow per group.
children = {}
for group, (child_name, node, file, covers) in GROUPS.items():
    members = [a for a, spec in ACTIONS.items() if GROUP_OF[spec[2]] == group]
    child_actions, child_conditions = response_nodes(members, "action")
    children[file] = {
        "name": child_name,
        "description": (f"Called by 'CDR triage and respond'. Runs one {covers} "
                        "response action in the detection's AWS account and comments the result on the case."),
        "trigger": {"name": "On demand", "type": "On demand", "next": list(child_conditions),
                    "parameters": {"type": "object", "properties": {k: {"type": t} for k, t in CHILD_INPUTS.items()},
                                   "required": ["action", "target", "account_id", "case_id"]}},
        "actions": child_actions,
        "conditions": child_conditions,
    }
    # Main workflow: hand the action to this child. Deploy fills in the child's definition ID.
    actions[node] = {"id": f"__WORKFLOW_{file}__", "name": child_name, "properties": dict(INLINE)}
    values = ", ".join(f"'{a}'" for a in members)
    conditions[f"is_{group.lower()}_response"] = {"next": [node], "expression": f"WorkflowCustomVariable.Action:[{values}]",
                                                  "display": [f"{child_name.removeprefix('CDR respond - ')} action"]}

workflow = {"name": "CDR triage and respond", "description": DESCRIPTION, "trigger": TRIGGER, "actions": actions, "conditions": conditions}


class Literal(str):
    pass


yaml.add_representer(Literal, lambda d, s: d.represent_scalar("tag:yaml.org,2002:str", s, style="|"))
for node in actions.values():
    if "script" in node["properties"]:
        node["properties"]["script"] = Literal(node["properties"]["script"])
os.makedirs(os.path.join(OUT, "self-contained"), exist_ok=True)
for file, definition in {"cdr-triage-and-respond": workflow, **children,
                         "self-contained/cdr-triage-and-respond": self_contained}.items():
    path = os.path.join(OUT, f"{file}.yaml")
    with open(path, "w") as f:
        f.write("# Generated by scripts/build-workflow.py. Edit that, not this file.\n")
        yaml.dump(definition, f, sort_keys=False, width=120, allow_unicode=True)
    print(f"wrote {os.path.relpath(path)}: {len(definition['actions'])} actions, {len(definition.get('conditions', {}))} conditions")
