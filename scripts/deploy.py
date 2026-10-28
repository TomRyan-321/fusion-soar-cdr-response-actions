#!/usr/bin/env python3
"""Import the CDR workflows into a Falcon tenant and enable them.

By default deploys the split version: the child workflows (workflows/cdr-respond-*.yaml) are
imported first, and their definition IDs are filled in to the main workflow, which calls them.
--self-contained deploys workflows/self-contained/cdr-triage-and-respond.yaml instead: one
workflow with every response action inline. Both are named "CDR triage and respond"; deploy
only one, or every detection gets two responses.

Looks up the tenant's AWS IAM, EC2, S3, Lambda, EFS, RDS, SNS, CloudTrail and GuardDuty
Store app configurations, fills in a lookup from account ID to config ID and the approver's
email, then imports and enables each workflow. A config with Account ID {account_id} covers
any account without its own config. That doesn't work for the generic AWS IAM actions or for
CloudTrail and GuardDuty, so it also tells the check step which accounts (IAM) and
account:region pairs (CloudTrail, GuardDuty) have their own config; elsewhere those responses
fall back to a deny or an escalation. Detections from an account with no matching config fail
at the response action.

Needs FALCON_CLIENT_ID, FALCON_CLIENT_SECRET and FALCON_BASE_URL (defaults to
auto), with the scopes Workflow: Read/Write and API integrations: Read, and
APPROVER_EMAIL: the Falcon user who approves response actions.

Usage: scripts/deploy.py [--self-contained] [--replace]
       --replace deletes the deployed copies of either version first
"""
import collections
import glob
import json
import os
import sys

from falconpy import APIIntegrations, Workflows

# CrowdStrike Store app IDs. These are not the prefixes of the apps' action IDs.
APPS = {"__IAM_CONFIG_ID__": ("AWS IAM", "fecfb32861a14223ad131dd34210573a"),
        "__EC2_CONFIG_ID__": ("AWS EC2", "57a142f536e64990bf4a85c491f9631c"),
        "__S3_CONFIG_ID__": ("AWS S3", "16342d87a8814cb99bbff645223debf2"),
        "__LAMBDA_CONFIG_ID__": ("AWS Lambda", "39ce6588340c4a088456435818f09964"),
        "__EFS_CONFIG_ID__": ("AWS EFS", "b428af1226624ed998f799d7581b9b45"),
        "__RDS_CONFIG_ID__": ("AWS RDS", "e202cee22b15454491675e6d49f4617d"),
        "__SNS_CONFIG_ID__": ("AWS SNS", "461a8aa0f1d140d9a4e17e25ae4fb2be"),
        "__CLOUDTRAIL_CONFIG_ID__": ("AWS CloudTrail", "b101a6a0b042414a938aef201c2798c1"),
        "__GUARDDUTY_CONFIG_ID__": ("AWS GuardDuty", "fd069ff8dc6c4ea6a6137243e5bac6f7")}
# Apps whose actions can't take the account (IAM) or the account and region (CloudTrail,
# GuardDuty) as input. parse_llm.py only uses them where a config of their own exists.
BOUND_APPS = {"IAM": "__IAM_CONFIG_ID__", "CLOUDTRAIL": "__CLOUDTRAIL_CONFIG_ID__", "GUARDDUTY": "__GUARDDUTY_CONFIG_ID__"}

# Children first: the main workflow needs their definition IDs.
SPLIT = sorted(glob.glob("workflows/cdr-respond-*.yaml")) + ["workflows/cdr-triage-and-respond.yaml"]
SELF_CONTAINED = "--self-contained" in sys.argv
paths = ["workflows/self-contained/cdr-triage-and-respond.yaml"] if SELF_CONTAINED else SPLIT
DELETE = dict(method="DELETE", route="/workflows/entities/definitions/v1")
auth = dict(client_id=os.environ["FALCON_CLIENT_ID"], client_secret=os.environ["FALCON_CLIENT_SECRET"],
            base_url=os.environ.get("FALCON_BASE_URL", "auto"))
plugins, workflows = APIIntegrations(**auth), Workflows(**auth)


def config_lookup(app_name, app_id):
    """CEL expression picking the app's config for the detection's AWS account.

    A config whose Account ID is {account_id} acts in whichever account the action
    names, so it covers every account that has the same role name and external ID.
    Per-account configs take precedence over it.
    """
    r = plugins.get_plugin_configs(limit=500)
    if r["status_code"] >= 300:
        sys.exit(f"Couldn't read Store app configurations: {r['body'].get('errors')}")
    by_account = {}
    for c in r["body"].get("resources") or []:
        if c["app_id"] == app_id:
            auth = c["config"].get("auth") or {}
            account = (auth.get("aws_0") or auth).get("account_id")
            by_account[account] = c["config_id"]
            region = ((c["config"].get("params") or {}).get("path") or {}).get("region")
            if account != "{account_id}":
                placed[app_id].append(account if region is None else f"{account}:{region}")
    if not by_account:
        sys.exit(f"No {app_name} app configuration found. Configure it in CrowdStrike Store first.")
    any_account = by_account.pop("{account_id}", None)
    print(f"{app_name}: " + ", ".join(sorted(by_account) + (["any account ({account_id})"] if any_account else [])))
    if not by_account:
        return any_account
    if len(by_account) == 1 and not any_account:
        # A single config serves every account. If it's later edited in place to
        # {account_id} it covers them all without a redeploy; until then, actions
        # for other accounts fail rather than act in the wrong one.
        return next(iter(by_account.values()))
    entries = ", ".join(f"'{account}': '{cid}'" for account, cid in sorted(by_account.items()))
    # Response actions read the account from the trigger, or from a child workflow's input.
    account = "data['Trigger.Detection.FCS.CloudAccountId']" if SELF_CONTAINED else "data['account_id']"
    if any_account:
        return f"\"${{{account} in {{{entries}}} ? {{{entries}}}[{account}] : '{any_account}'}}\""
    return f"\"${{{{{entries}}}[{account}]}}\""


def name_of(text):
    return next(line.split(":", 1)[1].strip() for line in text.splitlines() if line.startswith("name:"))


if "--replace" in sys.argv:
    deployed = {d["name"]: d["id"] for d in workflows.search_definitions(limit=500)["body"].get("resources") or []}
    for path in reversed(SPLIT):  # the main workflow first, so nothing calls a deleted child
        name = name_of(open(path).read())
        if name in deployed:
            r = workflows.override(**DELETE, parameters={"ids": deployed[name]})
            print(f"Deleted '{name}' ({deployed[name]})" if r["status_code"] < 300 else f"Couldn't delete '{name}': {r['body']}")

lookups, children = {}, {}
placed = collections.defaultdict(list)  # app ID -> accounts (or account:region) with their own config
for path in paths:
    text = open(path).read()
    text = text.replace("__APPROVER_EMAIL__", os.environ["APPROVER_EMAIL"])
    for placeholder, app in APPS.items():
        if placeholder in text:
            lookups[placeholder] = lookups.get(placeholder) or config_lookup(*app)
            text = text.replace(placeholder, lookups[placeholder])
    for file, wid in children.items():
        text = text.replace(f"__WORKFLOW_{file}__", wid)
    if "__BOUND_CONFIGS__" in text:
        bound = {}
        for app, placeholder in BOUND_APPS.items():
            lookups[placeholder] = lookups.get(placeholder) or config_lookup(*APPS[placeholder])
            # IAM actions have a region input; CloudTrail and GuardDuty use the config's region.
            bound[app] = [p.split(":")[0] if app == "IAM" else p for p in placed[APPS[placeholder][1]]]
        text = text.replace("__BOUND_CONFIGS__", json.dumps(bound, separators=(",", ":")))
    name = name_of(text)

    r = workflows.import_definition(data_file=text)
    if r["status_code"] >= 300 or r["body"].get("errors"):
        sys.exit(f"Importing {path} failed: {r['body'].get('errors')}. If it already exists, re-run with --replace.")
    wid = r["body"]["resources"][0]["id"]

    # Enable returns 200 even when validation fails, so check for errors too.
    r = workflows.workflow_definition_action(action_name="enable", ids=wid)
    if r["status_code"] >= 300 or r["body"].get("errors"):
        sys.exit(f"Imported '{name}' ({wid}) but enabling failed: {r['body'].get('errors')}")
    children[os.path.basename(path).removesuffix(".yaml")] = wid
    print(f"Imported and enabled '{name}' ({wid})")
