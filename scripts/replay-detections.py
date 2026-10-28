#!/usr/bin/env python3
"""Replay CDR detections through the workflow's decision steps, without acting.

Copies the routing and LLM steps of workflows/cdr-triage-and-respond.yaml into a
temporary on-demand workflow and runs it on the latest real detection for each
rule from the last day, plus any sample events you pass in. Prints what the
workflow would do and scores it, then deletes the temporary workflow. Use it to
test prompt or catalog changes in a couple of minutes instead of waiting for new
detections.

Sample events file: a JSON list of {"name", "severity", "raw_event", "expect"} objects,
where raw_event is a CloudTrail record (object or JSON string), name is the detection
name, and expect is a list of acceptable answers ({"action", and optionally "target",
"detail" and "port"}). An optional "description" is the detection's description. Real detections have no expect and aren't scored.

Account 123456789012 (the samples' account) is treated as having its own AWS IAM, CloudTrail
and GuardDuty configs in us-east-1; other accounts use the tenant's real configs.

Needs the same environment as deploy.py plus the Alerts: Read scope, and PyYAML.

Usage: scripts/replay-detections.py [--no-detections] [--days N] [--models "Claude Latest,GPT Latest"]
                                    [--repeat N] [samples.json]
"""
import argparse
import collections
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

import yaml
from falconpy import Alerts, APIIntegrations, Workflows

STEPS = ["CreateVariable", "Route", "SetRoute", "RecommendAction", "ParseRecommendation", "SetRecommendation"]
TRIGGER_FIELDS = {"${Trigger.Detection.Name}": "name", "${Trigger.Detection.SeverityDisplayName}": "severity",
                  "${Trigger.Detection.Description}": "description",
                  "${Trigger.Detection.FCS.CloudAccountId}": "account", "${Trigger.Detection.FCS.RawEvent}": "raw_event"}
DELETE = dict(method="DELETE", route="/workflows/entities/definitions/v1")
REPORT = ("print('|'.join(['${WorkflowCustomVariable.Action}', '${WorkflowCustomVariable.Target}', "
          "'${WorkflowCustomVariable.Detail}', '${WorkflowCustomVariable.Port}', '${WorkflowCustomVariable.AutoRun}', "
          "'${WorkflowCustomVariable.Confidence}', '${WorkflowCustomVariable.Check}']), end='')")
BOUND_APPS = {"IAM": "fecfb32861a14223ad131dd34210573a", "CLOUDTRAIL": "b101a6a0b042414a938aef201c2798c1",
              "GUARDDUTY": "fd069ff8dc6c4ea6a6137243e5bac6f7"}
SAMPLE_ACCOUNT = "123456789012"

args = argparse.ArgumentParser()
args.add_argument("samples", nargs="*")
args.add_argument("--no-detections", action="store_true")
args.add_argument("--days", type=float, default=1)
args.add_argument("--models", help="comma-separated Charlotte model names; default: the workflow's")
args.add_argument("--repeat", type=int, default=1, help="run each case this many times, to check consistency")
args = args.parse_args()

auth = dict(client_id=os.environ["FALCON_CLIENT_ID"], client_secret=os.environ["FALCON_CLIENT_SECRET"],
            base_url=os.environ.get("FALCON_BASE_URL", "auto"))
workflows, alerts, plugins = Workflows(**auth), Alerts(**auth), APIIntegrations(**auth)

# The same accounts and regions with their own configs that deploy.py fills in, plus the samples' account.
bound = {app: [SAMPLE_ACCOUNT if app == "IAM" else f"{SAMPLE_ACCOUNT}:us-east-1"] for app in BOUND_APPS}
for c in plugins.get_plugin_configs(limit=500)["body"].get("resources") or []:
    app = next((a for a, i in BOUND_APPS.items() if i == c["app_id"]), None)
    account = ((c["config"].get("auth") or {}).get("aws_0") or c["config"].get("auth") or {}).get("account_id")
    region = ((c["config"].get("params") or {}).get("path") or {}).get("region")
    if app and account != "{account_id}":
        bound[app].append(account if app == "IAM" or region is None else f"{account}:{region}")

source = yaml.safe_load(open("workflows/cdr-triage-and-respond.yaml"))
default_model = source["actions"]["RecommendAction"]["properties"]["model_name"]
models = [m.strip() for m in args.models.split(",")] if args.models else [default_model]
steps = json.dumps({name: source["actions"][name] for name in STEPS}).replace(
    "__BOUND_CONFIGS__", json.dumps(bound, separators=(",", ":")).replace('"', '\\"'))
for ref, param in TRIGGER_FIELDS.items():
    steps = steps.replace(ref, f"${{data['{param}']}}")
steps = json.loads(steps)
steps["SetRecommendation"]["next"] = ["Report"]
steps["Report"] = {"id": "7fb9eb10b23943efaf1e6082b0ac0338", "class": "Inline.Python", "name": "Report", "version_constraint": "~1",
                   "properties": {"runtime": "py0313general", "script": REPORT}}
conditions = {"is_llm": source["conditions"]["is_llm"]}


def replay_workflow(model):
    actions = json.loads(json.dumps(steps))
    actions["RecommendAction"]["properties"]["model_name"] = model
    return {"name": f"zz-replay-cdr-detections {model}", "description": "Temporary: scripts/replay-detections.py",
            "trigger": {"name": "On demand", "type": "On demand", "next": ["CreateVariable"],
                        "parameters": {"type": "object",
                                       "properties": {p: {"type": "string"} for p in TRIGGER_FIELDS.values()}}},
            "actions": actions, "conditions": conditions}


cases = []
if not args.no_detections:
    since = (datetime.now(timezone.utc) - timedelta(days=args.days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    ids = alerts.query_alerts_v2(filter=f"product:'fcs'+type:'cloud-ioa'+created_timestamp:>'{since}'",
                                 sort="created_timestamp.desc", limit=500)["body"]["resources"]
    seen = set()
    for i in range(0, len(ids), 100):
        for alert in alerts.get_alerts_v2(composite_ids=ids[i:i + 100])["body"]["resources"]:
            if alert["name"] not in seen:
                seen.add(alert["name"])
                cases.append({"name": alert["name"], "severity": alert.get("severity_name", ""),
                              "description": alert.get("description", ""), "account": alert.get("cloud_account_id", ""),
                              "raw_event": alert.get("raw_event", "")})
for path in args.samples:
    for sample in json.load(open(path)):
        raw = sample["raw_event"]
        raw = raw if isinstance(raw, str) else json.dumps(raw)
        cases.append({"account": json.loads(raw).get("recipientAccountId", ""), "description": "", **sample, "raw_event": raw})
if not cases:
    sys.exit("Nothing to replay: no CDR detections in the period and no sample file.")


def score(case, action, target, detail, port):
    """True if the answer matches one of the expected ones, None if there's nothing to compare to."""
    if not case.get("expect"):
        return None
    return any(action == x["action"] and target == x.get("target", target) and detail == x.get("detail", detail)
               and port == str(x.get("port", port)) for x in case["expect"])


ran = {}  # model -> [(case, execution id)]
created = []
try:
    for model in models:
        r = workflows.import_definition(data_file=yaml.safe_dump(replay_workflow(model), sort_keys=False))
        if r["body"].get("errors"):
            sys.exit(f"Importing the replay workflow failed: {r['body']['errors']}")
        wid = r["body"]["resources"][0]["id"]
        created.append(wid)
        r = workflows.workflow_definition_action(action_name="enable", ids=wid)
        if r["body"].get("errors"):
            sys.exit(f"Enabling the replay workflow failed: {r['body']['errors']}")
        body = lambda case: {k: case[k] for k in TRIGGER_FIELDS.values()}
        ran[model] = [(case, wid, workflows.execute(definition_id=wid, body=body(case))["body"]["resources"][0])
                      for _ in range(args.repeat) for case in cases]

    found = {}
    for _ in range(60):
        time.sleep(10)
        for wid in created:
            for offset in range(0, len(cases) * args.repeat, 100):
                found.update({x["execution_id"]: x for x in workflows.search_executions(
                    filter=f"definition_id:'{wid}'", limit=100, offset=offset)["body"].get("resources") or []})
        if all(found.get(i, {}).get("status") not in (None, "In progress") for runs in ran.values() for _, _, i in runs):
            break

    for model, runs in ran.items():
        print(f"\n=== {model} ===")
        tally, bands, tokens, answers = collections.Counter(), collections.defaultdict(lambda: [0, 0]), [], collections.defaultdict(set)
        for case, _, execution_id in runs:
            run = found.get(execution_id, {})
            acts = {a["node_id"]: a for a in run.get("activities") or []}
            report = ((acts.get("Report") or {}).get("result") or {}).get("output_stdout", "")
            if report:
                action, target, detail, port, auto, confidence, check = (report.split("|") + [""] * 7)[:7]
            elif run.get("status") == "Completed":
                action, target, detail, port, auto, confidence, check = "skip", "-", "", "0", "no", "", "made by the response role"
            else:
                action, target, detail, port, auto, confidence, check = run.get("status") or "missing", "", "", "", "", "", ""
            if action == "skip":
                target = "-"
            answers[case["name"]].add(f"{action} {target}" + (f" {detail}" if action != "escalate-human" else ""))
            ok = score(case, action, target, detail, port)
            tally["right" if ok else "wrong" if ok is False else "unscored"] += 1
            if ok is not None and confidence:
                band = bands["90+" if int(confidence) >= 90 else "70-89" if int(confidence) >= 70 else "<70"]
                band[0] += ok
                band[1] += 1
            result = (acts.get("RecommendAction") or {}).get("result") or {}
            meta = result.get("meta") or {}
            used = (result.get("meta.prompt_tokens") or meta.get("prompt_tokens"), result.get("meta.completion_tokens") or meta.get("completion_tokens"))
            if used[0]:
                tokens.append(used)
            mark = {True: "ok   ", False: "WRONG", None: "     "}[ok]
            print(f"{mark} {case['name']} ({case['severity']})\n        {action} {target} {detail} {port if port not in ('0', '') else ''}"
                  f"| auto {auto} | confidence {confidence} | {check}" + (f" | {used[0]}+{used[1]} tokens" if used[0] else ""))
            if ok is False:
                print(f"        expected: " + " or ".join(" ".join(map(str, x.values())) for x in case["expect"]))
                completion = (result.get("FaaS") or {}).get("nlpassistantapi", {}).get("llminvocator_handler", {}).get("completion") \
                    or result.get("completion") or json.dumps(result)[:400]
                print(f"        LLM said: {str(completion).replace(chr(10), ' ')[:400]}")
            for step, activity in acts.items():
                if activity["status"] == "Failed":
                    print(f"        FAILED {step}: {activity.get('error_message')}")
        print(f"\n{model}: {tally['right']} right, {tally['wrong']} wrong, {tally['unscored']} unscored")
        for band, (right, total) in sorted(bands.items()):
            print(f"  confidence {band}: {right}/{total} right")
        if tokens:
            print(f"  tokens: {sum(int(a) for a, _ in tokens) // len(tokens)} in, {sum(int(b) for _, b in tokens) // len(tokens)} out on average")
        if args.repeat > 1:
            flips = {n: a for n, a in answers.items() if len(a) > 1}
            print(f"  inconsistent across {args.repeat} runs: {len(flips)}" + "".join(f"\n    {n}: {' / '.join(sorted(a))}" for n, a in flips.items()))
finally:
    for wid in created:
        workflows.override(**DELETE, parameters={"ids": wid})
