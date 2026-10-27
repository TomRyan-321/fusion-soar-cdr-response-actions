#!/usr/bin/env python3
"""Replay CDR detections through the workflow's decision steps, without acting.

Copies the routing and LLM steps of workflows/cdr-triage-and-respond.yaml into a
temporary on-demand workflow and runs it on the latest real detection for each
rule from the last day, plus any sample events you pass in. Prints what the
workflow would do, then deletes the temporary workflow. Use it to test routing
or prompt changes in a couple of minutes instead of waiting for new detections.

Sample events file: a JSON list of {"name", "severity", "raw_event"} objects,
where raw_event is a CloudTrail record (object or JSON string) and name is the detection
name (some rules are routed on it). An optional "expect" field is for the reader.

Needs the same environment as deploy.py plus the Alerts: Read scope, and PyYAML.

Usage: scripts/replay-detections.py [--no-detections] [samples.json]
"""
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

import yaml
from falconpy import Alerts, Workflows

STEPS = ["CreateVariable", "Route", "SetRoute", "RecommendAction", "ParseRecommendation", "SetRecommendation"]
TRIGGER_FIELDS = {"${Trigger.Detection.Name}": "name", "${Trigger.Detection.SeverityDisplayName}": "severity",
                  "${Trigger.Detection.FCS.CloudAccountId}": "account", "${Trigger.Detection.FCS.RawEvent}": "raw_event"}
DELETE = dict(method="DELETE", route="/workflows/entities/definitions/v1")
REPORT = ("print('|'.join(['${WorkflowCustomVariable.Route}', '${WorkflowCustomVariable.Action}', "
          "'${WorkflowCustomVariable.Target}', '${WorkflowCustomVariable.Detail}', '${WorkflowCustomVariable.Port}', "
          "'${WorkflowCustomVariable.AutoRun}', '${WorkflowCustomVariable.Confidence}']), end='')")

auth = dict(client_id=os.environ["FALCON_CLIENT_ID"], client_secret=os.environ["FALCON_CLIENT_SECRET"],
            base_url=os.environ.get("FALCON_BASE_URL", "auto"))
workflows, alerts = Workflows(**auth), Alerts(**auth)

source = yaml.safe_load(open("workflows/cdr-triage-and-respond.yaml"))
steps = json.dumps({name: source["actions"][name] for name in STEPS})
for ref, param in TRIGGER_FIELDS.items():
    steps = steps.replace(ref, f"${{data['{param}']}}")
steps = json.loads(steps)
steps["SetRecommendation"]["next"] = ["Report"]
steps["Report"] = {"id": "7fb9eb10b23943efaf1e6082b0ac0338", "name": "Report", "version_constraint": "~1",
                   "properties": {"runtime": "py0313general", "script": REPORT}}
conditions = {k: source["conditions"][k] for k in ("is_table", "is_llm")}
conditions["is_table"] = {**conditions["is_table"], "next": ["Report"]}
replay = {"name": "zz-replay-cdr-detections", "description": "Temporary: scripts/replay-detections.py",
          "trigger": {"name": "On demand", "type": "On demand", "next": ["CreateVariable"],
                      "parameters": {"type": "object",
                                     "properties": {p: {"type": "string"} for p in TRIGGER_FIELDS.values()}}},
          "actions": steps, "conditions": conditions}

cases = []
if "--no-detections" not in sys.argv:
    since = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    ids = alerts.query_alerts_v2(filter=f"product:'fcs'+type:'cloud-ioa'+created_timestamp:>'{since}'",
                                 sort="created_timestamp.desc", limit=100)["body"]["resources"]
    seen = set()
    for alert in alerts.get_alerts_v2(composite_ids=ids)["body"]["resources"] if ids else []:
        if alert["name"] not in seen:
            seen.add(alert["name"])
            cases.append({"name": alert["name"], "severity": alert.get("severity_name", ""),
                          "account": alert.get("cloud_account_id", ""), "raw_event": alert.get("raw_event", "")})
for path in (a for a in sys.argv[1:] if not a.startswith("--")):
    for sample in json.load(open(path)):
        raw = sample["raw_event"]
        cases.append({"account": json.loads(raw if isinstance(raw, str) else json.dumps(raw)).get("recipientAccountId", ""),
                      **sample, "raw_event": raw if isinstance(raw, str) else json.dumps(raw)})
if not cases:
    sys.exit("Nothing to replay: no CDR detections in the last day and no sample file.")

r = workflows.import_definition(data_file=yaml.safe_dump(replay, sort_keys=False))
if r["body"].get("errors"):
    sys.exit(f"Importing the replay workflow failed: {r['body']['errors']}")
wid = r["body"]["resources"][0]["id"]
try:
    r = workflows.workflow_definition_action(action_name="enable", ids=wid)
    if r["body"].get("errors"):
        sys.exit(f"Enabling the replay workflow failed: {r['body']['errors']}")
    runs = [(case, workflows.execute(definition_id=wid, body=case)["body"]["resources"][0]) for case in cases]

    for _ in range(40):
        time.sleep(10)
        found = {x["execution_id"]: x for x in
                 workflows.search_executions(filter=f"definition_id:'{wid}'", limit=100)["body"].get("resources") or []}
        if all(found.get(i, {}).get("status") not in (None, "In progress") for _, i in runs):
            break

    for case, execution_id in runs:
        run = found.get(execution_id, {})
        steps = {a["node_id"]: a for a in run.get("activities") or []}
        report = ((steps.get("Report") or {}).get("result") or {}).get("output_stdout", "")
        route, action, target, detail, port, auto, confidence = (report.split("|") + [""] * 7)[:7]
        tokens = (steps.get("RecommendAction") or {}).get("result") or {}
        meta = tokens.get("meta") or {}
        used = f" | {tokens.get('meta.prompt_tokens') or meta.get('prompt_tokens')}+{tokens.get('meta.completion_tokens') or meta.get('completion_tokens')} tokens" if tokens else ""
        print(f"{case['name']}\n  [{route or ('skip' if run.get('status') == 'Completed' else run.get('status'))}] {action} {target} {detail} {port if port not in ('0', '') else ''}"
              f"| auto-run {auto} | confidence {confidence}{used}")
        for step, activity in steps.items():
            if activity["status"] == "Failed":
                print(f"  FAILED {step}: {activity.get('error_message')}")
finally:
    workflows.override(**DELETE, parameters={"ids": wid})
