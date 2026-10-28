import json

# Every detection goes to the LLM, with a trimmed CloudTrail event. The only rule here doesn't depend
# on the detection type: a response action can itself raise a detection (attaching AWSDenyAll fires
# "admin policy attached to role"), so skip anything CrowdStrike's response role did.
LONG = 600  # longer request values (policy documents) are cut to this many characters

e = json.loads(r'''${Trigger.Detection.FCS.RawEvent}''')
ui = e.get("userIdentity") or {}
caller = ui.get("arn") or ""


def trim(value):
    if isinstance(value, dict):
        return {k: trim(v) for k, v in value.items() if v not in (None, "", [], {})}
    if isinstance(value, list):
        return [trim(v) for v in value]
    if isinstance(value, str) and len(value) > LONG:
        return value[:LONG] + "…"
    return value


trimmed = {"eventName": e.get("eventName"), "eventSource": e.get("eventSource"), "awsRegion": e.get("awsRegion"),
           "sourceIPAddress": e.get("sourceIPAddress"), "userAgent": e.get("userAgent"), "errorCode": e.get("errorCode"),
           "userIdentity": {k: ui.get(k) for k in ("type", "arn", "userName", "accessKeyId") if ui.get(k)},
           "requestParameters": e.get("requestParameters"), "responseElements": e.get("responseElements")}
event = json.dumps(trim(trimmed), separators=(",", ":"), ensure_ascii=False)
region = e.get("awsRegion") or "us-east-1"
if "CrowdStrikeAutomatedResponse" in caller:
    route, check = "skip", "made by the CrowdStrike response role"
else:
    route, check = "llm", ""
print("|".join([route, region, check]) + "#EVENT#" + event, end="")
