import json

# The action catalog from build-workflow.py: how each action runs and where its target must come from.
CATALOG = json.loads(r'''__CATALOG__''')
AUTO_MIN = __AUTO_MIN__
# Some Store actions have no account input (generic AWS IAM), or neither account nor region
# (CloudTrail, GuardDuty): they act in their config's account and region, and an {account_id}
# config doesn't work for them. deploy.py fills in which accounts (IAM) or account:region pairs
# have their own config; anywhere else the catalog's fallback is used instead.
BOUND = r'''__BOUND_CONFIGS__'''
BOUND = None if BOUND.startswith("__") else json.loads(BOUND)
APP_NAMES = {"IAM": "AWS IAM", "CLOUDTRAIL": "AWS CloudTrail", "GUARDDUTY": "AWS GuardDuty"}

text = r'''${RecommendAction.FaaS.nlpassistantapi.llminvocator_handler.completion}'''
event = r'''${WorkflowCustomVariable.Event}'''
severity = "${Trigger.Detection.SeverityDisplayName}"
account = "${Trigger.Detection.FCS.CloudAccountId}"
region = "${WorkflowCustomVariable.Region}"

# The last JSON object in the reply: some models think aloud and correct themselves after a first answer.
r, i = {}, text.find("{")
while i != -1:
    try:
        found, end = json.JSONDecoder().raw_decode(text, i)
        r, i = (found, text.find("{", end)) if isinstance(found, dict) and "action" in found else (r, text.find("{", i + 1))
    except ValueError:
        i = text.find("{", i + 1)
e = json.loads(event)
ui = e.get("userIdentity") or {}
action = str(r.get("action") or "")
target, detail = str(r.get("target") or "").strip(), str(r.get("detail") or "").strip()
try:
    port = int(r.get("port") or 0)
except (TypeError, ValueError):
    port = 0
confidence = r.get("confidence")
if isinstance(confidence, str):  # high/medium/low instead of a number: never enough to run on its own
    confidence = {"high": 80, "medium": 60, "low": 30}.get(confidence.lower(), confidence)
try:
    confidence = float(confidence)
    confidence = max(0, min(100, round(confidence * 100 if 0 < confidence < 1 else confidence)))  # 0.9 means 90
except (TypeError, ValueError):
    confidence = 0
why = str(r.get("why") or "").replace("\n", " ")


def values(x, key):
    """Every value of `key` anywhere in x. Newer APIs capitalize field names (GroupId, FromPort)."""
    if isinstance(x, dict):
        return [v for k, v in x.items() if k.lower() == key.lower()] + [w for v in x.values() for w in values(v, key)]
    return [w for v in x for w in values(v, key)] if isinstance(x, list) else []


def matches(value, keys, scope):
    """True if value is the value of one of the event fields `keys` within scope."""
    keys = [keys] if isinstance(keys, str) else keys
    role = (ui.get("arn") or "").split("/")[1] if ui.get("type") == "AssumedRole" else None
    return any(str(value) == role if k == "@role" else str(value) in [str(v) for v in values(scope, k)] for k in keys)


def check():
    """The reason the recommendation can't run as given, or None. Doesn't depend on the detection type."""
    spec = CATALOG.get(action)
    if not spec:
        return f"unknown action {action or '(none)'}"
    if action == "skip" and severity not in ("Informational", "Low"):
        return f"won't skip a {severity} detection"
    # An undo acts on what the call changed; containment may act on the caller too.
    undo = spec.get("kind") == "undo"
    scope = [e.get("requestParameters"), e.get("responseElements")] if undo else e
    for name, value in (("target", target), ("detail", detail), ("port", port)):
        keys = spec.get(name)
        if keys and not value:
            return f"{action} needs a {name}"
        if keys and not matches(value, keys, scope):
            where = "request or response" if undo else "event"
            return f"{name} {value} isn't the {' or '.join([keys] if isinstance(keys, str) else keys)} in the {where}"
    if undo and e.get("errorCode"):
        return f"the call failed ({e['errorCode']}), so there is nothing to undo"
    if action.startswith("iam-") and target.startswith("AWSReservedSSO_"):
        return f"won't act on shared SSO role {target}"
    if spec.get("kind") == "contain" and ui.get("type") == "Root":
        return "won't contain the root user"
    return None


problem = check()
note = ""
found = "target matches the event" if CATALOG.get(action, {}).get("target") else "no target needed"
if problem:
    detail = f"{action} {target} {detail}".strip() if action not in ("escalate-human", "monitor-only") else detail
    action, target, port, confidence = "escalate-human", "-", 0, min(confidence, 50)
elif CATALOG[action].get("bound") and BOUND is not None:
    app, fallback = CATALOG[action]["bound"]
    where = account if app == "IAM" else f"{account}:{region}"
    if where not in BOUND.get(app, []):
        note = f"; {action} needs an {APP_NAMES[app]} config for {where.replace(':', ' ')}, so {fallback} instead"
        if fallback == "escalate-human":
            action, target, detail, port = fallback, "-", f"{action} {target} {detail}".strip(), 0
        else:
            action, detail = fallback, ""
if not CATALOG[action].get("target"):
    target = "-"
if CATALOG[action].get("detail") is None:
    detail = ""
if not CATALOG[action].get("port"):
    port = 0
check_text = problem or found + note
auto = "yes" if CATALOG[action]["runs"] == "auto" and confidence >= AUTO_MIN and not problem and not note else "no"
fields = [action, target, detail, port, confidence, why, check_text, auto]
print("|".join(str(f).replace("|", "") for f in fields), end="")
