import json

ACTIONS = {"iam-disable-access-key", "iam-apply-deny-policy-user", "iam-role-apply-deny-policy", "monitor-only", "escalate-human"}
text = r'''${RecommendAction.FaaS.nlpassistantapi.llminvocator_handler.completion}'''
event = r'''${WorkflowCustomVariable.Event}'''
try:
    r = json.loads(text[text.index("{"):text.rindex("}") + 1])
except ValueError:
    r = {}
action = r.get("action") if r.get("action") in ACTIONS else "escalate-human"
target, key = str(r.get("target") or ""), str(r.get("access_key_id") or "")
confidence = r.get("confidence")
if isinstance(confidence, (int, float)):  # the model sometimes answers 0.9
    confidence = "high" if confidence >= 0.8 else "medium" if confidence >= 0.5 else "low"
# Deterministic guard: the target (and key) must appear verbatim in the CloudTrail event.
needed = [t for t in (target, key if action == "iam-disable-access-key" else "") if t]
if action in ("monitor-only", "escalate-human"):
    check = "no target needed"
elif action == "iam-role-apply-deny-policy" and target.startswith("AWSReservedSSO_"):
    # Shared Identity Center role: denying it locks out every user of that permission set.
    action, check = "escalate-human", f"won't deny shared SSO role {target}"
elif needed and all(t in event for t in needed):
    check = "target found in the event"
else:
    action, check = "escalate-human", f"LLM target {target} {key} not found in the event"
why = str(r.get("why") or "").replace("\n", " ")
fields = [action, target, key, str(confidence or "low").lower(), why, check]
print("|".join(f.replace("|", "") for f in fields), end="")
