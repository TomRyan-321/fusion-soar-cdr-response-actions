"""Generate docs/architecture.svg (CrowdStrike brand colours, Inter fallback font). Run: python3 docs/make-architecture.py"""
import os
from html import escape

RED, DARK_RED, BLACK, STORM, CLOUD, SURF, DEEP = "#EC0000", "#B52026", "#000000", "#A7A9AC", "#F8F8F8", "#61C4C9", "#3D474F"
W, H = 1400, 1040
out = []


def box(x, y, w, h, title, lines=(), stripe=None, fill="#FFFFFF", stroke=STORM, title_color=BLACK, size=15):
    out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>')
    if stripe:
        out.append(f'<rect x="{x}" y="{y}" width="6" height="{h}" rx="3" fill="{stripe}"/>')
    ty = y + 26
    out.append(f'<text x="{x + 18}" y="{ty}" font-size="{size}" font-weight="700" fill="{title_color}">{escape(title)}</text>')
    for i, line in enumerate(lines):
        bullet = line.startswith("• ")
        out.append(f'<text x="{x + 18}" y="{ty + 22 + i * 19}" font-size="12.5" fill="{DEEP if not bullet else BLACK}">{escape(line)}</text>')


def arrow(x1, y1, x2, y2, label=None, lx=None, ly=None, color=DEEP):
    out.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="1.8" marker-end="url(#a)"/>')
    if label:
        out.append(f'<text x="{lx if lx is not None else (x1 + x2) / 2 + 6}" y="{ly if ly is not None else (y1 + y2) / 2 - 6}" '
                   f'font-size="12" font-style="italic" fill="{DEEP}">{escape(label)}</text>')


def path(d, color=DEEP):
    out.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="1.8" marker-end="url(#a)"/>')


out.append(f'<rect width="{W}" height="{H}" fill="#FFFFFF"/>')
out.append(f'<text x="40" y="52" font-size="26" font-weight="700" fill="{BLACK}">CDR triage and respond</text>')
out.append(f'<text x="40" y="78" font-size="14" fill="{DEEP}">Falcon Fusion SOAR response to AWS cloud IOA detections: fixed responses where the fix is obvious, '
           f'Charlotte AI for judgment calls, approval for anything disruptive.</text>')
out.append(f'<rect x="40" y="90" width="120" height="4" fill="{RED}"/>')

# Detection source
box(40, 140, 220, 96, "AWS account", ["CloudTrail API call, e.g.", "AuthorizeSecurityGroupIngress"], stripe=SURF)
arrow(150, 236, 150, 290)
box(40, 290, 220, 96, "Falcon Cloud Security", ["CDR cloud IOA detection", "Fusion trigger: FCS Detection"], stripe=RED)
path("M 260 338 C 295 338, 300 221, 328 221")

# Fusion workflow frame
out.append(f'<rect x="300" y="120" width="760" height="610" rx="10" fill="{CLOUD}" stroke="{RED}" stroke-width="2"/>')
out.append(f'<text x="320" y="146" font-size="13" font-weight="700" fill="{RED}">FUSION SOAR WORKFLOW</text>')

box(330, 165, 300, 112, "Route (Python step)", ["Maps 47 CloudTrail API calls, plus root,", "instance-role and attack-tool activity,", "to a fixed response with the exact", "target. 0 tokens."], stripe=RED)
box(660, 172, 370, 98, "Stop, no case", ["Informational with no fixed response,", "or made by the CrowdStrike response role", "(so containment is never undone)"], fill="#FFFFFF", title_color=DEEP)
arrow(630, 221, 658, 221)

box(330, 330, 300, 130, "Charlotte AI LLM Completion", ["Judgment calls only (malicious IP, tools,", "anomalies). ~300 in / 65 out tokens.", "Target must appear in the event;", "never denies an AWSReservedSSO_* role."], stripe=DARK_RED)
arrow(480, 277, 480, 328, "no fixed response", 488, 307)

box(680, 330, 350, 130, "Falcon case", ["Action, target, how it was decided,", "the target check and the trimmed event.", "Severity from the detection.", "monitor-only / escalate-human stop here."], stripe=RED)
arrow(630, 395, 678, 395)
path("M 630 255 C 660 255, 650 330, 700 328")
out.append(f'<text x="664" y="300" font-size="12" font-style="italic" fill="{DEEP}">fixed response</text>')

box(330, 510, 330, 190, "Runs automatically", ["Exact undo of the change:", "• revoke internet ingress on the port", "• make snapshot / AMI / RDS snapshot private",
                                                 "• turn on S3 Block Public Access", "• remove the public EFS policy", "• detach the admin policy (user, role, group)",
                                                 "• restart a trail; re-enable GuardDuty", "• delete a new GuardDuty trusted IP set"], stripe=RED)
box(690, 510, 340, 190, "Approval email, then run", ["Approve runs it; Decline comments the case:", "• delete an inline admin policy", "• disable an access key",
                                                       "• delete a login profile", "• Lambda reserved concurrency 0", "• reset an SNS topic policy to owner-only",
                                                       "• AWSDenyAll on an IAM user or role"], stripe=DARK_RED)
arrow(780, 460, 495, 508)
arrow(855, 460, 860, 508)

# Store apps and AWS
box(1100, 165, 260, 260, "Child workflows → Store apps", ["CDR respond - IAM · EC2 · data stores", "· logging and detection: one", "condition, AWS step and case", "comment per action.", "",
                                                     "EC2, S3, Lambda, EFS, RDS, SNS: one", "{account_id} config per app covers", "every account. Generic IAM undos,", "CloudTrail and GuardDuty need one", "per account (and region), else they", "fall back to a deny or an escalation."], stripe=RED)
# Both response paths join one bus outside the frame, with a single arrow into the child workflows.
path("M 495 700 L 495 716 L 1074 716 Q 1080 716, 1080 710 L 1080 406 Q 1080 400, 1086 400 L 1098 400")
out.append(f'<path d="M 1030 605 L 1080 605" fill="none" stroke="{DEEP}" stroke-width="1.8"/>')
out.append(f'<circle cx="1080" cy="605" r="3.5" fill="{DEEP}"/>')
out.append(f'<text x="1092" y="560" font-size="12" font-style="italic" fill="{DEEP}" transform="rotate(-90 1092 560)">call child workflow</text>')
arrow(1230, 425, 1230, 480)
box(1100, 480, 260, 170, "Every AWS account", ["CrowdStrikeAutomatedResponse role", "(CloudFormation / StackSet: same", "role name and external ID), plus", "cfn/extra-response-permissions.yaml", "for CloudTrail and GuardDuty.", "Result is commented on the case."], stripe=SURF)

# Tooling band
out.append(f'<text x="40" y="778" font-size="13" font-weight="700" fill="{RED}">REPO TOOLING</text>')
box(40, 792, 300, 96, "scripts/build-workflow.py", ["Action table + LLM prompt; embeds", "workflow/route.py and parse_llm.py"])
arrow(340, 840, 378, 840)
box(380, 792, 300, 96, "workflows/*.yaml", ["Generated: main workflow (13 actions)", "+ 4 child workflows (42 actions), or", "one self-contained workflow (51)"])
arrow(680, 840, 718, 840)
box(720, 792, 300, 96, "scripts/deploy.py", ["Fills Store config lookup, approver", "and child IDs; imports + enables all 5"])
path("M 870 792 C 870 760, 700 760, 700 732")
box(40, 910, 470, 96, "scripts/replay-detections.py + tests/sample-events.json", ["Dry run of routing and LLM steps on real and sample", "events. Prints route, action, target, tokens. No AWS action."])
box(540, 910, 480, 96, "scripts/simulate-detections.sh run | cleanup", ["Real detections from throwaway cdr-sim-* resources in a", "sandbox account. Public-exposure scenarios are opt-in."])
box(1100, 792, 260, 214, "Measured", ["Routed detections: 0 tokens", "LLM detections: ~300 in / 65 out", "(was ~1,290 / 200 on every one)", "",
                                      "Live tests: 13 CDR rules from real", "detections, results checked in AWS"], stripe=DARK_RED)

svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
       f'font-family="Inter, system-ui, -apple-system, Helvetica, Arial, sans-serif">'
       f'<defs><marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
       f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{DEEP}"/></marker></defs>' + "".join(out) + "</svg>")
open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "architecture.svg"), "w").write(svg)
print("ok")
