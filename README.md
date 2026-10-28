# CDR triage and respond with Falcon Fusion SOAR

![Architecture](docs/architecture.svg)

A Falcon Fusion SOAR workflow that responds to AWS cloud detections (Falcon Cloud Security CDR, cloud IOA).

- **Charlotte AI picks the response for every detection.** It gets a trimmed CloudTrail event, the detection's name and description, and a catalog of every response action and the event field its target comes from. It returns an action, a target and a confidence from 0 to 100. Nothing in the workflow is specific to a detection type, so new CDR rules need no change.
- **Code checks every pick before anything runs.** The target must be the value of the field the catalog names (an AMI's `imageId`, a bucket's `bucketName`), and an undo's target must come from what the call changed. A failed call is never undone. Shared SSO roles and the root user are never contained. Anything that fails a check becomes an escalation.
- **Exact undos of exposure and policy changes run automatically** at confidence 90 or above. Everything else that acts needs an analyst to approve it by email. Every result is commented on a Falcon case.

```
FCS cloud IOA detection (AWS)
  → Route (Python): made by CrowdStrike's own response role? → stop
  → Charlotte AI LLM Completion (~1,100 tokens in / ~55 out): action, target, confidence
  → Check (Python): target is the catalog's field in the event, call succeeded, never SSO or root; else escalate
        └ skip (Informational or Low only) → stop, no case
  → Case (severity from the detection, the pick, its confidence and the check)
  → auto action and confidence ≥ 90 → run now                 → child workflow → comment on the case
  → any other action                → approval email → Approve → child workflow → comment on the case
                                                     → Decline → comment on the case
  → monitor-only / escalate-human → case only
```

## Responses

| Action | Picked for, for example | Runs | Approval |
|---|---|---|---|
| `sg-revoke-ingress` | An ingress rule opened to 0.0.0.0/0 or ::/0 (`AuthorizeSecurityGroupIngress`, `ModifySecurityGroupRules`) | EC2: remove the internet ingress rule on that port | Auto |
| `remove-public-snapshot` | An EBS snapshot shared with `all` | EC2: make the snapshot private | Auto |
| `ami-make-private` | An AMI shared with `all` | EC2: remove public launch permission | Auto |
| `s3-block-public-access` | A bucket made public by its ACL or policy, or its Block Public Access removed | S3: turn on all four Block Public Access settings. A public policy stays attached but is ignored. | Auto |
| `efs-remove-public-access` | A public EFS file system policy | EFS: remove public statements from the policy | Auto |
| `rds-snapshot-private` | An RDS snapshot shared with `all` | RDS: remove public restore permission | Auto |
| `cloudtrail-start-logging` | `StopLogging` | CloudTrail: start logging the trail again | Auto |
| `guardduty-enable-detector` | A GuardDuty detector disabled (not deleted) | GuardDuty: enable the detector again | Auto |
| `guardduty-delete-ipset` | A new GuardDuty trusted IP set | GuardDuty: delete that IP set | Auto |
| `iam-detach-{user,role,group}-policy` | A managed policy attached to a user, role or group | IAM: detach exactly that policy | Auto |
| `sns-reset-topic-policy` | An SNS topic policy opened to others | SNS: replace the topic policy with the default owner-only policy (the old one is on the case) | Approval |
| `iam-delete-{user,role,group}-policy` | An inline policy put on a user, role or group | IAM: delete that inline policy (its document is on the case) | Approval |
| `iam-disable-access-key` | An access key created or abused | IAM: set the key inactive | Approval |
| `iam-delete-login-profile` | A console password created or changed for a user | IAM: remove the console password | Approval |
| `lambda-disable` | A Lambda function made publicly invocable (a `*` permission, or a function URL with no auth) | Lambda: reserved concurrency 0 | Approval |
| `iam-role-apply-deny-policy` | A role's trust policy opened to others, or a role acting maliciously: attack tools or a hacking OS, a malicious IP, instance credentials used outside the instance | IAM: attach `AWSDenyAll` to the role | Approval |
| `iam-apply-deny-policy-user` | An IAM user acting maliciously, as above | IAM: attach `AWSDenyAll` to the user | Approval |
| `monitor-only` | Nothing exposed, nothing to contain: versioning or logging settings, a failed attempt, an admin role on an EC2 instance | Case only | n/a |
| `escalate-human` | No action fits: public ECR, KMS, Secrets Manager or Lambda layer policies, S3 account Block Public Access, a deleted detector, a public RDS instance. Containment of a shared SSO role or the root user. Any pick that fails the check. CloudTrail and GuardDuty responses in an account and region without their own config (below) | Case naming the API call and resource | n/a |
| `skip` | Expected, low-risk activity, Informational or Low severity only | Nothing, no case | n/a |

The catalog (`CATALOG` in `scripts/build-workflow.py`) lists each action, whether it may run automatically, and the event field its target, detail and port come from. The prompt and the check are generated from it. Its rules don't depend on the detection type:

- **Undo actions** act on what the call changed: the target must be the named field's value in `requestParameters` or `responseElements`. Containment may also target the caller.
- **A failed call** (`errorCode` set) changed nothing, so it's never undone.
- **Never contained:** a shared AWS SSO (`AWSReservedSSO_*`) role or the root user; those become an escalation. This is enforced in code, not the prompt: telling the model about it made it escalate every change made by an SSO user.
- **`skip`** is only allowed for Informational or Low detections. Several Informational rules (an admin policy attached to a user, group or role) do need a response, so severity alone can't decide.
- **Auto-run** needs an `auto` action, confidence 90 or above and a clean check. Confidence never lets a containment action skip approval.

## Rule coverage and accuracy

`scripts/replay-detections.py` scores every pick against the expected answers in two sample sets:

- `tests/sample-events.json` (43 samples): the earlier routing table's cases, plus 7 anonymized real detections.
- `tests/unseen-events.json` (15 samples): detection types the earlier routing table had no entry for. For example, `ModifySecurityGroupRules`, a Lambda function URL with no auth, Pacu, public KMS and Secrets Manager policies, and a public RDS instance.

Two runs each, on 2026-10-28:

| Model | Samples | Unseen | Right at confidence ≥ 90 | Tokens in / out |
|---|---|---|---|---|
| GPT Latest (default) | 86/86 | 30/30 | 110/110 | ~1,100 / 55 |
| Claude Latest | 84/86 | 28/30 | 57/57 | ~1,270 / 65 |
| Nemotron 3 120B (one run, earlier prompt) | 27/43 | n/a | 19/29 | ~1,200 / 90 |

Claude's misses were all at confidence 72: it locked a user that a malicious caller had just created, instead of the caller. Nemotron picked actions for the wrong resource type (`ami-make-private` on an ECR repository), which the field check now blocks. Change `MODEL` in `scripts/build-workflow.py` to switch models.

To turn escalations into actions, add the Store app to `ACTIONS` and `CATALOG` in `scripts/build-workflow.py`, and the role permission. ECR, SES, KMS, Secrets Manager, CloudWatch Logs resource policies, the Serverless Application Repository and S3 account Block Public Access have no Fusion action.

## Cost

Every detection, except those made by the response role, costs one LLM call: about 1,100 input and 55 output tokens on GPT Latest. The input is mostly the action catalog, so it grows by about 30 tokens per action you add. The earlier design used no tokens for the 54 rules it routed in code, but needed a code change for every new rule or API call.

## Prerequisites

- Falcon Cloud Security with CDR (cloud IOA) on the AWS accounts, and Charlotte AI.
- CrowdStrike Store apps **AWS IAM**, **AWS EC2**, **AWS S3**, **AWS Lambda**, **AWS EFS**, **AWS RDS**, **AWS SNS**, **AWS CloudTrail** and **AWS GuardDuty**, using the CrowdStrike automated-response role (`CrowdStrikeAutomatedResponse`, from CrowdStrike's CloudFormation template).
  - **Extra role permissions:** CrowdStrike's template doesn't allow CloudTrail `StartLogging` or GuardDuty writes. Deploy `cfn/extra-response-permissions.yaml` in each account (or as a StackSet). It adds an inline policy to the existing role, so CrowdStrike template upgrades leave it alone: `aws cloudformation deploy --stack-name CdrSoar-ExtraResponsePermissions --template-file cfn/extra-response-permissions.yaml --capabilities CAPABILITY_IAM`.
  - **Many accounts:** set a config's Account ID to `{account_id}`. It then acts in whichever account the detection came from, provided that account has the same role name and external ID (deploy the role with a StackSet). One such config per app covers every account.
  - **Exceptions:** the generic `AWS IAM - …` actions (detach and delete policy, delete login profile) take no account input, and the CloudTrail and GuardDuty actions take neither account nor region; `{account_id}` configs don't work for them. Keep a per-account AWS IAM config, and an AWS CloudTrail and AWS GuardDuty config per account and region you want covered. Elsewhere the workflow falls back: IAM undos become an approval-gated deny, CloudTrail and GuardDuty become an escalation.
  - Configs can only be created in the console; the public API is read-only.
- An approver who is a Falcon user (`APPROVER_EMAIL`). Only they can approve, from the email: the human-input API returns 403 to API clients when responders are set, so an API key can't approve containment.
- A Falcon API client with **Workflow: Read/Write**, **API integrations: Read** and, for the replay script, **Alerts: Read**.
- Python 3 with [FalconPy](https://github.com/CrowdStrike/falconpy) and PyYAML: `pip install crowdstrike-falconpy pyyaml`.

## Deploy

```
cp .env.example .env   # fill in the API client and APPROVER_EMAIL (a Falcon user)
set -a; source .env; set +a
scripts/deploy.py
```

The script reads every Store app configuration and builds a lookup from AWS account ID to config, falling back to an `{account_id}` config for accounts without their own, so each detection acts in its own account. It fills in the approver, then imports and enables five workflows:

- **CDR respond - IAM**, **CDR respond - EC2**, **CDR respond - data stores** (S3, Lambda, EFS, RDS, SNS) and **CDR respond - logging and detection** (CloudTrail, GuardDuty) (`workflows/cdr-respond-*.yaml`): on-demand child workflows that each run one response action and comment the result on the case. They're imported first.
- **CDR triage and respond** (`workflows/cdr-triage-and-respond.yaml`): the detection-triggered workflow. It has Charlotte AI pick the response, checks it, opens the case, gets approval, then calls the child for the chosen action, using the definition IDs from the first step.

The split keeps the main workflow readable on the canvas: it has 13 actions where the single workflow has 51, because the Fusion editor can't group nodes. If a child's action fails, the main workflow's step fails too and links to the child's execution.

**Self-contained version:** `scripts/deploy.py --self-contained` deploys `workflows/self-contained/cdr-triage-and-respond.yaml` instead, a single workflow with all 51 actions inline. It behaves the same, and both versions are generated from the same action table. They share a name, so deploy one or the other, never both; `--replace` removes whichever is deployed.

Re-run it after adding an account. Detections from an account without a configuration fail at the response action. Import fails if the workflows already exist: `scripts/deploy.py --replace` deletes the deployed copies first, starting with the main workflow.

Images of each workflow as the Fusion canvas shows it, for when the canvas is too big to screenshot: `docs/workflow/*.png`. Regenerate them with `python3 docs/make-workflow-diagram.py` after rebuilding.

## Change it

The files in `workflows/` are generated. Edit `scripts/build-workflow.py` (the action table, catalog and prompt), `scripts/workflow/route.py` (the event trimming) or `scripts/workflow/parse_llm.py` (the check), then run `scripts/build-workflow.py`. A new detection type needs no change; replay it to see what the workflow would do.

## Test it

- `scripts/replay-detections.py tests/sample-events.json tests/unseen-events.json` runs the routing, LLM and check steps on the latest real detection per rule from the last day, plus the sample events, and prints what the workflow would do without acting. It scores each sample against its `expect` answers, and reports accuracy per confidence band and average tokens. `--models "GPT Latest,Claude Latest"` compares models side by side, `--repeat 2` shows answers that change between runs, and `--days 30` widens the real detections. It takes 2 to 5 minutes.
- `scripts/simulate-detections.sh run` triggers real CDR detections in a **test** AWS account using throwaway `cdr-sim-*` resources; `scripts/simulate-detections.sh list` shows the scenarios. Scenarios that make something public beyond an unused security group and an empty snapshot only run when named. `public-ami` fails while the account's AMI Block Public Access is on, which is the AWS default; the script doesn't turn it off. Detections arrive in about 5 to 15 minutes. `scripts/simulate-detections.sh cleanup` removes everything.

CDR raises one alert per rule per UTC clock hour. A repeat in the same hour is added to that alert, even a closed one, and the workflow doesn't fire, so the repeat gets no response. Run each scenario at most once per clock hour.
