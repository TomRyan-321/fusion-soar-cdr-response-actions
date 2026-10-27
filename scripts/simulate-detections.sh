#!/usr/bin/env bash
# Generate Falcon CDR (cloud IOA) detections in a TEST AWS account, each needing a
# different response, so the triage workflow can be exercised end to end.
#
# Every resource is a throwaway named cdr-sim-*: users and roles have no
# credentials an attacker could use, the security group has no instances,
# snapshots and AMIs are of an empty volume, and buckets, file systems and
# functions are empty. Names carry a per-run suffix so runs don't collide. CDR
# raises one alert per rule per UTC clock hour and folds repeats into it without
# firing the workflow, so run a scenario at most once per clock hour.
#
# The default set doesn't expose anything beyond SSH on an unused security group
# and a public snapshot of an empty volume. Scenarios marked PUBLIC expose more
# (a public bucket, AMI, Lambda function or file system, or a console password)
# and only run when named explicitly. CONTROLS scenarios change GuardDuty in the region (they create
# a cdr-sim detector if there is none, which starts GuardDuty billing) and also only run when named.
#
# Usage: scripts/simulate-detections.sh run [scenario ...] | cleanup | list
#        (uses AWS_REGION, default us-east-1)
set -euo pipefail

REGION=${AWS_REGION:-us-east-1}
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
ADMIN=arn:aws:iam::aws:policy/AdministratorAccess
ADMIN_INLINE='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
TRUST_ACCOUNT="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::${ACCOUNT}:root\"},\"Action\":\"sts:AssumeRole\"}]}"
SUFFIX=$(date +%s)
DEFAULT="access-key admin-user admin-role admin-group inline-user inline-role inline-group sg-ssh public-snapshot s3-versioning"
PUBLIC="public-bucket public-ami public-lambda public-efs public-sns login-profile"
CONTROLS="gd-suspend gd-ipset"
ec2() { aws ec2 --region "$REGION" "$@"; }

empty_snapshot() {
  local az vol snap
  az=$(ec2 describe-availability-zones --query 'AvailabilityZones[0].ZoneName' --output text)
  vol=$(ec2 create-volume --availability-zone "$az" --size 1 --tag-specifications \
    'ResourceType=volume,Tags=[{Key=Name,Value=cdr-sim}]' --query VolumeId --output text)
  ec2 wait volume-available --volume-ids "$vol"
  snap=$(ec2 create-snapshot --volume-id "$vol" --tag-specifications \
    'ResourceType=snapshot,Tags=[{Key=Name,Value=cdr-sim}]' --query SnapshotId --output text)
  ec2 wait snapshot-completed --snapshot-ids "$snap"
  echo "$snap"
}

sim_access_key() {  # Access Key created via CLI -> disable the key (approval)
  aws iam create-user --user-name cdr-sim-key-user-$SUFFIX >/dev/null
  aws iam create-access-key --user-name cdr-sim-key-user-$SUFFIX --query AccessKey.AccessKeyId --output text
}
sim_admin_user() {  # Administrative policy attached to user -> detach it (auto)
  aws iam create-user --user-name cdr-sim-admin-user-$SUFFIX >/dev/null
  aws iam attach-user-policy --user-name cdr-sim-admin-user-$SUFFIX --policy-arn $ADMIN
}
sim_admin_role() {  # Administrative policy attached to role -> detach it (auto)
  aws iam create-role --role-name cdr-sim-admin-role-$SUFFIX --assume-role-policy-document "$TRUST_ACCOUNT" >/dev/null
  aws iam attach-role-policy --role-name cdr-sim-admin-role-$SUFFIX --policy-arn $ADMIN
}
sim_admin_group() {  # Administrative policy attached to group -> detach it (auto)
  aws iam create-group --group-name cdr-sim-admin-group-$SUFFIX >/dev/null
  aws iam attach-group-policy --group-name cdr-sim-admin-group-$SUFFIX --policy-arn $ADMIN
}
sim_inline_user() {  # Administrative inline policy attached to user -> delete it (approval)
  aws iam create-user --user-name cdr-sim-inline-user-$SUFFIX >/dev/null
  aws iam put-user-policy --user-name cdr-sim-inline-user-$SUFFIX --policy-name cdr-sim-admin --policy-document "$ADMIN_INLINE"
}
sim_inline_role() {  # Administrative inline policy attached to role -> delete it (approval)
  aws iam create-role --role-name cdr-sim-inline-role-$SUFFIX --assume-role-policy-document "$TRUST_ACCOUNT" >/dev/null
  aws iam put-role-policy --role-name cdr-sim-inline-role-$SUFFIX --policy-name cdr-sim-admin --policy-document "$ADMIN_INLINE"
}
sim_inline_group() {  # Administrative inline policy attached to group -> delete it (approval)
  aws iam create-group --group-name cdr-sim-inline-group-$SUFFIX >/dev/null
  aws iam put-group-policy --group-name cdr-sim-inline-group-$SUFFIX --policy-name cdr-sim-admin --policy-document "$ADMIN_INLINE"
}
sim_sg_ssh() {  # Security group ingress open to the internet -> revoke it (auto)
  local sg
  sg=$(ec2 create-security-group --group-name cdr-sim-sg-$SUFFIX --description "CDR simulation" --query GroupId --output text)
  ec2 authorize-security-group-ingress --group-id "$sg" --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null
  echo "$sg"
}
sim_public_snapshot() {  # EBS snapshot shared publicly -> make it private (auto)
  local snap
  snap=$(empty_snapshot)
  ec2 modify-snapshot-attribute --snapshot-id "$snap" --attribute createVolumePermission --operation-type add --group-names all
  echo "$snap"
}
sim_s3_versioning() {  # S3 bucket versioning disabled -> monitor only
  local bucket=cdr-sim-$ACCOUNT-$SUFFIX
  aws s3api create-bucket --bucket "$bucket" --region "$REGION" >/dev/null
  aws s3api put-bucket-versioning --bucket "$bucket" --versioning-configuration Status=Enabled
  aws s3api put-bucket-versioning --bucket "$bucket" --versioning-configuration Status=Suspended
  echo "$bucket"
}
sim_public_bucket() {  # PUBLIC. S3 bucket made public through policy -> block public access (auto)
  local bucket=cdr-sim-pub-$ACCOUNT-$SUFFIX
  aws s3api create-bucket --bucket "$bucket" --region "$REGION" >/dev/null
  aws s3api delete-public-access-block --bucket "$bucket"
  aws s3api put-bucket-policy --bucket "$bucket" --policy \
    "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::${bucket}/*\"}]}"
  echo "$bucket"
}
sim_public_ami() {  # PUBLIC. AMI shared publicly -> make it private (auto)
  local snap ami
  snap=$(empty_snapshot)
  ami=$(ec2 register-image --name cdr-sim-$SUFFIX --root-device-name /dev/xvda --architecture x86_64 \
    --virtualization-type hvm --ena-support --block-device-mappings "DeviceName=/dev/xvda,Ebs={SnapshotId=$snap}" \
    --tag-specifications 'ResourceType=image,Tags=[{Key=Name,Value=cdr-sim}]' --query ImageId --output text)
  ec2 modify-image-attribute --image-id "$ami" --launch-permission 'Add=[{Group=all}]'
  echo "$ami"
}
sim_public_lambda() {  # PUBLIC. Lambda function policy allows public invoke -> set concurrency to 0 (approval)
  local dir role=cdr-sim-fn-role-$SUFFIX
  aws iam create-role --role-name $role --assume-role-policy-document \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
  dir=$(mktemp -d)
  printf 'def handler(event, context):\n    return "ok"\n' > "$dir/fn.py"
  (cd "$dir" && python3 -c "import zipfile; z = zipfile.ZipFile('fn.zip', 'w'); z.write('fn.py'); z.close()")
  sleep 10  # new roles take a moment before Lambda can use them
  aws lambda create-function --region "$REGION" --function-name cdr-sim-fn-$SUFFIX --runtime python3.12 \
    --handler fn.handler --role "arn:aws:iam::${ACCOUNT}:role/$role" --zip-file "fileb://$dir/fn.zip" >/dev/null
  aws lambda add-permission --region "$REGION" --function-name cdr-sim-fn-$SUFFIX --statement-id public \
    --action lambda:InvokeFunction --principal '*' >/dev/null
  echo "cdr-sim-fn-$SUFFIX"
}
sim_public_efs() {  # PUBLIC. EFS policy allows public access -> remove it (auto)
  local fs
  fs=$(aws efs create-file-system --region "$REGION" --tags Key=Name,Value=cdr-sim --query FileSystemId --output text)
  sleep 10
  aws efs put-file-system-policy --region "$REGION" --file-system-id "$fs" --bypass-policy-lockout-safety-check --policy \
    "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"elasticfilesystem:ClientMount\",\"Resource\":\"arn:aws:elasticfilesystem:${REGION}:${ACCOUNT}:file-system/${fs}\"}]}" >/dev/null
  echo "$fs"
}
sim_login_profile() {  # PUBLIC. Console password created for another user -> delete it (approval)
  aws iam create-user --user-name cdr-sim-login-user-$SUFFIX >/dev/null
  aws iam create-login-profile --user-name cdr-sim-login-user-$SUFFIX \
    --password "$(python3 -c 'import secrets; print(secrets.token_urlsafe(24) + "aA1!")')" --password-reset-required >/dev/null
}
sim_public_sns() {  # PUBLIC. SNS topic policy allows anyone to publish -> reset the policy (approval)
  local topic
  topic=$(aws sns create-topic --region "$REGION" --name cdr-sim-topic-$SUFFIX --query TopicArn --output text)
  aws sns set-topic-attributes --region "$REGION" --topic-arn "$topic" --attribute-name Policy --attribute-value \
    "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"SNS:Publish\",\"Resource\":\"$topic\"}]}"
  echo "$topic"
}
detector() {  # this region's GuardDuty detector, created (tagged cdr-sim) if there is none
  local d
  d=$(aws guardduty list-detectors --region "$REGION" --query 'DetectorIds[0]' --output text)
  if [ "$d" = "None" ]; then
    d=$(aws guardduty create-detector --region "$REGION" --enable --tags Name=cdr-sim --query DetectorId --output text)
  fi
  echo "$d"
}
sim_gd_suspend() {  # CONTROLS. GuardDuty detector suspended -> re-enable it (auto)
  local d
  d=$(detector)
  aws guardduty update-detector --region "$REGION" --detector-id "$d" --no-enable
  echo "$d"
}
sim_gd_ipset() {  # CONTROLS. GuardDuty trusted IP list added -> delete it (auto)
  local d bucket=cdr-sim-ipset-$ACCOUNT-$SUFFIX
  d=$(detector)
  aws s3api create-bucket --bucket "$bucket" --region "$REGION" >/dev/null
  printf '198.51.100.0/24\n' | aws s3 cp - "s3://$bucket/ips.txt" >/dev/null
  aws guardduty create-ip-set --region "$REGION" --detector-id "$d" --name cdr-sim-$SUFFIX --format TXT \
    --location "https://s3.amazonaws.com/$bucket/ips.txt" --activate --query IpSetId --output text
}

run() {
  local scenario
  for scenario in "${@:-$DEFAULT}"; do
    for scenario in $scenario; do
      echo "== $scenario"
      "sim_${scenario//-/_}"
    done
  done
}

cleanup() {
  set +e
  for u in $(aws iam list-users --query "Users[?starts_with(UserName,'cdr-sim-')].UserName" --output text); do
    for k in $(aws iam list-access-keys --user-name "$u" --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
      aws iam delete-access-key --user-name "$u" --access-key-id "$k"; done
    for p in $(aws iam list-attached-user-policies --user-name "$u" --query 'AttachedPolicies[].PolicyArn' --output text); do
      aws iam detach-user-policy --user-name "$u" --policy-arn "$p"; done
    for p in $(aws iam list-user-policies --user-name "$u" --query 'PolicyNames' --output text); do
      aws iam delete-user-policy --user-name "$u" --policy-name "$p"; done
    aws iam delete-login-profile --user-name "$u" 2>/dev/null
    aws iam delete-user --user-name "$u" && echo "deleted user $u"
  done
  for g in $(aws iam list-groups --query "Groups[?starts_with(GroupName,'cdr-sim-')].GroupName" --output text); do
    for p in $(aws iam list-attached-group-policies --group-name "$g" --query 'AttachedPolicies[].PolicyArn' --output text); do
      aws iam detach-group-policy --group-name "$g" --policy-arn "$p"; done
    for p in $(aws iam list-group-policies --group-name "$g" --query 'PolicyNames' --output text); do
      aws iam delete-group-policy --group-name "$g" --policy-name "$p"; done
    aws iam delete-group --group-name "$g" && echo "deleted group $g"
  done
  for f in $(aws lambda list-functions --region "$REGION" --query "Functions[?starts_with(FunctionName,'cdr-sim-')].FunctionName" --output text); do
    aws lambda delete-function --region "$REGION" --function-name "$f" && echo "deleted function $f"; done
  for r in $(aws iam list-roles --query "Roles[?starts_with(RoleName,'cdr-sim-')].RoleName" --output text); do
    for p in $(aws iam list-attached-role-policies --role-name "$r" --query 'AttachedPolicies[].PolicyArn' --output text); do
      aws iam detach-role-policy --role-name "$r" --policy-arn "$p"; done
    for p in $(aws iam list-role-policies --role-name "$r" --query 'PolicyNames' --output text); do
      aws iam delete-role-policy --role-name "$r" --policy-name "$p"; done
    aws iam delete-role --role-name "$r" && echo "deleted role $r"
  done
  for sg in $(ec2 describe-security-groups --filters 'Name=group-name,Values=cdr-sim-sg*' --query 'SecurityGroups[].GroupId' --output text); do
    ec2 delete-security-group --group-id "$sg" && echo "deleted $sg"; done
  for i in $(ec2 describe-images --owners self --filters Name=tag:Name,Values=cdr-sim --query 'Images[].ImageId' --output text); do
    ec2 deregister-image --image-id "$i" && echo "deregistered $i"; done
  for s in $(ec2 describe-snapshots --owner-ids self --filters Name=tag:Name,Values=cdr-sim --query 'Snapshots[].SnapshotId' --output text); do
    ec2 delete-snapshot --snapshot-id "$s" && echo "deleted $s"; done
  for v in $(ec2 describe-volumes --filters Name=tag:Name,Values=cdr-sim --query 'Volumes[].VolumeId' --output text); do
    ec2 delete-volume --volume-id "$v" && echo "deleted $v"; done
  for fs in $(aws efs describe-file-systems --region "$REGION" --query "FileSystems[?Name=='cdr-sim'].FileSystemId" --output text); do
    aws efs delete-file-system --region "$REGION" --file-system-id "$fs" && echo "deleted $fs"; done
  for t in $(aws sns list-topics --region "$REGION" --query "Topics[?contains(TopicArn,':cdr-sim-')].TopicArn" --output text); do
    aws sns delete-topic --region "$REGION" --topic-arn "$t" && echo "deleted topic $t"; done
  # Only a detector this script created; deleting it raises "GuardDuty monitoring disabled".
  for d in $(aws guardduty list-detectors --region "$REGION" --query 'DetectorIds' --output text); do
    for i in $(aws guardduty list-ip-sets --region "$REGION" --detector-id "$d" --query 'IpSetIds' --output text); do
      aws guardduty get-ip-set --region "$REGION" --detector-id "$d" --ip-set-id "$i" --query Name --output text | grep -q '^cdr-sim' &&
        aws guardduty delete-ip-set --region "$REGION" --detector-id "$d" --ip-set-id "$i" && echo "deleted IP set $i"; done
    [ "$(aws guardduty get-detector --region "$REGION" --detector-id "$d" --query 'Tags.Name' --output text)" = "cdr-sim" ] &&
      aws guardduty delete-detector --region "$REGION" --detector-id "$d" && echo "deleted detector $d"
  done
  for b in $(aws s3api list-buckets --query "Buckets[?starts_with(Name,'cdr-sim-')].Name" --output text); do
    aws s3 rb "s3://$b" --force >/dev/null && echo "deleted bucket $b"; done
}

case ${1:-} in
  run) shift; run "$@" ;;
  cleanup) cleanup ;;
  list) echo "default: $DEFAULT"; echo "PUBLIC (opt-in): $PUBLIC"; echo "CONTROLS (opt-in): $CONTROLS" ;;
  *) echo "usage: $0 run [scenario ...] | cleanup | list" >&2; exit 2 ;;
esac
