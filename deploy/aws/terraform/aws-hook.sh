#!/bin/sh
# Autoscaling hook for a Spawnbox primary on AWS. Install it on the primary
# as /etc/spawnbox/aws-hook.sh, and give the primary these flags:
#
#   --autoscale-hook /etc/spawnbox/aws-hook.sh --autoscale-max-workers 10
#
# It reads /etc/spawnbox/aws-hook.env (the hook_env output of the Terraform
# in this directory) and needs the AWS CLI and the primary_instance_profile.
#
# The primary may send the same request again (same ID and same join token)
# if this hook fails or a new primary takes over. So each request starts at
# most one machine: the request ID is the EC2 client token, and the subnet
# and user data depend only on the request.
#
# Optional settings in aws-hook.env for new workers:
#   SPAWNBOX_WORKER_ARGS   more flags for the worker, e.g. "--max-sandboxes 64"
#   SPAWNBOX_WORKER_SETUP  a script on the primary that each worker runs as
#                          root at boot, before Spawnbox is installed
set -eu

# shellcheck source=/dev/null
. "${SPAWNBOX_AWS_HOOK_ENV:-/etc/spawnbox/aws-hook.env}"
export AWS_REGION

# Instances of this fleet that are not terminated, matching more filters.
find_workers() {
  aws ec2 describe-instances \
    --filters "Name=tag:spawnbox-fleet,Values=$SPAWNBOX_FLEET" \
    "Name=instance-state-name,Values=pending,running,stopping,stopped" "$@" \
    --query 'Reservations[].Instances[].InstanceId' --output text
}

scale_up() {
  # The same request always picks the same subnet: EC2 refuses a client
  # token sent again with other values.
  # shellcheck disable=SC2086 # subnet IDs separated by spaces
  set -- $SPAWNBOX_SUBNETS
  n=$(printf %s "$SPAWNBOX_REQUEST_ID" | cksum | cut -d' ' -f1)
  shift $((n % $#))
  subnet=$1

  boot=$(mktemp)
  trap 'rm -f "$boot"' EXIT
  cat > "$boot" <<EOF
#!/bin/sh
set -eu
ip=\$(hostname -I | cut -d' ' -f1)
install -d -m 0755 /etc/spawnbox
(
umask 077
cat > /etc/spawnbox/spawnbox.env <<END
SPAWNBOX_ARGS="--preview-url $SPAWNBOX_PREVIEW_URL --primary $SPAWNBOX_PRIMARY_URL --node-listen \$ip:7444 --advertise https://\$ip:7444 --primary-ca-sha256 $SPAWNBOX_PRIMARY_CA_SHA256${SPAWNBOX_WORKER_ARGS:+ $SPAWNBOX_WORKER_ARGS}"
SPAWNBOX_JOIN_TOKEN=$SPAWNBOX_JOIN_TOKEN
END
)
EOF
  if [ -n "${SPAWNBOX_WORKER_SETUP:-}" ]; then
    {
      echo "cat > /etc/spawnbox/worker-setup <<'SPAWNBOX_SETUP_END'"
      cat "$SPAWNBOX_WORKER_SETUP"
      echo "SPAWNBOX_SETUP_END"
      echo "sh /etc/spawnbox/worker-setup"
    } >> "$boot"
  fi
  cat >> "$boot" <<EOF
# Downloads can fail for a while; the join token is good for 30 minutes.
for try in \$(seq 20); do
  curl -fsSL https://raw.githubusercontent.com/TulipFarm/spawnbox/main/install.sh | sh && break
  [ "\$try" -lt 20 ] || exit 1
  sleep 60
done
systemctl restart spawnbox
EOF
  tags="{Key=spawnbox-fleet,Value=$SPAWNBOX_FLEET},{Key=spawnbox-request,Value=$SPAWNBOX_REQUEST_ID}"
  aws ec2 run-instances \
    --client-token "$SPAWNBOX_REQUEST_ID" \
    --launch-template "LaunchTemplateId=$SPAWNBOX_LAUNCH_TEMPLATE" \
    --subnet-id "$subnet" \
    --tag-specifications "ResourceType=instance,Tags=[$tags]" "ResourceType=volume,Tags=[$tags]" \
    --user-data "file://$boot" \
    --query 'Instances[].InstanceId' --output text
}

scale_down() {
  # A worker from a scale-up is found by its request tag only: once it is
  # gone, a new worker can have its IP address.
  if [ -n "${SPAWNBOX_NODE_SCALE_UP:-}" ]; then
    ids=$(find_workers "Name=tag:spawnbox-request,Values=$SPAWNBOX_NODE_SCALE_UP")
  else
    ip=$(printf %s "$SPAWNBOX_NODE_URL" | sed 's|^https://||; s|:.*||')
    ids=$(find_workers "Name=private-ip-address,Values=$ip")
  fi
  if [ -z "$ids" ]; then
    echo "no instance of $SPAWNBOX_FLEET for $SPAWNBOX_NODE_ID; already stopped"
    return 0
  fi
  # shellcheck disable=SC2086 # one or more instance IDs
  aws ec2 terminate-instances --instance-ids $ids \
    --query 'TerminatingInstances[].InstanceId' --output text
}

case "${1:-}" in
scale_up) scale_up ;;
scale_down) scale_down ;;
*) echo "usage: $0 scale_up|scale_down" >&2; exit 2 ;;
esac
