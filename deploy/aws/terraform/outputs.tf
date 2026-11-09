output "primary_instance_profile" {
  description = "Attach this to the primary instance"
  value       = aws_iam_instance_profile.primary.name
}

output "hook_env" {
  description = "Put this in /etc/spawnbox/aws-hook.env on the primary"
  value       = <<-EOT
    AWS_REGION=${var.region}
    SPAWNBOX_FLEET=${var.fleet}
    SPAWNBOX_LAUNCH_TEMPLATE=${aws_launch_template.worker.id}
    SPAWNBOX_SUBNETS="${join(" ", var.subnet_ids)}"
    SPAWNBOX_PRIMARY_URL=${var.primary_url}
    SPAWNBOX_PREVIEW_URL=${var.preview_url}
    SPAWNBOX_WORKER_ARGS="${var.worker_args}"
  EOT
}
