# What the autoscaling hook of a Spawnbox primary needs on AWS: a launch
# template for workers, a security group, and an instance profile that lets
# the primary start workers from that template and stop only those workers.
# Refer to "Add and remove workers automatically" in the README.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source = "hashicorp/aws"
      # 6.33 adds cpu_options.nested_virtualization.
      version = ">= 6.33"
    }
  }
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

data "aws_ssm_parameter" "ubuntu" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

data "aws_subnet" "worker" {
  id = var.subnet_ids[0]
}

locals {
  arn     = "arn:aws:ec2:${var.region}:${data.aws_caller_identity.current.account_id}"
  managed = { "spawnbox-fleet" = var.fleet }
}

resource "aws_security_group" "worker" {
  name        = "${var.fleet}-worker"
  description = "Spawnbox workers of ${var.fleet}"
  vpc_id      = data.aws_subnet.worker.vpc_id
  tags        = local.managed
}

# The primary calls workers on 7444.
resource "aws_vpc_security_group_ingress_rule" "worker_from_primary" {
  security_group_id            = aws_security_group.worker.id
  referenced_security_group_id = var.primary_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 7444
  to_port                      = 7444
}

# Workers join and report to the primary on 7443.
resource "aws_vpc_security_group_ingress_rule" "primary_from_worker" {
  security_group_id            = var.primary_security_group_id
  referenced_security_group_id = aws_security_group.worker.id
  ip_protocol                  = "tcp"
  from_port                    = 7443
  to_port                      = 7443
}

# Workers download Spawnbox, images and packages.
resource "aws_vpc_security_group_egress_rule" "worker_out" {
  security_group_id = aws_security_group.worker.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_launch_template" "worker" {
  name                   = "${var.fleet}-worker"
  image_id               = var.ami_id != "" ? var.ami_id : nonsensitive(data.aws_ssm_parameter.ubuntu.value)
  instance_type          = var.instance_type
  vpc_security_group_ids = [aws_security_group.worker.id]

  # Firecracker needs /dev/kvm. C8i, M8i and R8i give it to VMs.
  cpu_options {
    nested_virtualization = "enabled"
  }

  # Only the host itself may read the metadata service, never a container
  # or a sandbox behind it. Sandboxes also cannot reach 169.254.0.0/16.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size           = var.disk_gib
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.managed, { Name = "${var.fleet}-worker" })
  }

  tag_specifications {
    resource_type = "volume"
    tags          = local.managed
  }
}

data "aws_iam_policy_document" "assume_ec2" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "primary" {
  # Start workers only from the template, tagged as this fleet.
  statement {
    sid       = "RunTaggedWorkers"
    actions   = ["ec2:RunInstances"]
    resources = ["${local.arn}:instance/*", "${local.arn}:volume/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/spawnbox-fleet"
      values   = [var.fleet]
    }
    condition {
      test     = "ArnEquals"
      variable = "ec2:LaunchTemplate"
      values   = [aws_launch_template.worker.arn]
    }
  }

  statement {
    sid     = "RunWithTheseResources"
    actions = ["ec2:RunInstances"]
    resources = concat(
      [
        aws_launch_template.worker.arn,
        aws_security_group.worker.arn,
        "${local.arn}:network-interface/*",
        "arn:aws:ec2:${var.region}::image/*",
      ],
      [for id in var.subnet_ids : "${local.arn}:subnet/${id}"],
    )
  }

  statement {
    sid       = "TagOnLaunch"
    actions   = ["ec2:CreateTags"]
    resources = ["${local.arn}:instance/*", "${local.arn}:volume/*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["RunInstances"]
    }
  }

  # Stop only workers of this fleet.
  statement {
    sid       = "TerminateFleetWorkers"
    actions   = ["ec2:TerminateInstances"]
    resources = ["${local.arn}:instance/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/spawnbox-fleet"
      values   = [var.fleet]
    }
  }

  # Describe calls cannot be limited to some resources.
  statement {
    sid       = "FindWorkers"
    actions   = ["ec2:DescribeInstances"]
    resources = ["*"]
  }
}

resource "aws_iam_role" "primary" {
  name               = "${var.fleet}-primary"
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json
}

resource "aws_iam_role_policy" "primary" {
  name   = "start-and-stop-workers"
  role   = aws_iam_role.primary.id
  policy = data.aws_iam_policy_document.primary.json
}

resource "aws_iam_instance_profile" "primary" {
  name = "${var.fleet}-primary"
  role = aws_iam_role.primary.name
}
