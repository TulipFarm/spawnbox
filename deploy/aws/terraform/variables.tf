variable "region" {
  description = "AWS region of the primary and its workers"
  type        = string
}

variable "fleet" {
  description = "Name of this fleet. Workers get the tag spawnbox-fleet with this value, and the primary can stop only those."
  type        = string
  default     = "spawnbox"
}

variable "subnet_ids" {
  description = "Private subnets for workers, in the VPC of the primary"
  type        = list(string)
}

variable "primary_security_group_id" {
  description = "Security group of the primary"
  type        = string
}

variable "primary_url" {
  description = "The --fleet-listen URL of the primary, for example https://10.0.0.1:7443"
  type        = string
}

variable "preview_url" {
  description = "The --preview-url of the primary"
  type        = string
  default     = "http://{label}.localhost:8081"
}

variable "instance_type" {
  description = "Worker type. It must support nested virtualization: C8i, M8i or R8i, not metal."
  type        = string
  default     = "c8i.2xlarge"
}

variable "disk_gib" {
  description = "Worker disk size"
  type        = number
  default     = 100
}

variable "ami_id" {
  description = "Worker image. Empty for the latest Ubuntu 24.04. An image with Spawnbox already installed makes workers join faster."
  type        = string
  default     = ""
}
