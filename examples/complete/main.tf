terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  description = "AWS region of the VPC, such as us-west-2."
  type        = string
}

variable "public_subnet_id" {
  description = "Public subnet for the NATs, such as subnet-0123456789abcdef0. The pair runs in this subnet's availability zone."
  type        = string
}

variable "public_route_table_id" {
  description = "Route table of the public subnet, such as rtb-0123456789abcdef0."
  type        = string
}

variable "private_route_table_ids" {
  description = "Route tables of the private subnets that send internet traffic through the pair, such as [\"rtb-0fedcba9876543210\"]."
  type        = list(string)
}

variable "shared_eip_allocation_id" {
  description = "Allocation ID of an existing Elastic IP for the shared address, such as eipalloc-0123456789abcdef0. The module associates it but never releases it."
  type        = string
}

variable "instance_type" {
  description = "Arm64 instance type for both NATs. Either NAT must carry the pair's full load."
  type        = string
  default     = "c7gn.large"
}

variable "max_connections" {
  description = "Most connections each NAT tracks, a power of two from 65,536 to 4,194,304."
  type        = number
  default     = 1048576
}

variable "datadog_api_key_secret_arn" {
  description = "ARN of a Secrets Manager secret that holds only the Datadog API key, such as arn:aws:secretsmanager:us-west-2:111122223333:secret:datadog-api-key-AbCdEf."
  type        = string
}

variable "release" {
  description = "natpair release the NATs run, such as v0.1.1."
  type        = string
}

# Copy this from checksums.txt in the GitHub release for the tag in `release`:
# the line for natpair_linux_arm64.tar.gz.
variable "release_sha256" {
  description = "SHA-256 of the release's natpair_linux_arm64.tar.gz."
  type        = string
}

module "natpair" {
  source = "git::https://github.com/artie-labs/natpair.git//terraform?ref=v0.1.1"

  name    = "natpair-main"
  pair_id = "natpair-main"

  public_subnet_id         = var.public_subnet_id
  public_route_table_id    = var.public_route_table_id
  shared_eip_allocation_id = var.shared_eip_allocation_id

  instance_type   = var.instance_type
  max_connections = var.max_connections

  datadog_api_key_secret_arn = var.datadog_api_key_secret_arn
  datadog_site               = "datadoghq.com"

  release        = var.release
  release_sha256 = var.release_sha256
}

# Each private subnet's default route goes to the shared ENI. Moving an
# existing route here from a NAT Gateway is an in-place change.
resource "aws_route" "private_default" {
  for_each = toset(var.private_route_table_ids)

  route_table_id         = each.value
  destination_cidr_block = "0.0.0.0/0"
  network_interface_id   = module.natpair.shared_eni_id
}

output "shared_public_ip" {
  description = "The address that private subnets' traffic leaves from."
  value       = module.natpair.shared_public_ip
}

output "nat_instance_ids" {
  description = "Instance IDs of NAT a and NAT b."
  value       = module.natpair.nat_instance_ids
}
