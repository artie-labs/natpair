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

variable "private_cidrs" {
  description = "CIDRs of the private subnets, such as [\"10.0.16.0/20\"]."
  type        = list(string)
}

variable "release" {
  description = "natpair release the NATs run, such as v0.1.0."
  type        = string
}

# Copy this from checksums.txt in the GitHub release for the tag in `release`:
# the line for natpair_linux_arm64.tar.gz.
variable "release_sha256" {
  description = "SHA-256 of the release's natpair_linux_arm64.tar.gz."
  type        = string
}

# The address that private subnets' traffic leaves from. It is a separate
# resource so it outlives the pair.
resource "aws_eip" "shared" {
  domain = "vpc"

  tags = {
    Name = "natpair-shared"
  }
}

module "natpair" {
  source = "git::https://github.com/artie-labs/natpair.git//terraform?ref=v0.1.0"

  name    = "natpair"
  pair_id = "natpair"

  public_subnet_id         = var.public_subnet_id
  public_route_table_id    = var.public_route_table_id
  shared_eip_allocation_id = aws_eip.shared.allocation_id
  worker_route_table_ids   = var.private_route_table_ids
  worker_cidrs             = var.private_cidrs

  instance_type = "c7gn.medium"

  release        = var.release
  release_sha256 = var.release_sha256
}

output "shared_public_ip" {
  description = "The address that private subnets' traffic leaves from."
  value       = module.natpair.shared_public_ip
}
