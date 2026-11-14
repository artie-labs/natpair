variable "name" {
  description = "Name or name prefix for the pair's resources: the lease table, security group, IAM role and instance profile, Lambda function and Name tags. IAM names are global to the AWS account, so it must be unique in the account. Changing it replaces the lease table and security group, so don't change it on a running pair."
  type        = string
}

variable "pair_id" {
  description = "ID for this NAT pair, unique in the AWS account. Its lease records start with it, and the natpair-pair tag that scopes each NAT's EC2 permissions carries it. Don't change it on a running pair."
  type        = string
}

variable "public_subnet_id" {
  description = "Public subnet for both NATs and the shared ENI. An ENI can't move between availability zones, so the pair lives in this subnet's zone."
  type        = string
}

variable "public_route_table_id" {
  description = "Route table of the public subnet. The DynamoDB gateway endpoint is added to it."
  type        = string
}

variable "create_dynamodb_endpoint" {
  description = "Whether to add a DynamoDB gateway endpoint to the public route table. A route table can use only one, so set it to false for a second pair whose public route table already has one."
  type        = bool
  default     = true
}

variable "shared_eip_allocation_id" {
  description = "Allocation ID of the Elastic IP for the shared ENI, the address worker traffic leaves from. It must not be associated with anything else. The module associates it but never creates or releases it, so the address outlives the pair. It may come from a resource created in the same apply."
  type        = string
  nullable    = false
}

variable "worker_cidrs" {
  description = "Source CIDRs the NATs forward and translate to the shared address. Null, the default, means every CIDR of the VPC, so any subnet whose default route points at the shared ENI works. NATs read it at first boot, so changing it needs new NATs."
  type        = list(string)
  default     = null

  validation {
    condition     = var.worker_cidrs == null || length(coalesce(var.worker_cidrs, [])) > 0
    error_message = "worker_cidrs must be null or hold at least one CIDR."
  }
}

variable "instance_type" {
  description = "Arm64 instance type for both NATs. Either NAT must carry the pair's full load. Changing it stops and starts each NAT, so change one NAT per apply, the standby first."
  type        = string
}

variable "kernel" {
  description = "Amazon Linux 2023 kernel line the NATs boot: 6.1, 6.12 or 6.18. New NATs use the newest image on that line. 6.18 is the newest long-term support kernel AWS offers for Amazon Linux 2023, with the longest support ahead of it. Running NATs keep their image, so a new line applies when you replace the NATs. 6.12 and 6.18 need a release that turns on threaded NAPI, the one from this module version or later. With an older release, use 6.1."
  type        = string
  default     = "6.18"
  nullable    = false

  validation {
    condition     = contains(["6.1", "6.12", "6.18"], var.kernel)
    error_message = "kernel must be one of the Amazon Linux 2023 kernel lines: 6.1, 6.12 or 6.18."
  }
}

variable "max_connections" {
  description = "Most connections each NAT tracks and copies to its peer, a power of two from 65,536 to 4,194,304. Null uses natpair's default, 262,144. A full table costs about 80 MB per 262,144 connections in the kernel, and as much again in conntrackd. NATs read it at first boot, so changing it needs new NATs."
  type        = number
  default     = null

  validation {
    condition     = contains([65536, 131072, 262144, 524288, 1048576, 2097152, 4194304], coalesce(var.max_connections, 262144))
    error_message = "max_connections must be a power of two from 65,536 to 4,194,304."
  }
}

variable "release" {
  description = "natpair release tag the pair runs, such as v0.1.1. New NATs install it at first boot. Changing it pins a new release, which the NATs roll out to themselves one at a time."
  type        = string

  # The NATs ignore a pin the updater can't use, so the roll wouldn't start.
  validation {
    condition     = can(regex("^v[0-9]+\\.[0-9]+\\.[0-9]+$", var.release))
    error_message = "release must be a version tag such as v0.1.0."
  }
}

variable "release_url" {
  description = "Where NATs download releases from: an https:// or s3:// prefix that holds <tag>/natpair_linux_arm64.tar.gz. The default is natpair's GitHub releases. The module grants the NATs' IAM role read access to an s3:// mirror. NATs read it at first boot, so changing it needs new NATs."
  type        = string
  default     = "https://github.com/artie-labs/natpair/releases/download"

  validation {
    condition     = startswith(var.release_url, "https://") || startswith(var.release_url, "s3://")
    error_message = "release_url must start with https:// or s3://."
  }
}

variable "release_sha256" {
  description = "SHA-256 of the release's natpair_linux_arm64.tar.gz, from its checksums.txt."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.release_sha256))
    error_message = "release_sha256 must be the 64 lowercase hex digits from checksums.txt."
  }
}

variable "datadog_api_key_secret_arn" {
  description = "ARN of a Secrets Manager secret whose value is the Datadog API key alone, as plaintext. It may be in another region: NATs read it once, at first boot, so one secret can serve every pair, and changing it needs new NATs. When set, each NAT installs the Datadog agent at first boot. The agent ships natpair's logs and the host's metrics, including the connection table's size, tagged service:natpair. Null leaves the agent out."
  type        = string
  default     = null
}

variable "datadog_site" {
  description = "Datadog site the agent reports to, such as datadoghq.com or datadoghq.eu. NATs read it at first boot, so changing it needs new NATs."
  type        = string
  default     = "datadoghq.com"
}
