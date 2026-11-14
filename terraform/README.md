# natpair Terraform module

This module deploys one natpair pair into an existing VPC. It creates two arm64
NAT instances on Amazon Linux 2023 in the public subnet's availability zone,
each with its own ENI and Elastic IP, plus the shared ENI that moves between
them. It also creates the DynamoDB lease table, the NATs' IAM role and security
group, a DynamoDB gateway endpoint, and a Lambda function URL that the NATs
send health probes to. It associates the Elastic IP you pass in with the shared
ENI. You point each private route table's default route at that ENI, the
`shared_eni_id` output. NATs install the pinned natpair release at first boot
and check it against `release_sha256`.

## Usage

```hcl
resource "aws_eip" "shared" {
  domain = "vpc"
}

module "natpair" {
  source = "git::https://github.com/artie-labs/natpair.git//terraform?ref=v0.1.1"

  name    = "natpair"
  pair_id = "natpair"

  public_subnet_id         = "subnet-0123456789abcdef0"
  public_route_table_id    = "rtb-0123456789abcdef0"
  shared_eip_allocation_id = aws_eip.shared.allocation_id

  instance_type = "c7gn.medium"

  release = "v0.1.1"
  # From checksums.txt in the v0.1.1 GitHub release, the line for
  # natpair_linux_arm64.tar.gz.
  release_sha256 = "<64 hex digits>"
}

resource "aws_route" "private_default" {
  route_table_id         = "rtb-0fedcba9876543210"
  destination_cidr_block = "0.0.0.0/0"
  network_interface_id   = module.natpair.shared_eni_id
}
```

See [`examples/`](../examples) for complete configurations.

## Resources

- 2 EC2 instances, `<name>-nat-a` and `<name>-nat-b`, each with its own ENI
  and Elastic IP
- the shared ENI, `<name>-shared`, and the association of your Elastic IP
  with it
- a security group, `<name>`
- a DynamoDB gateway endpoint on the public route table, unless
  `create_dynamodb_endpoint` is false
- a DynamoDB table, `<name>`, with on-demand billing, and the item that pins
  the release
- an IAM role, instance profile and policy for the NATs, `<name>`
- the probe receiver: a Lambda function, `<name>-receiver`, its IAM role and a
  function URL that requires IAM authentication

## What the NATs may do

The NATs' IAM policy allows only:

| Permission | Scope | Why |
| --- | --- | --- |
| `dynamodb:GetItem`, `PutItem`, `UpdateItem` | The pair's lease and health records in its table | The lease and health reports |
| `dynamodb:GetItem` | The pair's pinned release record | Self-update |
| `ec2:AttachNetworkInterface`, `DetachNetworkInterface` | The shared ENI, and instances tagged `natpair-pair = <pair_id>`, in the pair's region | Moving the shared ENI |
| `ec2:DescribeNetworkInterfaces`, `DescribeInstances` | All, in the pair's region | Seeing where the shared ENI is attached |
| `lambda:InvokeFunctionUrl`, `InvokeFunction` | The probe receiver | Health probes |
| `ssm:UpdateInstanceInformation`, `ssmmessages:*Channel` | All | Session Manager shells |
| `s3:GetObject` | The `release_url` prefix, only when it starts with `s3://` | Downloading releases from your bucket |
| `secretsmanager:GetSecretValue` | `datadog_api_key_secret_arn`, only when set | The Datadog agent's API key |

The policy is attached after the NATs are created, so it can rely on their
tag. A NAT that boots before then logs `AccessDenied` errors and retries until
the policy applies. They need no action.

## Requirements

| Name | Version |
| --- | --- |
| terraform | >= 1.6.0 |
| aws | ~> 6.0 |
| archive | ~> 2.0 |

## Inputs

| Name | Description | Type | Default | Required |
| --- | --- | --- | --- | :---: |
| `instance_type` | Arm64 instance type for both NATs. Either NAT must carry the pair's full load. Changing it stops and starts each NAT, so change one NAT per apply, the standby first. | `string` | n/a | yes |
| `name` | Name or name prefix for the pair's resources: the lease table, security group, IAM role and instance profile, Lambda function and Name tags. IAM names are global to the AWS account, so it must be unique in the account. Changing it replaces the lease table and security group, so don't change it on a running pair. | `string` | n/a | yes |
| `pair_id` | ID for this NAT pair, unique in the AWS account. Its lease records start with it, and the natpair-pair tag that scopes each NAT's EC2 permissions carries it. Don't change it on a running pair. | `string` | n/a | yes |
| `public_route_table_id` | Route table of the public subnet. The DynamoDB gateway endpoint is added to it. | `string` | n/a | yes |
| `public_subnet_id` | Public subnet for both NATs and the shared ENI. An ENI can't move between availability zones, so the pair lives in this subnet's zone. | `string` | n/a | yes |
| `release` | natpair release tag the pair runs, such as v0.1.1. New NATs install it at first boot. Changing it pins a new release, which the NATs roll out to themselves one at a time. | `string` | n/a | yes |
| `release_sha256` | SHA-256 of the release's natpair_linux_arm64.tar.gz, from its checksums.txt. | `string` | n/a | yes |
| `shared_eip_allocation_id` | Allocation ID of the Elastic IP for the shared ENI, the address worker traffic leaves from. It must not be associated with anything else. The module associates it but never creates or releases it, so the address outlives the pair. It may come from a resource created in the same apply. | `string` | n/a | yes |
| `create_dynamodb_endpoint` | Whether to add a DynamoDB gateway endpoint to the public route table. A route table can use only one, so set it to false for a second pair whose public route table already has one. | `bool` | `true` | no |
| `datadog_api_key_secret_arn` | ARN of a Secrets Manager secret whose value is the Datadog API key alone, as plaintext. It may be in another region: NATs read it once, at first boot, so one secret can serve every pair, and changing it needs new NATs. When set, each NAT installs the Datadog agent at first boot. The agent ships natpair's logs and the host's metrics, including the connection table's size, tagged service:natpair. Null leaves the agent out. | `string` | `null` | no |
| `datadog_site` | Datadog site the agent reports to, such as datadoghq.com or datadoghq.eu. NATs read it at first boot, so changing it needs new NATs. | `string` | `"datadoghq.com"` | no |
| `kernel` | Amazon Linux 2023 kernel line the NATs boot: 6.1, 6.12 or 6.18. New NATs use the newest image on that line. 6.18 is the newest long-term support kernel AWS offers for Amazon Linux 2023, with the longest support ahead of it. Running NATs keep their image, so a new line applies when you replace the NATs. 6.12 and 6.18 need a release that turns on threaded NAPI, the one from this module version or later. With an older release, use 6.1. | `string` | `"6.18"` | no |
| `max_connections` | Most connections each NAT tracks and copies to its peer, a power of two from 65,536 to 4,194,304. Null uses natpair's default, 262,144. A full table costs about 80 MB per 262,144 connections in the kernel, and as much again in conntrackd. NATs read it at first boot, so changing it needs new NATs. | `number` | `null` | no |
| `release_url` | Where NATs download releases from: an https:// or s3:// prefix that holds &lt;tag&gt;/natpair_linux_arm64.tar.gz. The default is natpair's GitHub releases. The module grants the NATs' IAM role read access to an s3:// mirror. NATs read it at first boot, so changing it needs new NATs. | `string` | `"https://github.com/artie-labs/natpair/releases/download"` | no |
| `worker_cidrs` | Source CIDRs the NATs forward and translate to the shared address. Null, the default, means every CIDR of the VPC, so any subnet whose default route points at the shared ENI works. NATs read it at first boot, so changing it needs new NATs. | `list(string)` | `null` | no |

## Outputs

| Name | Description |
| --- | --- |
| `nat_instance_ids` | Instance IDs of NAT a and NAT b. |
| `nat_public_ips` | Each NAT's own Elastic IP, which its own-path probes leave from. |
| `receiver_url` | Probe receiver URL. The NATs sign their uploads to it with their role's credentials. |
| `shared_eni_id` | The shared ENI that moves between the NATs. Point each private route table's 0.0.0.0/0 route at it. |
| `shared_public_ip` | The shared Elastic IP that worker traffic leaves through. |
| `table_name` | Lease table name. |
