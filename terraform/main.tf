# One natpair NAT pair: both NAT instances, the shared ENI and its Elastic
# IP, the lease table, the NATs' IAM role, the probe receiver, and a private
# DynamoDB path. Callers point their route tables' default routes at the
# shared ENI (the shared_eni_id output), so moving a route to the pair is one
# in-place change. The NATs run stock Amazon Linux 2023
# and install the pinned natpair release at first boot.
#
# To upgrade, change release and release_sha256. The apply only rewrites the
# pinned release in the lease table, and natpair on each NAT moves the
# pair to it: the standby first, then a handover, then the old owner.
# Instances ignore changes to their image and boot script, including the
# configuration it writes, so an apply never replaces a serving NAT by
# surprise. Changing those needs replacements, as docs/operations.md describes.

data "aws_region" "current" {}

data "aws_subnet" "public" {
  id = var.public_subnet_id
}

data "aws_vpc" "this" {
  id = data.aws_subnet.public.vpc_id
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-kernel-*-arm64"]
  }
}

locals {
  peer = { a = "b", b = "a" }
  # Every CIDR of the VPC unless the caller narrows it, so a new private subnet
  # needs no change to the NATs.
  vpc_cidrs        = sort([for association in data.aws_vpc.this.cidr_block_associations : association.cidr_block])
  worker_cidrs     = coalesce(var.worker_cidrs, local.vpc_cidrs)
  shared_public_ip = data.aws_eip.shared.public_ip
  # Each NAT reads and writes only its pair's lease record and the board where
  # the NATs post health reports. The key format must match
  # config.NAT.LeaseRecordID in the Go code.
  lease_key   = "${var.pair_id}/v3/ownership"
  board_key   = "${var.pair_id}/v3/health"
  release_key = "${var.pair_id}/v3/release"
  # pair_tag marks the pair's NATs, which may attach and detach the shared ENI.
  pair_tag = "natpair-pair"
  table_access = {
    Effect   = "Allow"
    Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"]
    Resource = aws_dynamodb_table.lease.arn
    Condition = {
      "ForAllValues:StringEquals" = {
        "dynamodb:LeadingKeys" = [local.lease_key, local.board_key]
      }
    }
  }
  # The NATs only read the release Terraform pins for them.
  release_record_access = {
    Effect   = "Allow"
    Action   = "dynamodb:GetItem"
    Resource = aws_dynamodb_table.lease.arn
    Condition = {
      "ForAllValues:StringEquals" = {
        "dynamodb:LeadingKeys" = [local.release_key]
      }
    }
  }
  # The only EC2 changes are attaching and detaching the shared ENI on the NATs.
  # Reading instances tells a forced detach from a stopping instance, which
  # needs no action, from one that does.
  #
  # The NATs are allowed by their pair tag, not by instance ARN. With ARNs,
  # replacing a NAT with -target would leave the policy naming the old
  # instance, so no NAT could attach the shared ENI until a full apply.
  ec2_access = [
    {
      Effect    = "Allow"
      Action    = ["ec2:DescribeNetworkInterfaces", "ec2:DescribeInstances"]
      Resource  = "*"
      Condition = { StringEquals = {} }
    },
    {
      Effect    = "Allow"
      Action    = ["ec2:AttachNetworkInterface", "ec2:DetachNetworkInterface"]
      Resource  = aws_network_interface.shared.arn
      Condition = { StringEquals = {} }
    },
    {
      Effect    = "Allow"
      Action    = ["ec2:AttachNetworkInterface", "ec2:DetachNetworkInterface"]
      Resource  = "arn:aws:ec2:*:*:instance/*"
      Condition = { StringEquals = { "aws:ResourceTag/${local.pair_tag}" = var.pair_id } }
    },
  ]
  # The NATs may call the probe receiver, which requires IAM authentication.
  receiver_access = {
    Effect   = "Allow"
    Action   = ["lambda:InvokeFunctionUrl", "lambda:InvokeFunction"]
    Resource = aws_lambda_function.receiver.arn
  }
  # Releases from an S3 mirror need read access to it. GitHub releases need none.
  release_access = startswith(var.release_url, "s3://") ? [{
    Effect   = "Allow"
    Action   = "s3:GetObject"
    Resource = "arn:aws:s3:::${trimsuffix(trimprefix(var.release_url, "s3://"), "/")}/*"
  }] : []
  # Session Manager gives an engineer a shell on a NAT, which runs no SSH
  # server and refuses connections from outside the VPC. These are the agent's
  # own permissions. Who may open a session is up to each engineer's IAM access.
  session_access = {
    Effect = "Allow"
    Action = [
      "ssm:UpdateInstanceInformation",
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ]
    Resource = "*"
  }
  # With Datadog, the NATs read its API key at first boot. A secret encrypted
  # with AWS's own aws/secretsmanager key needs no KMS permission.
  datadog_access = var.datadog_api_key_secret_arn == null ? [] : [{
    Effect   = "Allow"
    Action   = "secretsmanager:GetSecretValue"
    Resource = var.datadog_api_key_secret_arn
  }]
}

# Network

# NATs take worker traffic and copy connections to each other with conntrackd.
resource "aws_security_group" "nat" {
  name        = var.name
  description = "natpair NAT pair ${var.pair_id}"
  vpc_id      = data.aws_vpc.this.id

  # A new description would replace the group while the NATs use it.
  lifecycle {
    ignore_changes = [description]
  }

  # Every CIDR of the VPC, so workers in a secondary CIDR can reach the NATs.
  ingress {
    description = "Worker traffic and replication from inside the VPC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = local.vpc_cidrs
  }

  # With all TCP and UDP open in both directions, AWS doesn't track connections
  # through the NATs. Tracked state stays on the host that held the shared ENI,
  # so after a takeover AWS would drop the replies to copied connections. Each
  # NAT's host firewall drops new connections to its own services from outside
  # the VPC.
  ingress {
    description = "Replies to connections the NATs forward, untracked"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Replies to connections the NATs forward, untracked"
    from_port   = 0
    to_port     = 65535
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Each NAT's primary interface is created first, so each NAT's configuration
# can name its peer's address.
resource "aws_network_interface" "nat" {
  for_each = local.peer

  subnet_id         = var.public_subnet_id
  security_groups   = [aws_security_group.nat.id]
  source_dest_check = false
  tags              = { Name = "${var.name}-nat-${each.key}" }
}

# Each NAT's own public address, for its own traffic, such as first-boot
# downloads and own-path probes.
resource "aws_eip" "nat" {
  for_each = local.peer

  domain            = "vpc"
  network_interface = aws_network_interface.nat[each.key].id
  tags              = { Name = "${var.name}-nat-${each.key}" }
}

# The worker route target, carrying the shared Elastic IP. natpair moves it
# between the NATs.
resource "aws_network_interface" "shared" {
  subnet_id         = var.public_subnet_id
  security_groups   = [aws_security_group.nat.id]
  source_dest_check = false
  tags              = { Name = "${var.name}-shared" }

  lifecycle {
    ignore_changes = [attachment]
  }
}

data "aws_eip" "shared" {
  id = var.shared_eip_allocation_id
}

# The apply fails rather than take an address that's already associated with
# something else.
resource "aws_eip_association" "shared" {
  allocation_id        = var.shared_eip_allocation_id
  network_interface_id = aws_network_interface.shared.id
  allow_reassociation  = false
}

# Lease renewals and health reports reach DynamoDB without depending on the
# internet path the NATs forward. Only the public route table, where the NATs
# live, gets it, so workers' DynamoDB traffic keeps leaving from the shared
# address. A route table can use only one DynamoDB gateway endpoint, so a
# second pair on the same public route table sets create_dynamodb_endpoint to
# false and uses the first pair's. The endpoint keeps the default policy, so
# anything else on the public subnet can keep using DynamoDB. The NAT policy
# already limits what natpair can do.
resource "aws_vpc_endpoint" "dynamodb" {
  count = var.create_dynamodb_endpoint ? 1 : 0

  vpc_id            = data.aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [var.public_route_table_id]
}

# NATs

resource "aws_instance" "nat" {
  for_each = local.peer

  ami                  = data.aws_ami.al2023.id
  instance_type        = var.instance_type
  iam_instance_profile = aws_iam_instance_profile.nat.name
  user_data = templatefile("${path.module}/boot.sh.tftpl", {
    release        = var.release
    release_sha256 = var.release_sha256
    release_url    = trimsuffix(var.release_url, "/")
    datadog_secret = var.datadog_api_key_secret_arn == null ? "" : var.datadog_api_key_secret_arn
    datadog_site   = var.datadog_site
    pair           = var.pair_id
    config = jsonencode(merge({
      lease_table      = aws_dynamodb_table.lease.name
      pair             = var.pair_id
      shared_eni       = aws_network_interface.shared.id
      shared_address   = "${aws_network_interface.shared.private_ip}/${split("/", data.aws_subnet.public.cidr_block)[1]}"
      shared_public_ip = local.shared_public_ip
      protected_cidrs  = local.worker_cidrs
      probe_url        = aws_lambda_function_url.receiver.function_url
      peer_ip          = aws_network_interface.nat[local.peer[each.key]].private_ip
      release_url      = trimsuffix(var.release_url, "/")
    }, var.max_connections == null ? {} : { max_connections = var.max_connections }))
  })

  primary_network_interface {
    network_interface_id = aws_network_interface.nat[each.key].id
  }

  metadata_options {
    http_tokens = "required"
  }

  # Encrypted with the account's default EBS key, the AWS managed aws/ebs
  # unless the account sets another. EC2 uses the key on behalf of whoever
  # launches the NAT, so their KMS permissions apply.
  root_block_device {
    volume_type = "gp3"
    encrypted   = true
  }

  tags = { Name = "${var.name}-nat-${each.key}", (local.pair_tag) = var.pair_id }

  # The NATs boot once the shared ENI has its address, so the first takeover
  # doesn't wait for it, and once they may use what they need while booting.
  depends_on = [aws_eip_association.shared, aws_iam_role_policy.nat_boot]

  lifecycle {
    # source_dest_check belongs to the primary interface, which turns it off.
    # The provider rejects setting it here alongside primary_network_interface,
    # and its default, true, would otherwise turn checking back on at the next
    # apply and drop replies to workers.
    # Changing the root volume replaces the NAT, so existing NATs keep theirs
    # until they're replaced on purpose.
    ignore_changes = [ami, user_data, source_dest_check, root_block_device]
  }
}

resource "aws_dynamodb_table" "lease" {
  name         = var.name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "lease_id"

  attribute {
    name = "lease_id"
    type = "S"
  }

  # false keeps the table encrypted with an AWS owned key, which needs no KMS
  # calls. A key in the account, even AWS managed aws/dynamodb, makes every
  # read call KMS as the caller, so the caller's KMS policies apply too.
  server_side_encryption {
    enabled = false
  }

  # No point-in-time recovery: restoring an old lease record would be harmful.
  # Never enable TTL: deleting a record would let a new owner skip the takeover wait.
}

# The release the NATs should run. natpair on each NAT reads it and rolls
# the pair to it, one NAT at a time. The key format must match
# config.ReleaseRecord in the Go code.
resource "aws_dynamodb_table_item" "release" {
  table_name = aws_dynamodb_table.lease.name
  hash_key   = aws_dynamodb_table.lease.hash_key
  item = jsonencode({
    lease_id = { S = local.release_key }
    value    = { S = jsonencode({ release = var.release, sha256 = var.release_sha256 }) }
  })
}

# Each pair gets its own role, so the role lives in the same account and stack
# as the NATs that use it.
resource "aws_iam_role" "nat" {
  name = var.name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_instance_profile" "nat" {
  name = var.name
  role = aws_iam_role.nat.name
}

resource "aws_iam_role_policy" "nat" {
  name = var.name
  role = aws_iam_role.nat.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([local.table_access, local.release_record_access, local.receiver_access], [for statement in local.ec2_access : merge(statement, {
      Condition = { StringEquals = merge(statement.Condition.StringEquals, { "aws:RequestedRegion" = data.aws_region.current.region }) }
    })])
  })

  # Applied after the NATs, so they carry the pair tag before the policy relies
  # on it. The daemon retries until it applies.
  depends_on = [aws_instance.nat]
}

# What a NAT needs while it boots, attached before the NATs launch: Session
# Manager, the release download and the Datadog key. On a fresh apply, the SSM
# agent that started without these permissions never came online, and the
# Datadog install, which doesn't retry, failed.
resource "aws_iam_role_policy" "nat_boot" {
  name   = "${var.name}-boot"
  role   = aws_iam_role.nat.id
  policy = jsonencode({ Version = "2012-10-17", Statement = concat([local.session_access], local.release_access, local.datadog_access) })
}

# The probe receiver is a Lambda function behind a function URL that requires
# IAM authentication. AWS runs it across availability zones, so there is no
# host to maintain. If the receiver is down, a standby still takes over as a
# last resort when the owner fails.
data "archive_file" "receiver" {
  type        = "zip"
  source_file = "${path.module}/receiver/index.mjs"
  output_path = "${path.root}/.terraform/${var.name}-receiver.zip"
}

resource "aws_iam_role" "receiver" {
  name = "${var.name}-receiver"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_lambda_function" "receiver" {
  function_name    = "${var.name}-receiver"
  role             = aws_iam_role.receiver.arn
  runtime          = "nodejs24.x"
  architectures    = ["arm64"]
  handler          = "index.handler"
  filename         = data.archive_file.receiver.output_path
  source_code_hash = data.archive_file.receiver.output_base64sha256
  memory_size      = 128
  timeout          = 3
}

resource "aws_lambda_function_url" "receiver" {
  function_name      = aws_lambda_function.receiver.function_name
  authorization_type = "AWS_IAM"
}
