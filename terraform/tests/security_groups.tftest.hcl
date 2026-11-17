# Each NAT's own interface takes only conntrackd's copies and replies, and the
# shared ENI stays open so AWS doesn't track forwarded connections. These runs
# apply against mock providers, so they need no AWS account.

mock_provider "aws" {
  # The data sources feed CIDR math and ARN-checked arguments, which reject
  # the mocks' random strings.
  override_data {
    target = data.aws_subnet.public
    values = { vpc_id = "vpc-0123456789abcdef0", cidr_block = "10.0.0.0/24" }
  }
  override_data {
    target = data.aws_vpc.this
    values = { id = "vpc-0123456789abcdef0", cidr_block_associations = [{ cidr_block = "10.0.0.0/16" }, { cidr_block = "100.64.0.0/16" }] }
  }
  override_data {
    target = data.aws_region.current
    values = { region = "eu-west-2" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/test" }
  }
  mock_resource "aws_dynamodb_table" {
    defaults = { arn = "arn:aws:dynamodb:eu-west-2:123456789012:table/test" }
  }
  mock_resource "aws_lambda_function" {
    defaults = { arn = "arn:aws:lambda:eu-west-2:123456789012:function:test" }
  }
}

mock_provider "archive" {}

variables {
  name                     = "test"
  pair_id                  = "test"
  public_subnet_id         = "subnet-0123456789abcdef0"
  public_route_table_id    = "rtb-0123456789abcdef0"
  shared_eip_allocation_id = "eipalloc-0123456789abcdef0"
  instance_type            = "c7gn.medium"
  kernel                   = "6.1"
  release                  = "v0.1.1"
  release_sha256           = "0000000000000000000000000000000000000000000000000000000000000000"
}

run "security_groups" {
  command = apply

  assert {
    condition     = alltrue([for eni in aws_network_interface.nat : eni.security_groups == toset([aws_security_group.own.id])])
    error_message = "Each NAT's own interface must carry only the own group."
  }
  assert {
    condition     = aws_network_interface.shared.security_groups == toset([aws_security_group.nat.id])
    error_message = "The shared ENI must carry only the shared group."
  }

  # The own group lets in only conntrackd's copies, UDP 3780 between the own
  # interfaces and every protocol from the shared ENI, whose copies arrive as
  # IP fragments without ports, and ICMP errors from the VPC. Nothing from the
  # internet.
  assert {
    condition     = length(aws_security_group.own.ingress) == 4
    error_message = "The own group must have exactly four inbound rules."
  }
  assert {
    condition = anytrue([for rule in aws_security_group.own.ingress :
      rule.protocol == "udp" && rule.from_port == 3780 && rule.to_port == 3780 && rule.self &&
      try(length(rule.security_groups), 0) == 0 && try(length(rule.cidr_blocks), 0) == 0 &&
      try(length(rule.ipv6_cidr_blocks), 0) == 0 && try(length(rule.prefix_list_ids), 0) == 0
    ])
    error_message = "The own group must allow UDP 3780 from itself only."
  }
  assert {
    condition = anytrue([for rule in aws_security_group.own.ingress :
      rule.protocol == "-1" && !coalesce(rule.self, false) && rule.security_groups == toset([aws_security_group.nat.id]) &&
      try(length(rule.cidr_blocks), 0) == 0 && try(length(rule.ipv6_cidr_blocks), 0) == 0 && try(length(rule.prefix_list_ids), 0) == 0
    ])
    error_message = "The own group must allow every protocol from the shared group, and no CIDR."
  }
  assert {
    condition = alltrue([for type in [3, 11] : anytrue([for rule in aws_security_group.own.ingress :
      rule.protocol == "icmp" && rule.from_port == type && rule.to_port == -1 &&
      toset(rule.cidr_blocks) == toset(["10.0.0.0/16", "100.64.0.0/16"]) && !coalesce(rule.self, false) && try(length(rule.security_groups), 0) == 0
    ])])
    error_message = "The own group must allow ICMP destination unreachable and time exceeded from every VPC CIDR only."
  }
  assert {
    condition     = alltrue([for rule in aws_security_group.own.ingress : !contains(coalesce(rule.cidr_blocks, ["none"]), "0.0.0.0/0")])
    error_message = "The own group must not allow anything from the internet."
  }
  assert {
    condition     = length(aws_security_group.own.egress) == 1 && alltrue([for rule in aws_security_group.own.egress : rule.protocol == "-1" && toset(rule.cidr_blocks) == toset(["0.0.0.0/0"])])
    error_message = "The own group must allow all outbound traffic."
  }

  # The shared group allows all traffic from every VPC CIDR, and all TCP and
  # UDP from anywhere, so AWS doesn't track it.
  assert {
    condition     = length(aws_security_group.nat.ingress) == 3
    error_message = "The shared group's inbound rules changed."
  }
  assert {
    condition     = anytrue([for rule in aws_security_group.nat.ingress : rule.protocol == "-1" && toset(rule.cidr_blocks) == toset(["10.0.0.0/16", "100.64.0.0/16"])])
    error_message = "The shared group must allow all traffic from every VPC CIDR."
  }
  assert {
    condition = alltrue([for protocol in ["tcp", "udp"] : anytrue([for rule in aws_security_group.nat.ingress :
      rule.protocol == protocol && rule.from_port == 0 && rule.to_port == 65535 && toset(rule.cidr_blocks) == toset(["0.0.0.0/0"])
    ])])
    error_message = "The shared group must allow all TCP and UDP from anywhere."
  }

  # EC2 accepts only these characters in group and rule descriptions, and
  # mock providers don't check them.
  assert {
    condition = alltrue([for description in concat(
      [aws_security_group.own.description, aws_security_group.nat.description],
      [for rule in concat(tolist(aws_security_group.own.ingress), tolist(aws_security_group.own.egress), tolist(aws_security_group.nat.ingress), tolist(aws_security_group.nat.egress)) :
      rule.description == null ? "" : rule.description],
    ) : can(regex("^[a-zA-Z0-9 ._:/()#,@\\[\\]+=&;{}!$*-]*$", description))])
    error_message = "A security group or rule description has a character EC2 rejects."
  }
}
