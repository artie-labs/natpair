# shaping goes into each NAT's config file, and only releases after v0.2.0
# accept it. These runs plan and apply against mock providers, so they need no
# AWS account.

mock_provider "aws" {
  # The data sources feed CIDR math and ARN-checked arguments, which reject
  # the mocks' random strings.
  override_data {
    target = data.aws_subnet.public
    values = { vpc_id = "vpc-0123456789abcdef0", cidr_block = "10.0.0.0/24" }
  }
  override_data {
    target = data.aws_vpc.this
    values = { id = "vpc-0123456789abcdef0", cidr_block_associations = [{ cidr_block = "10.0.0.0/16" }] }
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
  release_sha256           = "0000000000000000000000000000000000000000000000000000000000000000"
}

run "shaping_with_v0_2_0_fails" {
  command = plan

  variables {
    release = "v0.2.0"
    shaping = {}
  }

  expect_failures = [aws_instance.nat]
}

run "computed_shaping" {
  command = apply
  # user_data is ignored after create, so each run needs NATs of its own.
  state_key = "computed_shaping"

  variables {
    release = "v0.3.0"
    shaping = {}
  }

  assert {
    condition     = strcontains(aws_instance.nat["a"].user_data, "\"shaping\":{}")
    error_message = "the config file should hold an empty shaping, which computes the rate"
  }
}

run "set_shaping_rate" {
  command = apply
  # user_data is ignored after create, so each run needs NATs of its own.
  state_key = "set_shaping_rate"

  variables {
    release = "v0.3.0"
    shaping = { rate_mbps = 4000 }
  }

  assert {
    condition     = strcontains(aws_instance.nat["b"].user_data, "\"shaping\":{\"rate_mbps\":4000}")
    error_message = "the config file should hold the shaping rate"
  }
}

run "no_shaping" {
  command = apply
  # user_data is ignored after create, so each run needs NATs of its own.
  state_key = "no_shaping"

  variables {
    release = "v0.2.0"
  }

  assert {
    condition     = !strcontains(aws_instance.nat["a"].user_data, "shaping")
    error_message = "the config file should leave shaping out, so releases up to v0.2.0 accept it"
  }
}

run "shaping_rate_of_zero_fails" {
  command = plan

  variables {
    release = "v0.3.0"
    shaping = { rate_mbps = 0 }
  }

  expect_failures = [var.shaping]
}
