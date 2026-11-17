# The NATs' kernel line and release must agree: 6.12 and 6.18 need a release
# with threaded NAPI. These runs plan and apply against mock providers, so
# they need no AWS account.

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

# A pair that upgrades the module but keeps an older release gets the default
# kernel, 6.18.
run "default_kernel_with_v0_1_1_fails" {
  command = plan

  variables {
    release = "v0.1.1"
  }

  expect_failures = [aws_instance.nat]
}

run "kernel_6_12_with_v0_1_0_fails" {
  command = plan

  variables {
    kernel  = "6.12"
    release = "v0.1.0"
  }

  expect_failures = [aws_instance.nat]
}

run "kernel_6_1_with_v0_1_1_passes" {
  command = plan

  variables {
    kernel  = "6.1"
    release = "v0.1.1"
  }
}

run "kernel_6_18_with_later_release_passes" {
  command = apply

  variables {
    kernel  = "6.18"
    release = "v0.1.2"
  }
}

# Uses the pair the previous run applied, so its NATs already exist.
run "rollback_to_v0_1_1_on_6_18_fails" {
  command = plan

  variables {
    kernel  = "6.18"
    release = "v0.1.1"
  }

  expect_failures = [aws_instance.nat]
}
