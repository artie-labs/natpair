# The NATs need at least 2 vCPUs. These runs plan against mock providers, so
# they need no AWS account. Each run sets the vCPU count AWS reports for its
# instance type.

mock_provider "aws" {
  # The data sources feed CIDR math, which rejects the mocks' random strings.
  override_data {
    target = data.aws_subnet.public
    values = { vpc_id = "vpc-0123456789abcdef0", cidr_block = "10.0.0.0/24" }
  }
  override_data {
    target = data.aws_vpc.this
    values = { id = "vpc-0123456789abcdef0", cidr_block_associations = [{ cidr_block = "10.0.0.0/16" }] }
  }
}

mock_provider "archive" {}

variables {
  name                     = "test"
  pair_id                  = "test"
  public_subnet_id         = "subnet-0123456789abcdef0"
  public_route_table_id    = "rtb-0123456789abcdef0"
  shared_eip_allocation_id = "eipalloc-0123456789abcdef0"
  release                  = "v0.1.1"
  release_sha256           = "0000000000000000000000000000000000000000000000000000000000000000"
}

run "one_vcpu_fails" {
  command = plan

  variables {
    instance_type = "c7g.medium"
  }

  override_data {
    target = data.aws_ec2_instance_type.nat
    values = { default_vcpus = 1 }
  }

  expect_failures = [aws_instance.nat]
}

run "two_vcpus_pass" {
  command = plan

  variables {
    instance_type = "c7g.large"
  }

  override_data {
    target = data.aws_ec2_instance_type.nat
    values = { default_vcpus = 2 }
  }
}

run "four_vcpus_pass" {
  command = plan

  variables {
    instance_type = "c7gn.xlarge"
  }

  override_data {
    target = data.aws_ec2_instance_type.nat
    values = { default_vcpus = 4 }
  }
}
