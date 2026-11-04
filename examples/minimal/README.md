# Minimal example

Deploys a natpair pair into an existing VPC with a new Elastic IP as the shared
address. Private subnets' default routes point at the pair.

You need:

- the VPC's public subnet ID and its route table ID
- the route table IDs and CIDRs of the private subnets that should use the pair
- a natpair release tag and the SHA-256 of its `natpair_linux_arm64.tar.gz`,
  from `checksums.txt` in that GitHub release

```sh
terraform init
terraform apply \
  -var region=us-west-2 \
  -var public_subnet_id=subnet-0123456789abcdef0 \
  -var public_route_table_id=rtb-0123456789abcdef0 \
  -var 'private_route_table_ids=["rtb-0fedcba9876543210"]' \
  -var 'private_cidrs=["10.0.16.0/20"]' \
  -var release=v0.1.0 \
  -var release_sha256=<sha256 from checksums.txt>
```

The private route tables must not already have a default route. The module
adds one to the shared ENI.
