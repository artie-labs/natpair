# Minimal example

Deploys a natpair pair into an existing VPC with a new Elastic IP as the shared
address. Private subnets' default routes point at the pair.

You need:

- the VPC's public subnet ID and its route table ID
- the route table IDs of the private subnets that should use the pair
- a natpair release tag and the SHA-256 of its `natpair_linux_arm64.tar.gz`,
  from `checksums.txt` in that GitHub release

```sh
terraform init
terraform apply \
  -var region=us-west-2 \
  -var public_subnet_id=subnet-0123456789abcdef0 \
  -var public_route_table_id=rtb-0123456789abcdef0 \
  -var 'private_route_table_ids=["rtb-0fedcba9876543210"]' \
  -var release=v0.1.1 \
  -var release_sha256=<sha256 from checksums.txt>
```

The example adds a default route to the shared ENI in each private route
table, so those tables must not already have one. If they point at a NAT
Gateway today, change those routes' `nat_gateway_id` to
`network_interface_id = module.natpair.shared_eni_id` instead, which updates
them in place.
