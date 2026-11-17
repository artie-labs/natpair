# Complete example

Deploys a natpair pair into an existing VPC and sets the optional inputs:

- an existing Elastic IP as the shared address, so the address stays the same
  if you replace the pair
- `instance_type` and `max_connections` sized for more traffic
- a Secrets Manager secret holding a Datadog API key, so each NAT installs the
  Datadog agent

It also points each private route table's default route at the shared ENI.
Workers on those routes can't reach the internet until one NAT logs
`forwarding open`. It outputs the shared public IP and the two NATs' instance
IDs.

Copy `release_sha256` from `checksums.txt` in the GitHub release for the tag in
`release`. Use the line for `natpair_linux_arm64.tar.gz`.

Put your values in a `natpair.tfvars` file:

```hcl
region                     = "us-west-2"
public_subnet_id           = "subnet-0123456789abcdef0"
public_route_table_id      = "rtb-0123456789abcdef0"
private_route_table_ids    = ["rtb-0fedcba9876543210"]
shared_eip_allocation_id   = "eipalloc-0123456789abcdef0"
datadog_api_key_secret_arn = "arn:aws:secretsmanager:us-west-2:111122223333:secret:datadog-api-key-AbCdEf"
release                    = "v0.1.1"
release_sha256             = "<sha256 from checksums.txt>"
```

Then apply:

```sh
terraform init
terraform apply -var-file=natpair.tfvars
```

See [`terraform/README.md`](../../terraform/README.md) for every input.
