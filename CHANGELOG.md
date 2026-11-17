# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Anyone on the internet could send traffic to each NAT's own Elastic IP,
  because one security group, open to all TCP and UDP, covered every
  interface of the pair. The host firewall dropped it, but only after the NAT
  had received it. On AWS, a flood of 1 million packets a second at a 1-vCPU
  NAT's own address made it lose its lease. Each NAT's own interface now has
  its own security group, `<name>-own`. It lets in only conntrackd's copies
  from the peer NAT and replies to what the NAT sent, so AWS drops the rest
  before it reaches the NAT. The shared ENI keeps the open group.

  AWS now tracks every connection on the NATs' own interfaces, including one
  for each worker connection on the owner, and each instance type can track
  only so many. Watch `conntrack_allowance_available`, as
  [Monitoring](docs/operations.md#monitoring) describes.

  On a running pair, the apply creates `aws_security_group.own` and swaps the
  groups on `aws_network_interface.nat` in place, with no new NATs and no
  handover. Worker traffic, conntrackd's copies and lease renewals carry on.
  The NATs' other connections to the internet that are open during the swap,
  such as Session Manager sessions, may drop and reconnect, and the standby
  may fail one own-path probe. To roll back, apply the previous module
  version, which swaps the groups back the same way.

### Fixed

- On a fresh apply, the NATs' SSM agent never came online and the Datadog
  agent install failed, because the NATs booted before their IAM policy was
  attached. Session Manager, release download and Datadog permissions are now
  in a `<name>-boot` policy attached before the NATs launch. NATs that already
  booted without them keep running without the Datadog agent, and may stay
  without Session Manager, until you
  [replace them](docs/operations.md#replace-a-nat) one at a time.
- conntrackd's copies to the peer left through the shared ENI, from the
  shared address, once that ENI was attached. Its MTU is 1500, so each copy
  of about 8.9 KB went out as 7 fragments, which counted against the NAT's
  packets-per-second allowance. Under connection churn, AWS dropped tens of
  thousands of packets a second. A host route now sends traffic to the peer
  through each NAT's own interface, from its own address. NATs set it at
  boot and at every takeover, and check it every 5 s, putting it back and
  logging a warning if it's missing or wrong. Pairs pick it up when they roll
  to a release with this fix.

## [0.1.1] - 2026-11-09

### Changed

- New NATs' root volumes are encrypted with the account's default EBS key, AWS
  managed `aws/ebs` unless the account sets another. Running NATs keep their
  volumes until you replace them. The release binary is the same as 0.1.0, so
  pairs can move to the 0.1.1 module and keep `release = "v0.1.0"`.

## [0.1.0] - 2026-11-08

### Added

- A highly available NAT for AWS: two Amazon Linux 2023 instances share one ENI
  and Elastic IP, and the standby takes the ENI over when the owner fails.
- A DynamoDB lease decides which NAT owns the ENI. A kernel fence stops a NAT
  from forwarding once its lease expires, even if the daemon is frozen or killed.
- conntrackd copies connection state to the standby, so open TCP connections
  survive a failover.
- Self-updating releases. Each pair is pinned to a release tag and the SHA-256
  of its tarball, and the NATs roll a new pin out one at a time.
- A Terraform module that deploys the whole pair into an existing VPC. You
  point your route tables at its `shared_eni_id` output, and the NATs forward
  traffic from every CIDR of the VPC unless you set `worker_cidrs`.
- Optional Datadog agent that ships natpair's logs and host metrics.

[0.1.1]: https://github.com/artie-labs/natpair/releases/tag/v0.1.1
[0.1.0]: https://github.com/artie-labs/natpair/releases/tag/v0.1.0
