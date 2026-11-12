# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Traffic pacing, off by default. With the module's `pacing` input on, each
  NAT paces forwarded worker traffic just under the instance's network
  allowances, so AWS doesn't drop packets at random, and a worker that sends
  too much slows to its fair share. Traffic the NAT sends itself, such as
  lease renewals and connection copies, is never paced. The NAT learns the
  allowances from the ENA driver's allowance counters, read every 10 ms on
  every interface, and also keeps forwarded packets a second below what the
  CPUs can carry, so a NAT never runs out of CPU and steps down.
  `natpair pacing-off` and `pacing-on` turn it off and on without a restart.

### Changed

- natpair spreads the ENA queue interrupts across the CPUs, queue n on CPU n,
  and the install script turns irqbalance off. irqbalance could put all of an
  interface's queues on one CPU, so a two-CPU NAT forwarded with one. On a
  c7gn.large that was 9.6 Gbps instead of 14.7.
- NATs install the `iproute-tc` package, which pacing needs.

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
