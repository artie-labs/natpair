# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The default `max_connections` is 524,288, up from 262,144. Each connection
  in the table costs the owner about 1.9 KB of memory and up to 2.6 KB during
  a takeover, far more than the 160 MB per 262,144 the docs said. 524,288
  fits within half of a 4 GiB instance. NATs that leave `max_connections`
  unset move to the new default when they reboot into this release, as the
  upgrade itself does. **Before upgrading a pair whose NATs have less than
  4 GiB, such as c7gn.medium,** set `max_connections = 262144` and replace
  both NATs one at a time, as in
  [Replace a NAT](docs/operations.md#replace-a-nat), while still on the
  release they run. NATs read the setting only when they're created. See
  [Size the connection table](docs/operations.md#size-the-connection-table).
- The kernel's connection table and conntrackd's caches have one hash bucket
  per connection, up from a quarter, so lookups in a full table stay short.
  This costs about 15 MB more at 524,288.

### Fixed

- A full copy of the connection table to the standby, which happens after
  the standby's conntrackd restarts or the standby reboots, as in every
  upgrade, silently lost 13 to 31% of the connections on AWS. The standby
  still reported ready, so the next takeover reset those connections.
  conntrackd's socket buffers now hold a full copy, and it keeps every update
  until the standby acknowledges it, so it can resend the lost ones. A standby
  now counts as ready only when its copy holds at least 95% as many
  connections as the owner tracks. One that stays short for 30 s asks for a
  full copy again, and planned maintenance and upgrades wait for it. In the
  first upgrade to this release, the upgraded standby copies from an owner
  still on the old settings. The standby's larger receive buffer is what
  keeps the copy whole, so it should arrive complete, as it did in a local
  test with 250,000 connections. If the standby still isn't ready after a few
  minutes, see [Upgrade](docs/operations.md#upgrade).

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
