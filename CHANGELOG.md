# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- A full connection table cut off the NAT's own traffic: under 3,000 new
  worker connections a second, the owner's DNS lookups failed and it stepped
  down. Traffic within the NAT, its own TCP connections, its UDP with the
  VPC and with Amazon Time Sync and the Route 53 Resolver, and the peer's
  copies now skip the connection table. The host firewall accepts their replies without state,
  only on the NAT's own ephemeral ports, with rate-limited ICMP errors. The
  own canary's probes now use ports 61000 to 65535. NATs log `the connection
  table is nearly full` at 90%. NATs set this up at boot, so pairs pick it
  up when they roll to a release with this fix.
- A full connection table made the owner step down, and then the NAT that
  took over from it, because their probes need an entry in the table. A
  probe that fails while the kernel drops packets for lack of room, with the
  table at least 90% full, no longer counts as a path failure. NATs log `the
  connection table is full` and `the health probe failed because this NAT's
  connection table is full`. A takeover still needs its own probe to pass,
  so a NAT whose table fills while it loads the copies fails the takeover
  and tries again.
- A closed TCP connection now leaves the connection table after 30 s instead
  of 120 s, so the same table holds 4 times as many new connections a
  second. The NAT may then give a closed connection's address and port to a
  new one sooner, so a connection to a server that closed the old one first
  can take about 1 s longer to open. NATs set this at boot.

### Security

- The host firewall drops traffic from outside the VPC without an answer,
  instead of resetting TCP, so scans of the NAT's addresses go unanswered.
  It accepts a TCP reply to the NAT's own untracked connections only when
  one of its sockets owns it. TCP without SYN to the shared address that
  matches no tracked connection still gets a reset, so remote servers close
  connections a new owner never copied, but only on ports 1024 to 60999,
  and at most 50 at once and then 10 a second for each remote address.
  Worker TCP is now translated to those ports on the shared address. The
  VPC and the peer still get resets from closed ports.

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
