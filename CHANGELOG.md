# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The module's new `kernel` input pins the Amazon Linux 2023 kernel line the
  NATs boot, 6.18 by default. The image lookup picked whichever line AWS
  published last, so new NATs booted 6.1, 6.12 or 6.18 depending on the day.
  Running NATs keep their image. Replaced NATs boot the pinned line. Linux
  6.5 and later, so 6.12 and 6.18, need a `release` from this version or
  later, which turns on threaded NAPI. A pair that keeps `release` at v0.1.0
  or v0.1.1 must set `kernel = "6.1"`, or `terraform plan` fails.

### Fixed

- On Linux 6.5 and later, such as the Amazon Linux 2023 6.18 kernel, a NAT
  whose forwarding filled its CPU did that forwarding inside its daemon's
  system calls, so its lease renewals and DNS lookups timed out. The daemon
  now turns on threaded NAPI for every ENI, so receive processing runs in
  kernel threads that the scheduler shares with the daemon. It does this at
  start, when the shared ENI comes up during a takeover, and every 5 s. Each
  forwarded packet costs 4 to 7.5% more CPU below saturation. On Linux 6.1,
  which doesn't have the problem, that cost buys nothing.
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
  connection table is full`. Such a probe no longer fails a takeover either,
  so a NAT whose table fills while it loads the copies still opens
  forwarding once its upload through the shared Elastic IP passes. Two
  failed rounds count as in a row only if at most two such rounds came
  between them.
- An owner that got more traffic than it could forward stepped down, the NAT
  that took over saturated and stepped down too, and the pair moved 2 to 4
  times a minute, pausing forwarding for about 10 s each time. When a loaded
  owner's upload times out, it now tries 40 TCP handshakes through the shared
  Elastic IP, and if some but not all complete, the path is congested and the
  round doesn't count as a path failure. A NAT taking over accepts a congested
  shared path by the same check. So that a fault on a loaded owner can't hold it, an owner
  hands over to a standby that has proven its own path once it has served 10
  minutes with at least half of its health rounds congested or failed, and a
  new owner must serve 10 minutes first. NATs log `the health probe failed,
  but the path is alive` and `handing over because at least half of this
  NAT's health rounds in the last 10 minutes were congested or failed`.
- A closed TCP connection now leaves the connection table after 30 s instead
  of 120 s, so the same table holds 4 times as many new connections a
  second. The NAT may then give a closed connection's address and port to a
  new one sooner, so a connection to a server that closed the old one first
  can take about 1 s longer to open. NATs set this at boot.
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
