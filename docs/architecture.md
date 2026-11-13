# How natpair works

natpair is two NAT instances, A and B, in one public subnet. Private subnets
route their internet traffic to a third network interface, the **shared ENI**,
which carries the pair's Elastic IP. Whichever NAT holds the shared ENI
forwards. That NAT is the **owner**. The other is the **standby**.

```mermaid
flowchart LR
  subgraph vpc["VPC"]
    subgraph private["Private subnets"]
      workers@{ shape: procs, label: "Your instances and pods" }
    end
    subgraph public["Public subnet, one availability zone"]
      eni["Shared ENI<br/>shared Elastic IP"]
      a["NAT A, owner<br/>natpair + conntrackd"]
      b["NAT B, standby<br/>natpair + conntrackd"]
    end
  end
  dynamo[("DynamoDB<br/>lease, health reports,<br/>pinned release")]
  receiver["Probe receiver<br/>Lambda function URL"]
  internet["Internet"]

  workers -->|default route| eni
  eni -->|attached| a
  eni -.->|moves on takeover| b
  a <-->|copies connections| b
  a -->|from the shared Elastic IP| internet
  a & b -.->|test uploads| receiver
  a & b -->|lease, reports| dynamo
```

The Terraform module in [`terraform/`](../terraform) creates all of it: both
NATs, the shared ENI and its Elastic IP association, the DynamoDB table, the
NATs' IAM role, the probe receiver and a DynamoDB gateway endpoint. You point
the private subnets' default routes at the shared ENI.

## Who owns the shared ENI: the lease

One DynamoDB item, the lease, records the owner.

- The owner renews the lease every 0.5 s with a conditional write. Each
  successful renewal lets it forward for the next 4 s.
- The standby may take the lease only after the item has stayed unchanged for
  6 s. Because 6 s is longer than 4 s, the old owner has always stopped
  forwarding before the standby starts.
- An owner that stops on purpose releases the lease, so the standby takes over
  on its next check instead of waiting 6 s.

## Stopping a NAT that can't renew: the fence

A small BPF program in the kernel checks every forwarded packet against the
end of the owner's current 4 s. After that, the kernel drops private-subnet
traffic, even if the natpair daemon has crashed, hung or been killed. So two
NATs never forward at the same time, and a frozen owner can't keep traffic
going to the wrong place.

## Keeping connections across a takeover: conntrackd

Each NAT runs conntrackd, which copies the owner's connection table to the
standby as connections open and close. When the standby takes over, it loads
those copies, so established TCP connections keep their source address and
port and carry on. Only TCP over IPv4 is copied. The copies always travel
between the NATs' own interfaces and addresses, never through the shared
ENI.

A connection the new owner doesn't know gets a TCP reset instead of silence,
so the client reconnects at once rather than waiting for its own timeout.

## Checking the path: probes

The daemon checks that traffic actually gets out, not just that the instance
is up.

- **The owner** uploads 4 KiB over HTTPS through the shared Elastic IP every
  second. The probe receiver, a Lambda function URL that requires IAM
  authentication, sends the upload back, so large packets are tested in both
  directions.
- **The standby** checks its own path every 5 s through its own Elastic IP,
  and checks that its copy of the connection table holds the owner's recent
  probe connections and the owner's 16 oldest connections.
- Each NAT writes a short report to DynamoDB after every round, so the peer
  can see it.

An owner steps down after two failed rounds, but only once the standby has
proved its own path. So a failure that affects both, such as the receiver
being down, never makes a healthy owner step down. If the owner also crashes
during such a failure, the standby still takes over, about 2 s later than
usual.

A round whose upload failed while the NAT's connection table was full
doesn't count as failed. The kernel dropped the upload's new connection, as
it drops new worker connections, and the standby would load the same copied
table on taking over and fail the same way. Full means the kernel dropped
packets it couldn't track since the last round while the table was at least
90% full.

## Taking over

When the standby takes the lease, it:

1. loads the copied connections,
2. moves the shared ENI to itself, forcing the detach after 15 s if the old
   owner doesn't let go,
3. checks an upload through the shared Elastic IP,
4. and only then opens its fence and starts forwarding.

## Upgrading itself

The pinned release lives in the same DynamoDB table. Every minute each NAT
compares it with the release it runs.

1. The standby downloads the pinned release, checks its SHA-256, installs it
   and reboots into it. It does this only while the owner serves with a
   working path.
2. Once the standby has run the new release and stayed ready for 2 minutes,
   the owner hands over, as in planned maintenance.
3. The old owner, now the standby, installs the release and reboots.

A release that never gets ready stays on the standby, so traffic stays on the
old release. See [operations](operations.md#upgrade) for the steps.

## Staying responsive at full load

Worker traffic in both directions arrives on the shared ENI: uploads from the
workers, and replies from the internet to the shared Elastic IP. The NAT's
primary interface receives only its own traffic, such as lease and AWS API
replies, DNS answers and the peer's connection copies. Downloads to the
workers leave through the primary interface, but sending costs far less than
receiving and forwarding.

By default Linux processes received packets in softirq context, which runs
ahead of every process. A NAT whose forwarding fills the CPU then has no time
left for its own work. On AWS, a one-CPU NAT spent 84 to 95% of its CPU there.
Its DNS lookups, lease renewals and probes timed out, so it stepped down, and
the standby filled up in turn and handed back, several times a minute.

So natpair moves receive processing into kernel threads, called threaded NAPI,
and ranks the NAT's own work above forwarding:

- The daemon turns on threaded NAPI (`/sys/class/net/<interface>/threaded`)
  for every ENI when it starts, when the shared ENI attaches, and every 5 s.
  Each receive queue then has a thread named `napi/<interface>-<id>`. While
  `/var/lib/natpair/receive-threads-off` exists, it turns threaded NAPI off
  instead, so a benchmark can compare both on one NAT.
- The daemon and conntrackd run in `natpair.slice`, a systemd slice with a CPU
  weight of 1000. The primary interface's threads run at nice -10, which has
  about the same weight. The shared ENI's threads keep the kernel's default,
  nice 0, which is the same weight, 100, as every other slice.

These are weights, not strict priorities. A busy task gets a share of the CPU
in proportion to its weight, so when the CPU is full, the NAT's own work gets
about ten times the share of each forwarding thread. It needs only a few
percent, and forwarding gets every CPU cycle it leaves.

The owner's upload probe still travels through the shared ENI, like worker
traffic, so that it tests the real path. At full load the interface drops
some of its packets, as it does worker packets, and TCP sends them again.

A real-time policy (`SCHED_FIFO`) would rank the daemon strictly first, but
everything it starts, such as `iptables`, `conntrack` and the updater's
download, would inherit that rank. The only way to stop that, resetting the
policy on fork, also resets the Go runtime's own threads. A real-time task
that loops would also take 95% of the CPU, and a worker that opens
connections quickly would drive conntrackd ahead of all forwarding.

## Network details

- Both NATs and the shared ENI must be in one availability zone, because an
  ENI can't move between zones.
- The NATs' security group allows all traffic from the VPC's CIDRs, and all
  TCP and UDP ports from anywhere. With every port open, AWS doesn't track
  connections through the NATs. That matters because after a takeover, the
  replies to copied connections arrive at the other instance, and AWS would
  drop replies it tracked on the old one.
- So the host firewall on each NAT is what filters traffic to the NAT itself.
  It accepts new connections only from the VPC and the peer, and drops
  everything else from outside the VPC without an answer. Traffic the NAT
  forwards doesn't pass through it.
- The NAT's own connections skip the kernel's connection table, so when
  worker connections fill it, the NAT's DNS lookups, lease renewals, AWS API
  calls and connection copies still work. The own-path probes still use the
  table, because they test the forwarding path, which needs it.
  [Security](#security) lists exactly what skips it.
- The module adds a DynamoDB gateway endpoint to the public route table, so
  lease renewals and health reports reach DynamoDB without depending on the
  internet path the NATs forward. Workers' DynamoDB traffic goes through the
  NATs like their other traffic, so it leaves from the shared Elastic IP.
- A NAT forwards on the CPU that took each network queue's interrupt. natpair
  puts queue n of every ENI on CPU n, checks again every 5 s, which catches
  the shared ENI after a takeover, and turns irqbalance off. Otherwise
  irqbalance can put all of an ENI's queues on one CPU, and a two-CPU NAT
  forwards with only one of them.
- By default the NATs forward traffic from every CIDR of the VPC. Their own
  traffic, such as AWS API calls and lease renewals, always keeps their own
  address and route, even though that address is inside the VPC.

## Security

- **Access.** The NATs run no SSH server. Open a shell with Session Manager.
  Instance metadata requires IMDSv2.
- **Permissions.** Each NAT's IAM role can change only its own pair's lease
  records and move only its own pair's shared ENI.
  [The module reference](../terraform/README.md#what-the-nats-may-do) lists
  every permission.
- **CPU priority.** natpair raises the CPU weight of its own daemon,
  conntrackd and the primary interface's receive threads, not their
  real-time priority. A flood of worker traffic can't starve the lease
  renewals, and a fault in the NAT's own work takes at most about 90% of a
  full CPU from forwarding, not all of it. Traffic to a NAT's own address,
  which the security group lets in from anywhere, is received at the raised
  weight, so a flood aimed there now outweighs forwarding instead of sharing
  softirq time with it. The host firewall still drops it. The daemon raises
  only kernel threads named for the primary interface, never a process that
  names itself that way.
- **Connection copies.** conntrackd sends connection state to the peer in
  cleartext over UDP port 3780. The host firewall accepts it only from inside
  the VPC.
- **Host firewall.** It accepts new connections to the NAT only from the VPC
  and the peer, which get the kernel's usual reset from a closed port. From
  outside the VPC, it drops everything without an answer, on every port of
  the NAT's own and shared addresses. The one exception is TCP without SYN
  to the shared address that matches no connection the NAT tracks. It gets
  a reset, so a remote server still sending on a connection the new owner
  never copied closes it at once, instead of waiting for its own timeout.
  A scan of the NAT's own address learns nothing, and a scan of the shared
  address learns only that it answers such packets. Forwarded traffic
  doesn't pass through the firewall.
- **Untracked connections.** These skip the connection table, both ways:
  TCP on the NAT's own ephemeral ports (32768 to 60999), UDP between those
  ports and the VPC, the peer's copies to port 3780, and UDP with Amazon Time
  Sync (169.254.169.123, port 123) and the Route 53 Resolver
  (169.254.169.253, port 53). Without state, the firewall accepts only their
  replies:
  - TCP without SYN, to the NAT's own address and ephemeral ports, that
    belongs to one of the NAT's sockets. Such a packet can't open a
    connection. The kernel finds the socket by the packet's addresses and
    ports, which needs no connection tracking, and ignores sockets
    listening on any address. Other TCP to those ports is dropped like any
    other port's.
  - UDP from those two link-local services, from their port to the NAT's
    ephemeral ports. Nothing outside the instance can send from a
    link-local address.
  - ICMP fragmentation-needed, host-unreachable, port-unreachable and
    time-exceeded messages to the NAT's own address, limited to 50 a
    second. Errors about tracked connections are accepted as before.
  The NAT's own sockets keep to the ephemeral range, and the own-path probes
  use ports 61000 to 65535, which stay tracked.
- **Forged ICMP errors.** Anyone can send the NAT ICMP errors that name one
  of its connections. Linux acts on one only if it matches a socket's
  addresses and ports. For TCP, its sequence number must also fall inside
  the connection's unacknowledged data, which an attacker who can't see the
  traffic has to guess. A forged fragmentation-needed message can lower
  the path MTU no further than 552 bytes, which slows a connection but
  doesn't break it. On an established TCP connection, Linux records an
  unreachable message only as a soft error, which ends the connection only
  if it is already timing out. While a connection is being set up, a forged
  one that matches can abort it, and the caller tries again. A forged
  port-unreachable that matches a DNS lookup's random port fails that
  lookup, which is retried. The rate limit bounds all of it.
- **Encryption at rest.** The lease table uses DynamoDB's AWS owned key. The
  root volumes are encrypted with the account's default EBS key, AWS managed
  `aws/ebs` unless you've set another, so whoever launches the NATs needs
  permission to use that key through EC2.
- **Releases.** A NAT installs a release only if its SHA-256 matches
  `release_sha256`. Each release's files carry a GitHub build provenance
  attestation. To check one:

  ```sh
  gh attestation verify natpair_linux_arm64.tar.gz --repo artie-labs/natpair
  ```
