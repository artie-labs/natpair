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

When the owner's upload times out, it then tries 40 TCP handshakes with the
probe receiver at once, through the shared Elastic IP like the upload, and
closes each one as soon as it connects:

- **Some complete and some don't.** The path works but loses packets, as
  when workers send more than the owner can forward. On AWS, small UDP
  packets beyond what the CPU could process lost up to 87% of the packets
  through the NAT. The standby would get the same traffic on taking over,
  and the pair used to move 2 to 4 times a minute, pausing forwarding each
  time. So the round doesn't count as failed, and it ends any run of failed
  rounds.
- **None complete.** The path is dead, and the round counts as failed.
- **All complete.** Small packets get through without loss, so the upload
  failed for another reason, such as a path that drops full-size packets,
  and the round counts as failed.

The check runs only for an owner whose upload timed out while its
connection table wasn't full. A failure that
came back over the path, such as a reply showing the wrong source address,
always counts.
## Shedding a flood: the overload guard

Workers can send more small packets than the owner's CPU forwards. On a
1-vCPU c7gn.medium, 64-byte UDP at 800,000 packets a second or more fills the
CPU. The shared ENI's receive ring then overflows, and the NIC drops packets
at random, including the replies to the owner's own probe, which leaves
through the shared Elastic IP like worker traffic. The probe fails, the owner
hands over, and the new owner gets the same flood.

So the owner runs a small XDP program on the shared ENI. XDP runs in the
driver, before the kernel builds a packet buffer, and dropping a packet there
costs about 100 ns, against about 1,450 ns for the kernel's path.

- **Normally it does nothing.** Its budget is 0, and it passes every packet
  after one map lookup, a few nanoseconds.
- **It engages** when the busiest CPU has been at least 95% busy for 300 ms
  and the NIC dropped at least 5% of what reached the shared ENI in the last
  second. A full CPU alone isn't enough: TCP as fast as it goes also fills a
  small NAT's CPU, but TCP senders slow down at the first losses, so the NIC
  drops little and the probe gets through.
- **It measures for 100 ms**, then gives each CPU a budget of 90% of the
  packets the busiest CPU passed, per 1 ms tick. Past the budget it drops
  worker packets. Dropping the other 10% is cheap, so the CPU has room again.
- **It raises the shared ENI's receive threads** to nice -10 while it
  limits. With threaded NAPI, each receive queue has a kernel thread
  that shares the CPU with the daemon. On a 1-vCPU NAT, each health round's
  own work held the CPU for longer than the receive ring lasts, so the NIC
  dropped the probe's replies even with the budget on. The budget bounds
  what those threads do, so they can't take the whole CPU.
- **It always passes** anything that isn't IPv4, such as ARP, and replies to
  the probes: TCP from the probe receiver's port to the shared address on
  ports 61000 to 65535, which only the shared canary's connections use. Past
  the budget, each CPU passes at most 128 such replies every 16.8 ms.
- **It clears** once it has dropped less than 5% of what it saw over the
  last second, and then waits at least 1 s before it can engage again.

When it attaches, the daemon also raises the shared ENI's receive ring to
the most the NIC allows, 2,048 packets on a c7gn.medium against ENA's
default of 1,024, so the ring rides out short waits for the CPU. It puts the
ring back when the guard detaches.

The daemon attaches the program when a takeover configures the shared ENI,
before forwarding opens, and checks every 5 s that it's on the interface that
holds the shared address, and only there. It never attaches to the NAT's own
interface, where its lease renewals, DNS lookups and conntrackd copies
arrive. Attaching, and changing the ring, each restart an ENA interface,
which costs no gap while forwarding is still closed. The program goes away when the daemon stops.

The guard only drops packets. It never decides who owns the pair: the probes
and the lease still do, so a broken owner fails over as before. To turn it
off, see [operations](operations.md#turn-the-overload-guard-off).

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

## Forwarding at full load

Linux processes received packets in softirq context, kernel work that the
scheduler doesn't manage like a process. How that work shares the CPU with the
daemon depends on the kernel:

- Linux 6.1 runs softirq work in the ksoftirqd threads once there is more than
  it can finish at once. The scheduler shares the CPU between those threads
  and the daemon, so a NAT whose forwarding fills the CPU still renews its
  lease.
- Linux 6.5 and later run pending softirq work in whatever task re-enables
  bottom halves, which the daemon does in many of its own system calls.
  Upstream made this change in commit
  [d15121be7485](https://git.kernel.org/torvalds/c/d15121be7485655129101f3960ae6add40204463)
  ("Revert "softirq: Let ksoftirqd do its job""), which names threaded NAPI
  as the way to keep receive work under the scheduler. On a c7gn.large on
  Linux 6.18 with both CPUs full of forwarding, 96.7% of the daemon's CPU
  samples were forwarding work. It used 31.5% of a CPU, and in a 60 s run its
  lease renewals timed out 11 times and its DNS lookups and probes 35 times.

NAPI is how Linux polls a network device's receive queues. So the daemon turns
on threaded NAPI (writes 1 to `/sys/class/net/<interface>/threaded`) for every
ENI: when it starts, right
after the shared ENI comes up during a takeover, and every 5 s, which also
catches an ENI that wasn't up yet. Each receive queue is then polled by a
kernel thread named `napi/<interface>-<id>`, at the default priority, and the
scheduler shares the CPU between those threads and the daemon as it did with
ksoftirqd on 6.1. On the same 6.18 NAT and load with threaded NAPI on, the
daemon used 0.9% of a CPU, with no lease or DNS timeouts, and the NAT
forwarded 2.7% less.

The daemon leaves interfaces without a device, such as `lo`, alone, and
leaves any value other than 0 in `threaded`, such as 2 for busy polling on
newer kernels. If something else writes 0, the daemon writes 1 again within
5 s.

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
- **Receive threads.** The daemon turns on threaded NAPI for the ENIs, as in
  [Forwarding at full load](#forwarding-at-full-load). It needs no new
  permission: it already runs as root. The receive threads run at the
  default priority, so a flood of traffic to a NAT's own address competes for
  the CPU as an equal of forwarding, not ahead of it. The host firewall still
  drops it.
- **Connection copies.** conntrackd sends connection state to the peer in
  cleartext over UDP port 3780. The host firewall accepts it only from inside
  the VPC.
- **Host firewall.** It accepts new connections to the NAT only from the VPC
  and the peer, which get the kernel's usual reset from a closed port. From
  outside the VPC, it drops everything without an answer, on every port of
  the NAT's own and shared addresses. The one exception is TCP without SYN
  to the shared address that matches no connection the NAT tracks, on a
  port worker connections use. The NAT translates worker TCP to ports 1024
  to 60999 on the shared address, and keeps a worker's port when it's
  already in that range. Such a packet gets a reset, so a remote server
  still sending on a connection the new owner never copied closes it at
  once, instead of waiting for its own timeout. Each remote address gets at
  most 50 resets at once and then 10 a second. A scan of the NAT's own
  address learns nothing, and a scan of the shared address gets a few
  answers on worker ports and silence for the rest. Forwarded traffic
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
- **Congested paths.** A failed upload that the handshake check calls
  congested keeps the owner serving, so traffic can't hold a broken owner
  in place unless its path still carries some packets. A completed
  handshake can't be forged from off the path: the answer must acknowledge
  the random 32-bit sequence number the kernel chose for that SYN, and
  reach the port address translation chose for it. Flooding the NAT, from
  workers or from the internet to the shared address, can only make
  handshakes fail, which counts toward failing over. The limit: a path
  that a fault leaves degraded but not dead, such as one losing 99% of
  packets, or one that drops only full-size packets while a flood loses
  some small ones, counts as congested for as long as that lasts. An
  attacker can't cause such a fault, only add a flood while it lasts.
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
- **Overload guard.** Anyone on the internet can send packets that match
  its exemption, TCP from the receiver's port to the shared address's probe
  ports. Each costs what it would without the guard, and past the budget
  each CPU passes at most 128 of them every 16.8 ms, about 1.5% of a CPU,
  and drops the rest. So forged replies can't buy more CPU than they could
  without the guard. What they can do is crowd out real probe replies while
  the guard is engaged, which fails the probe. A flood big enough to engage
  the guard does that anyway without it. The guard never sees the NAT's own
  interface, so it can't drop lease renewals, DNS answers or conntrackd
  copies, and it only drops, so it can't keep a broken owner serving. It
  raises the priority only of kernel threads named for the shared ENI,
  checked by the kernel's own kernel-thread flag, so a process that names
  itself like one gets nothing.
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
