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

## Pacing forwarded traffic

Pacing is optional and off by default. Turn it on with the module's
`pacing` input, as in [operations](operations.md#pace-forwarded-traffic).

AWS limits each instance's bandwidth in each direction and its packets per
second. Above a limit, the hypervisor drops packets at random from every
flow. That includes the lease renewals and connection copies the pair
depends on, so one worker sending too much can slow every worker and put the
lease at risk. With pacing on, the NAT keeps forwarded traffic just under
the limits itself. A worker that sends too much slows to its fair share, and
the others barely notice.

**Which packets.** Uploads, from workers to the internet, leave through the
shared ENI. Downloads, from the internet to workers, leave through the NAT's
own interface, because only traffic from the worker CIDRs uses the shared
ENI's route table. AWS counts both against the same limits, so both are
paced against one budget. A small BPF program on every interface copies each
arriving packet's source address into its mark. A packet the NAT sends
itself has no mark, so lease renewals, probes, conntrackd's copies and AWS
API calls are never paced. The mark also tells which worker sent an upload
after source NAT has replaced its address.

**How a packet waits.** A second BPF program, on packets leaving, gives each
forwarded worker packet a departure time, and `sch_fq` holds it until then.
This is the earliest departure time model that Cilium's bandwidth manager
uses. Each interface gets one `sch_fq` per transmit queue under `mq`, so CPUs
don't share a qdisc lock. A packet that would have to wait more than 20 ms
is dropped instead. That tells the sender to slow down and keeps the queues
short.

**Fair shares.** Each worker address has its own token bucket, in bytes and
in packets, and all traffic shares one more. Four times a second the daemon
looks at which workers had packets wait more than 1 ms. Workers that didn't
keep what they use, and those that did split the rest of the cap equally.
Below the cap, no worker waits. A packet that its worker's bucket delayed
skips the shared bucket, so a heavy worker's queue never holds up the
others. With the AWS VPC CNI, each pod has its own address, so each pod is
its own worker.

**Finding the cap.** The daemon reads the ENA driver's allowance counters,
`bw_in_allowance_exceeded`, `bw_out_allowance_exceeded` and
`pps_allowance_exceeded`, every 10 ms by default, on every interface. ENA
refreshes them at least every millisecond. AWS counts the whole instance, and
when it drops, it drops on both ENIs: on AWS, after a c7gn.medium's burst ran
out, its own ENI lost 40% of the acknowledgements going back to workers.
Bandwidth and packet rate each have their own cap:

- While the counters stay still and traffic presses the cap, it rises by 1%
  a second.
- When a counter moves, the cap drops to 80% of the rate forwarded at the
  time, and the NAT remembers that rate. If the counters keep moving after
  the cut, the next cut is to 50%.
- The cap then climbs back to 95% of the remembered rate and stays there.
  Every 5 minutes, and only while traffic presses it, it rises again to
  check whether the limit went up.
- When burst credits run out and the limit falls to the instance's baseline,
  the counters move again and the cap follows it down.

After a cut, the cap ignores the counters for 50 ms, while packets already
queued under the old cap leave.

A cap only cuts when forwarded traffic is to blame. It must make up at
least half of what AWS counts against that allowance: bytes sent, for
bandwidth, and packets sent and received, for packet rate. And if a cut
forwards less but AWS keeps dropping at the same rate, the cap goes back to
where it was and stops cutting until the drops stop. Otherwise traffic the
NAT can't pace, such as its own, would push the workers' caps down for
nothing.

A NAT can start from a configured cap, or with no cap until the counters
first move. A cut never takes a cap below 100 Mbit/s or 100,000 packets a
second, because counters that move while forwarded traffic is lower than that
come from other traffic.

**The CPUs' limit.** A NAT forwards in the kernel, on the CPUs that take the
network interrupts, at about 1.1 µs a full-size packet and 1.6 µs a small
one. One CPU runs out at about 600,000 forwarded packets a second, long
before AWS's packet rate allowance. A NAT whose CPU is full can't renew its
lease, resolve DNS or probe its path, so it steps down, and the standby
inherits the same load. So the daemon also caps forwarded packets a second
by CPU. Four times a second it reads `/proc/stat`. If the busiest CPU was
more than 80% busy, the cap is cut the same way as an allowance cap, then
settles at 95% of the rate that overloaded it and probes again every 5
minutes. It cuts only when forwarding is to blame: forwarded traffic is at
the cap, and at 1.6 µs a packet it explains at least half of the load. If a
cut forwards less but the CPU stays as busy, as when conntrackd or traffic
that senders keep offering fills it, the cap goes back to where it was and
stops cutting until the CPU calms down. It starts at 400,000 packets a second
per CPU and never goes below 250,000. The packet cap in
force is the lower of the two. Pacing delays and drops packets on the way
out, so it bounds incoming traffic only as TCP senders slow down.

**Takeovers.** Pacing runs on its own and nothing waits for it, so it can't
delay or stop a takeover, and forwarding works if it fails to load. Both
NATs pace their own interface all the time. A new owner paces the shared ENI
within a second of the ENI appearing. Each NAT keeps its caps in memory and
starts again from the configured values when its daemon restarts, or when
`natpair pacing-on` turns pacing back on. If no
daemon renews the limits for 10 s, the kernel stops pacing, so a NAT whose
daemon is gone, or runs a release without pacing, forwards unpaced.

## Network details

- Both NATs and the shared ENI must be in one availability zone, because an
  ENI can't move between zones.
- The NATs' security group allows all traffic from the VPC's CIDRs, and all
  TCP and UDP ports from anywhere. With every port open, AWS doesn't track
  connections through the NATs. That matters because after a takeover, the
  replies to copied connections arrive at the other instance, and AWS would
  drop replies it tracked on the old one.
- So the host firewall on each NAT is what filters traffic to the NAT itself.
  It accepts new connections only from the VPC and the peer, resets other TCP
  and drops everything else. Traffic the NAT forwards doesn't pass through it.
- The NAT's own connections, from and to its own address, skip the kernel's
  connection table. So when worker connections fill the table, the NAT's DNS
  lookups, lease renewals, AWS API calls and connection copies still work.
  The firewall accepts their replies without state: TCP packets that can't
  open a connection, traffic from link-local addresses such as the metadata
  service, and ICMP unreachable messages. The own-path probes still use the
  table, because they test the forwarding path, which needs it.
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
- **Connection copies.** conntrackd sends connection state to the peer in
  cleartext over UDP port 3780. The host firewall accepts it only from inside
  the VPC.
- **Pacing.** The pace program keeps state for at most 65,536 workers, and
  forgets the least recently seen one first. The NAT's own traffic never
  has state there. A packet gets a worker's state only if it arrived on an
  interface, so the mark program marked it with its source address, and
  that mark, or else its destination, is in the worker CIDRs. Traffic from
  the internet is only forwarded as replies on a worker's own connections,
  so it can't create or drain another worker's state. A worker that can
  send from other workers' addresses can use up their fair shares. AWS stops
  that unless an instance turns off its source and destination check, or
  several pods share one node's addresses.
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
