# Operating natpair

This guide covers the day-to-day work on a pair: checking it, taking a NAT
out of service, upgrading, replacing NATs and monitoring. The examples assume
the module is called `natpair` with `name = "natpair"`. Change the names to
match yours.

- [Open a shell on a NAT](#open-a-shell-on-a-nat)
- [Find the owner](#find-the-owner)
- [Verify a new pair](#verify-a-new-pair)
- [Move from a NAT Gateway](#move-from-a-nat-gateway)
- [Take a NAT out of service](#take-a-nat-out-of-service)
- [Upgrade](#upgrade)
- [Replace a NAT](#replace-a-nat)
- [Pace forwarded traffic](#pace-forwarded-traffic)
- [Monitoring](#monitoring)
- [Download releases from your own S3 bucket](#download-releases-from-your-own-s3-bucket)
- [Remove a pair](#remove-a-pair)

## Open a shell on a NAT

The NATs run no SSH server. Use Session Manager:

```sh
aws ssm start-session --target <instance ID>
```

This needs the
[Session Manager plugin](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html)
for the AWS CLI and `ssm:StartSession` on the instance. You can also select
the instance in the EC2 console and choose **Connect**. The `natpair` commands
and logs need `sudo`.

natpair logs one JSON object per line to journald. To follow them:

```sh
sudo journalctl -u natpair -f -o cat
```

## Find the owner

The owner is the NAT the shared ENI is attached to:

```sh
aws ec2 describe-network-interfaces \
  --filters Name=tag:Name,Values=natpair-shared \
  --query 'NetworkInterfaces[0].Attachment.InstanceId' --output text
```

To see whether an instance is NAT `a` or `b`, read its Name tag. It prints
`natpair-nat-a` or `natpair-nat-b`:

```sh
aws ec2 describe-instances --instance-ids <instance ID> \
  --query 'Reservations[0].Instances[0].Tags[?Key==`Name`].Value' --output text
```

The module's `nat_instance_ids` output maps `a` and `b` to instance IDs.

## Verify a new pair

1. On each NAT, look at the latest health round:

   ```sh
   sudo journalctl -u natpair -o cat | grep '"msg":"health round"' | tail -1
   ```

   The owner shows `"serving":true` and `"healthy":true`. The standby shows
   `"ready":true`, which means it can take over with copied connections. A
   NAT logs a round whenever its result changes, and at least once a minute.

2. From a worker, check that traffic leaves from the shared IP:

   ```sh
   curl -s https://checkip.amazonaws.com
   ```

   It should print the module's `shared_public_ip` output.

3. Optionally, test a handover. Run `sudo natpair maintenance` on the owner,
   wait for the standby to log `forwarding open`, and check step 2 again. Then
   run `sudo natpair resume` on the old owner so it becomes the standby.

## Move from a NAT Gateway

Deploy the pair first, check it, then point the routes at it. Changing a
route's target is one in-place update, so workers keep a default route the
whole time.

1. **Choose the shared address.** The module won't take an Elastic IP that's
   still associated with the NAT Gateway. Either use a new Elastic IP and add
   it to every allowlist that holds your current address before the move, or
   keep the NAT Gateway's address and accept an outage: delete the NAT
   Gateway first, then continue from step 2 with that address. Workers have
   no internet access until the new pair forwards.
2. **Deploy the pair.** Add the module and apply, leaving the routes alone.
   Wait for one NAT to log `forwarding open` and the other to log a health
   round with `"ready":true`.
3. **Move the routes.** In each private route table's default route, replace
   the NAT Gateway target with the shared ENI:

   ```hcl
   route {
     cidr_block           = "0.0.0.0/0"
     network_interface_id = module.natpair.shared_eni_id # was nat_gateway_id
   }
   ```

   The same works on an `aws_route` resource. Apply, and the plan updates
   each route in place. If another module owns the routes, such as
   terraform-aws-vpc with `enable_nat_gateway`, turning it off deletes them.
   The new routes are then created in the same apply, and each table has no
   default route in between. If one fails with `RouteAlreadyExists`, apply
   again.
4. **Check** traffic from a worker as in [Verify a new pair](#verify-a-new-pair),
   then delete the NAT Gateway if it's still there.

To go back, point the routes at the NAT Gateway again.

## Take a NAT out of service

To reboot, stop or replace the owner, hand over first:

1. On the owner, run `sudo natpair maintenance`. It hands over once the
   standby passes its checks.
2. Wait for the other NAT to log `forwarding open`, and check that worker
   traffic works.
3. Reboot, stop or replace the old owner. It no longer holds the shared ENI.
4. After a reboot or a stop and start, run `sudo natpair resume` on it. The
   maintenance request lasts across restarts until you do. A replaced NAT
   starts without one.

The handover pauses traffic for about 10 s. Skipping it costs more. EC2 holds
the shared ENI until a stopping instance has fully stopped, so the standby
has to force it off, and traffic pauses for 25 to 35 s. A rebooting instance
never stops, so after a forced detach from one, it must be stopped and started
before it can serve again.

The standby needs no handover. Reboot, stop or replace it whenever you like.
The pair can't fail over while it's gone.

## Upgrade

The module and the daemon share one version. Keep the module's `?ref=` and its
`release` input on the same version, and read the [changelog](../CHANGELOG.md)
first.

1. Set `?ref=`, `release` and `release_sha256` to the new version. Take the
   SHA-256 of `natpair_linux_arm64.tar.gz` from the release's
   `checksums.txt`.
2. Run `terraform apply`. It writes the new release to the lease table.
   Check the plan first. It must not replace or change
   `aws_instance.nat`.

natpair on each NAT checks the pinned release every minute and moves the pair
to it, one NAT at a time:

1. The standby downloads the release, checks its SHA-256, installs it and
   reboots into it. It does this only while the owner is serving with a
   working path.
2. Once the standby has run the new release and stayed ready for 2 minutes,
   the owner hands over, as with `natpair maintenance`. Traffic pauses for
   about 10 s.
3. The old owner, now the standby, installs the release and reboots.

The upgrade is done when both NATs' health rounds show the new `release`.
Until then, a NAT on the old release logs an `update` line every minute that
says what it's waiting for.

A release that never gets ready stays on the standby, and traffic stays on the
owner's old release. To roll back, pin the previous release and its SHA-256
again, and the standby moves back. If the new release can't run at all, the
standby can't move itself back, so replace it.

A NAT you put in maintenance by hand isn't upgraded until you run
`natpair resume`.

## Replace a NAT

Running NATs keep the image, configuration and boot script they launched
with. These changes need new NATs:

- `worker_cidrs`, `max_connections`, `release_url`, `pacing`,
  `datadog_api_key_secret_arn` and `datadog_site`, and a new CIDR on the VPC
  when `worker_cidrs` is left at its default
- a newer Amazon Linux image
- a module upgrade whose changelog says so

A new NAT installs the pinned release at first boot.

A new private subnet inside the VPC's CIDRs only needs its default route.
If you set `worker_cidrs` yourself, add the subnet's CIDR and replace both
NATs first, then add its route. Otherwise the subnet gets a route through
NATs that don't forward its traffic.

Replace one NAT per apply, the standby first:

1. [Find the owner](#find-the-owner). The other NAT is the standby. Say it's
   `b`.
2. Replace the standby:

   ```sh
   terraform apply -replace='module.natpair.aws_instance.nat["b"]'
   ```

   Check that the plan replaces only that NAT.
3. Wait until the new NAT logs a health round with `"ready":true`.
4. Hand over from the owner, as in steps 1 and 2 of
   [Take a NAT out of service](#take-a-nat-out-of-service).
5. Replace the old owner the same way.

Changing `instance_type` stops and starts a NAT instead of replacing it.
Apply it to one NAT at a time with `-target`:

```sh
terraform apply -target='module.natpair.aws_instance.nat["b"]'
```

Do the standby first, then hand over, then do the other NAT and run
`sudo natpair resume` on it.

Changing only tags updates the NATs in place without a restart, so it's safe
to apply to both at once.

## Pace forwarded traffic

Pacing keeps forwarded traffic just under the instance's network limits, so
AWS doesn't drop packets at random, and splits the limit fairly between
workers. [How natpair works](architecture.md#pacing-forwarded-traffic)
explains it. It is off by default.

To turn it on, set the module's `pacing` input and
[replace the NATs](#replace-a-nat), the standby first:

```hcl
module "natpair" {
  # ...
  pacing = {
    enabled    = true
    start_mbps = 2900
  }
}
```

`start_mbps` is the bandwidth cap a NAT starts from. About 95% of the
instance type's baseline bandwidth is a good start: 2,900 for a c7gn.medium,
whose baseline is 3.125 Gbps. The cap rises from there while traffic presses
it and AWS reports nothing. Leave it unset and a NAT forwards uncapped until
AWS first reports exceeding the limit, then caps itself just below. Leave
`start_kpps`, the packet rate cap, unset unless you know the instance's
packet rate limit. AWS doesn't publish it.

`poll_interval_ms` is how often a NAT reads the allowance counters. The
default, 10, lets the cap follow AWS's first drops within tens of
milliseconds, for about 1% of one CPU. The NAT also caps forwarded packets a
second at what its CPUs carry. That cap starts once a CPU first passes 80%
busy, as [How natpair works](architecture.md#pacing-forwarded-traffic)
explains.

Pacing needs the `iproute-tc` package. NATs that boot with this module
version install it.

### Turn it off on a running NAT

```sh
sudo natpair pacing-off
```

The NAT removes its qdiscs and programs within a second, without a restart or
a handover, and traffic flows unpaced. The request lasts across restarts and
reboots until you run `sudo natpair pacing-on`, which starts again from the
configured caps. To turn pacing off for good,
set `enabled = false` and replace the NATs. A daemon whose configuration
turns pacing off removes anything an earlier daemon installed during the same
boot. If no daemon renews the limits, for example after rolling `release`
back to one without pacing, the kernel stops pacing within 10 s and forwards
unpaced until the next reboot clears the rest. Removal puts back the kernel's
default qdisc, not one you had installed yourself.

### What to watch

Each NAT that forwarded traffic logs `pacing status` every minute:

| Field | Meaning |
| --- | --- |
| `cap_mbps`, `cap_kpps` | The allowance caps. 0 means no cap yet. |
| `ceiling_mbps`, `ceiling_kpps` | The forwarded rate when AWS last reported exceeding the limit. The cap settles at 95% of it, and 10 s after each cut rises again while traffic presses it. |
| `cap_cuts` | How many times AWS's reports cut the allowance caps during the minute. While traffic presses a limit, each probe ends in a cut, about 5 a minute. |
| `cpu_cap_kpps`, `cpu_ceiling_kpps` | The CPU cap on forwarded packets, 0 until a CPU first passes 80% busy, and the rate at which a CPU last passed 80% busy. The cap rises while the busiest CPU is under 70% busy. The kernel enforces the lower of `cap_kpps` and `cpu_cap_kpps`. |
| `busiest_cpu` | How busy the busiest CPU was in the last 100 ms, from 0 to 1. |
| `bw_in_allowance_exceeded`, `bw_out_allowance_exceeded`, `pps_allowance_exceeded` | Packets AWS queued or dropped during the minute, summed over all interfaces. |
| `upload_mbps`, `download_mbps`, `upload_kpps`, `download_kpps` | Paced worker traffic in each direction, averaged over the minute. |
| `worker_share_mbps`, `worker_share_kpps` | The most one worker may use right now. It is 97% of the cap while no worker has to wait. |
| `waited_packets`, `dropped_packets` | Worker packets that waited more than 1 ms, and those dropped because they would have waited more than 20 ms. Drops are how pacing slows a heavy worker. |
| `active_workers`, `waiting_workers` | Workers that sent in the last quarter second, and those whose packets waited more than 1 ms. |

`the instance exceeded its network allowance, so pacing cut its cap` means
AWS queued or dropped packets. It is logged at most once a minute, and
`cap_cuts` counts every cut. Cuts after a start or a probe are how pacing
finds the limit, so a few a minute mean traffic is at the limit. If the cap
keeps falling instead of settling, traffic pacing doesn't control is over
the limit, such as the NAT's own traffic or bursts of inbound packets.
Consider a larger instance type.

`a forwarding CPU is nearly full, so pacing cut the packet cap` means the NAT
was close to running out of CPU. If it recurs, consider an instance type with
more CPUs. `a CPU stayed full after pacing forwarded less` means something
other than forwarding fills the CPU, such as conntrackd under heavy
connection churn, so pacing can't relieve it. Likewise, `AWS kept dropping
after pacing forwarded less` means traffic pacing doesn't control is over
the allowance.

## Monitoring

natpair tests its own uploads, not your workers' traffic. **Run an egress
check from the workers.** A job that requests an external URL every minute
and alerts when the request fails, or when it leaves from an address other
than the shared IP, catches failures that natpair can't see.

If you ship the NATs' logs, these alerts cover the rest:

| Alert when | Why |
| --- | --- |
| No `health round` with `"ready":true` from the standby for 10 minutes | The pair can't fail over. |
| `ownership acquired` is logged outside an upgrade or maintenance | A NAT took over without a planned handover. Find out why. |
| `forced the stuck shared ENI detach. Stop and start the NAT it was attached to before it serves again.` is logged | That NAT needs a stop and start. See [troubleshooting](troubleshooting.md#forced-the-stuck-shared-eni-detach). |
| `update` lines continue for more than an hour | An upgrade is stuck. The `reason` field says why. |
| `conntrackd is not answering` or `copied connections are incomplete` lasts more than 5 minutes | A takeover would reset connections. |
| `the instance exceeded its network allowance` or `a forwarding CPU is nearly full` is logged more than a few times an hour, with pacing on | The pair is near its limits. See [What to watch](#what-to-watch). |
| `failed to load pacing` or `failed to pace an interface` is logged | Forwarded traffic isn't paced. See [troubleshooting](troubleshooting.md#failed-to-load-pacing-so-forwarded-traffic-isnt-paced). |
| `the connection table is full` is logged | The kernel is dropping new worker connections. `the connection table is nearly full` warns earlier, at 90%. See [troubleshooting](troubleshooting.md#the-connection-table-is-full). |
| `the health probe failed because this NAT's connection table is full` is logged | The owner's uploads fail because of the full table, not its path, so it stays the owner instead of stepping down. Workers' new connections fail the same way. See [troubleshooting](troubleshooting.md#the-health-probe-failed-because-this-nats-connection-table-is-full). |

Set `datadog_api_key_secret_arn` to have each NAT install the Datadog agent.
It ships the logs of `natpair.service`, `natpair-bootstrap.service` and
`conntrackd.service`, tagged `service:natpair` and `natpair_pair:<pair_id>`,
plus host metrics. Two metrics are worth watching:

- `system.net.conntrack.count`, the size of the connection table, against
  `system.net.conntrack.max`.
- `system.net.aws.ec2.bw_out_allowance_exceeded` and the other
  `allowance_exceeded` counters. They count packets AWS queued or dropped
  because the instance hit its network limits, a sign the instance type is
  too small.

Without Datadog, ship the same journald units with your own agent. The
network counters are in `sudo ethtool -S <interface> | grep allowance`.

## Download releases from your own S3 bucket

By default, NATs download releases from GitHub through their own Elastic IPs.
To use your own bucket instead, copy each release's
`natpair_linux_arm64.tar.gz` to `<prefix>/<tag>/natpair_linux_arm64.tar.gz`
and set:

```hcl
release_url = "s3://my-bucket/natpair"
```

The module gives the NATs read access to that prefix. The SHA-256 check
applies to either source.

## Remove a pair

Point the private route tables' default routes elsewhere first, because the
shared ENI goes away with the pair. Removing the module also removes the
DynamoDB gateway endpoint on the public route table. The Elastic IP you passed
in isn't deleted.
