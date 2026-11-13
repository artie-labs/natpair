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

3. On each NAT, check that receive processing runs in threads and the NAT's
   own work is weighted ahead of forwarding:

   ```sh
   grep . /sys/class/net/*/threaded
   ps -eo pid,ni,comm | grep napi/
   cat /sys/fs/cgroup/natpair.slice/cpu.weight
   ```

   Each ENI, such as `ens5` and `ens6`, prints `1`. `lo` and the probes'
   `nat-can` interfaces have no receive queues of their own and print `0`.
   The primary interface's `napi/` threads show nice `-10` and the shared
   ENI's show `0`. The slice's weight is `1000`. See
   [How natpair works](architecture.md#staying-responsive-at-full-load).

   To compare a NAT with threaded NAPI off, such as in a benchmark, create
   the switch file. Within 5 s the daemon turns threaded NAPI off on every
   ENI, and receive work runs in softirq context again. Remove the file to
   turn it back on. Nothing restarts.

   ```sh
   sudo touch /var/lib/natpair/receive-threads-off
   sudo rm /var/lib/natpair/receive-threads-off
   ```

4. Optionally, test a handover. Run `sudo natpair maintenance` on the owner,
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

- `worker_cidrs`, `max_connections`, `release_url`,
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
