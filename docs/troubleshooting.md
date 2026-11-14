# Troubleshooting

Start with the logs on both NATs. [Operations](operations.md#open-a-shell-on-a-nat)
shows how to open a shell and read them. Each section below starts from a
symptom or a log message.

- [Workers can't reach the internet](#workers-cant-reach-the-internet)
- [The standby isn't ready](#the-standby-isnt-ready)
- [An upgrade doesn't finish](#an-upgrade-doesnt-finish)
- [The NAT is too small](#the-nat-is-too-small)
- [Log messages](#log-messages)

## Workers can't reach the internet

1. **Is a NAT forwarding?** [Find the owner](operations.md#find-the-owner)
   and check that its latest `health round` shows `"serving":true`. If no
   NAT holds the shared ENI, read both NATs' logs for the reason.
2. **Is it a new pair?** Each NAT installs natpair at first boot and reboots
   before natpair starts. If a NAT never logs anything, read its boot log
   in `/var/log/cloud-init-output.log`. The usual causes are a download that
   keeps failing and a SHA-256 that doesn't match the release
   (`release.tar.gz: FAILED`).
3. **Does the worker's route table send `0.0.0.0/0` to the shared ENI?** Its
   target must be the module's `shared_eni_id`.
4. **Is the worker inside `worker_cidrs`?** The NATs forward traffic only from
   those CIDRs, which default to the VPC's. If you set them yourself, a subnet
   routed to the pair but missing from them gets no internet access. So does
   one in a CIDR added to the VPC after the NATs launched.
5. **Do the NATs' own uploads work?** If the owner's health rounds show
   `"healthy":true` but workers still fail, the problem is between the
   workers and the NAT, such as a network ACL or the workers' security
   group. natpair can't detect this, which is why
   [an egress check on the workers](operations.md#monitoring) matters.

## The standby isn't ready

The standby's `health round` shows `"ready":false`. The pair can't fail over
with copied connections until it's fixed. The other fields say why:

- **`"healthy":false` with a `probe_error`.** The standby's own path to the
  internet fails. Check its Elastic IP, the public subnet's route to the
  internet gateway, and the error itself.
- **`"copied":false`.** The standby's copy is missing the owner's recent
  connections. Check conntrackd on both NATs with
  `sudo systemctl status conntrackd`, and look for the conntrackd messages
  below. A standby that just started needs two rounds, about 10 s, to catch
  up.
- **`"peer_ready":false` and `"peer_tracked_connections":0` while the owner
  is running.** The standby can't read the owner's reports. Look for
  `failed to read the peer's report`.

## An upgrade doesn't finish

A NAT that doesn't run the pinned release logs an `update` line every minute.
Its `reason` field says what it's waiting for:

| `reason` | What to do |
| --- | --- |
| `maintenance was requested by hand` | Run `sudo natpair resume` on that NAT when you're done with it. |
| `this NAT's health checks are stale` | The daemon's health checks have stopped. Read the rest of its log. |
| `the peer isn't serving with a working path, so this NAT stays ready to take over` | The standby waits for the owner to be healthy before it upgrades. Fix the owner first. |
| `waiting for the peer to run the pinned release and be ready` | The owner waits for the standby. Check the standby's log for a failed install or a failed `health round`. |
| `waiting for the peer to stay ready` | Normal. The owner hands over after the standby has been ready for 2 minutes. |

A failed install logs `update pass failed` with the error, and the NAT tries
again every 10 minutes. `download has SHA-256 ..., expected ...` means
`release_sha256` doesn't match the release. Copy it again from
`checksums.txt`, for `natpair_linux_arm64.tar.gz`.
`release ... rejects this NAT's configuration, so replace this NAT` means the
new release needs configuration this NAT didn't get at first boot. Replace
the NATs one at a time, as in [Replace a NAT](operations.md#replace-a-nat).

## The NAT is too small

- **Network limits.** Rising `allowance_exceeded` counters mean AWS is
  queuing or dropping packets at the instance's limits. Read them with
  `sudo ethtool -S <interface> | grep allowance`, or in Datadog as
  `system.net.aws.ec2.*_allowance_exceeded`. Move to an instance type with
  more baseline bandwidth, as in
  [Replace a NAT](operations.md#replace-a-nat).
- **Connection table full.** When the table reaches `max_connections`, the
  kernel drops new connections and logs `nf_conntrack: table full, dropping
  packet` in `sudo dmesg`. Raise `max_connections` and replace the NATs. Each
  262,144 connections uses about 160 MB of memory, half in the kernel and half
  in conntrackd.

## Log messages

Warnings that need attention:

### `forced the stuck shared ENI detach`

The full message ends with `Stop and start the NAT it was attached to before
it serves again.` The new owner forced the shared ENI off a NAT that was still
running. AWS may keep showing that NAT as attached, so it can't take the ENI
back cleanly. Stop and start the NAT named in the `instance` field. A reboot
isn't enough. When the old NAT was already stopping or gone, natpair logs an
info message that needs no action instead.

### `lease store unreachable, forwarding on while the shared ENI stays here`

The owner can't reach DynamoDB. It keeps forwarding, and no NAT can take over
until DynamoDB is back. Check that the DynamoDB gateway endpoint is still on
the public route table, and that the NATs' IAM role is intact. The owner logs
`lease store reachable again` when it recovers.

### `taking over without copied connections`

A NAT took over without loading the copies, usually because its conntrackd
was down. Existing connections were reset. Check conntrackd on that NAT.

### `conntrackd is not answering, so connections are not being copied`

natpair can't talk to conntrackd on this NAT. Check
`sudo systemctl status conntrackd` and `sudo journalctl -u conntrackd`. If this
NAT takes over before conntrackd is back, existing connections are reset.

### `copied connections are incomplete, requesting a full copy from the peer`

The standby's copy missed some of the owner's oldest connections for two
rounds, so it asks the owner for a full copy. This fixes itself. If it repeats
for more than 5 minutes, check the network between the NATs and
conntrackd on both.

### `shared Elastic IP not working yet, trying again`

During a takeover, the new owner's test upload through the shared Elastic IP
failed, so it hasn't opened forwarding yet. They're normal for up to about
10 s while AWS moves the ENI. If they continue, check that the Elastic IP is still
associated with the shared ENI.

### `overload guard engaged`

The full message is `overload guard engaged: the CPU can't forward everything
the shared ENI receives, so it drops worker packets past a budget`. Workers
send more packets than the owner's CPU forwards, so it drops about a tenth of
them, and more if they keep coming faster, to keep its own path probe
working. `busiest_cpu` and `nic_drop_share` show the overload it saw, and
`budget_pps_per_cpu` how many packets a second each CPU now forwards. While
the NIC still drops packets, it logs `overload guard lowered its budget`
once a second, down to half of `measured_pps_per_cpu`. It logs
`overload guard cleared`, with how many packets it `dropped`, once the
traffic fits the budget again.

Find the worker sending the most packets, often small UDP, and slow it down,
or move to an instance type with more CPUs, as in
[Replace a NAT](operations.md#replace-a-nat).

### `overload guard failed`

The daemon couldn't attach or run the overload guard, and the `err` field
says why. The NAT forwards as it would without the guard. If `err` says
`failed to attach the overload guard`, check that nothing else attached an
XDP program to the shared ENI (`ip -d link show`), and that its MTU is at
most 3,502 bytes, the most ENA allows with XDP. The daemon tries again at
the next overload, and logs the same failure once. `overload guard failed
to raise the receive ring` means it sheds the flood with the ring's current
size.

### `this boot was prepared by another release, so this NAT reports none until it reboots`

This NAT took over while it was installing a release, so it runs a binary it
didn't boot with and doesn't count as ready. Once it's the standby again, the
updater reinstalls the pinned release and reboots it. No action is needed.
