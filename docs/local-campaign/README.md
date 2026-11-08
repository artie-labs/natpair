# Local fault campaign

`make test-campaign` runs two real natpair NATs inside one disposable,
privileged Docker container. Network namespaces stand in for the hosts: NATs
`a` and `b`, a `worker`, and a `receiver` outside the pair. Each NAT also has
its own mount namespace, so like a separate instance it has its own
`/var/lib/natpair`, BPF filesystem and the namespaces its probes run in.
conntrackd really copies connection state, iptables and the kernel forwarding
deadline are real, and the NATs run the real binary. The lease uses a fake
DynamoDB endpoint, and a takeover moves neighbor entries instead of EC2
interfaces. Nothing calls AWS.

The NATs forward from the worker subnet and from the subnet they reach the
lease through, which holds their own addresses. That matches the default on
AWS, where the NATs forward from the whole VPC, their own addresses
included, and their own traffic must still leave from those addresses.

## Latest results

All 17 cases passed, recorded in [results.json](results.json) and
[environment.json](environment.json). The
container runs Amazon Linux 2023 with conntrackd 1.4.6 and Go 1.26, on Linux
7.0 under Docker Desktop.

| Case | Outcome |
| --- | --- |
| Healthy baseline | A serves. B holds copied connections and stands by. |
| Owner service stopped | A closed its fence and released the lease. B took over in 0.5 s. The 18-second upload finished on its original connection, with at most 0.7 s without progress. |
| Owner process killed | B took over in 6.4 s. The upload survived with at most 3.2 s without progress. |
| Owner process frozen | B took over in 6.5 s. The upload survived with at most 3.2 s without progress. A stayed closed after waking. |
| Large packets dropped on A | Upload probes detected it. B confirmed the failure by proving its own path, A stepped down and released the lease, and B took over in 4.4 s. The upload survived with at most 6.4 s without progress. |
| Planned maintenance | A released the lease and B took over in 0.5 s. The upload survived with at most 0.7 s without progress. Maintenance held across a restart. |
| Worker-side path failure | A dropped all forwarded worker traffic while its own probes kept working. A kept serving and B stayed standby, as designed, because natpair only tests its own uploads. An egress check on the workers is what catches this case. |
| Large packets dropped on the way back in | Probes detected it, because the receiver sends each upload back, and B took over in 5.4 s. |
| Connection unknown to the new owner | B received no copies, then A was killed. After B took over, the client got a TCP reset 0.3 s later and could reconnect, instead of hanging until its own 30 s timeout. |
| Standby restarted before a handover | An idle worker connection stayed open while B's conntrackd restarted. B asked A for the whole table at startup, and after maintenance moved traffic to B, the connection kept working with a 0.03 s pause. |
| Probe receiver down | Both NATs' uploads failed. B could not prove its own path, so it never confirmed a failure of A, and A kept serving. Worker traffic was unaffected. |
| Probe receiver down, then the owner killed | B took the lease as a last resort with its path unproven and took over in 6.4 s. A NAT that can't prove its path waits 2 s longer than one that can. Depending on whether that wait overlaps the 6 s lease wait, runs took 6.4 to 8.6 s. New connections worked through B, and B proved its path once the receiver was back. |
| Maintenance with an unhealthy standby | A kept serving while B could not forward. Once B recovered, A handed over. |
| Lease service down for both NATs | For 10 s, longer than the 4 s hold and the 6 s takeover wait, A kept forwarding and B never took over. The upload never paused for more than 0.1 s. Once the service returned, A renewed its own lease. |
| Lease service down for the owner only | B took the lease after the 6 s wait and moved the shared path, taking over in 6.4 s. A kept forwarding until then, so the upload never paused for more than 0.2 s. Once A reached the service again, it saw B's lease and closed. |
| Standby's conntrackd down, then the owner killed | B took over in 6.6 s without copied connections, and new connections worked. |
| Kernel deadline without a controller | Forwarding worked before the deadline and stopped at it. Repeated fence installs did not stack guard rules. |

Each case is one trial, not a statistical sample. The results files hold the
latest run. Across recent runs on Amazon Linux 2023, takeover took 0.1 to
0.5 s after a service stop and 0.3 to 0.9 s for maintenance, and the longest
pause stayed under 0.7 s for both. A crash or freeze took 6.4 to 7.2 s with a
3.2 s pause. Large-packet loss took 4.4 to 5.5 s with a 6.4 s pause. Takeover is timed until B's kernel
forwarding deadline opens. TCP backs off retransmissions exponentially, so the
upload resumes at whichever retry first follows the takeover.

These are local measurements. On AWS, a takeover itself takes about 9 s, mostly
spent moving the shared ENI, so a crash takes about 16 s and a planned handover
about 10 s. The [README](../../README.md#when-something-fails) lists the AWS
times.

