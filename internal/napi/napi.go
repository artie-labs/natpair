// Package napi moves the network interfaces' receive processing into kernel
// threads, and runs the primary interface's threads ahead of the shared ENI's.
//
// By default Linux processes received packets in softirq context, which runs
// ahead of every process. On AWS, a one-CPU NAT forwarding at full load spent
// 84 to 95% of its CPU there. Its daemon's DNS lookups, lease renewals and
// probes then timed out, so it stepped down, and the standby saturated in
// turn. Threaded NAPI (Linux 5.12 and later) does this work in kernel threads
// named "napi/<interface>-<id>" instead, which the scheduler shares with the
// daemon.
//
// Worker traffic in both directions arrives on the shared ENI. The primary
// interface receives only the NAT's own traffic, such as lease and AWS API
// replies, DNS and conntrackd's copies, so its threads get the daemon's
// priority.
package napi

import (
	"fmt"
	"strconv"
	"strings"
)

// OwnNice is the nice value of the primary interface's receive threads. It
// gives them about ten times the CPU weight of the shared ENI's threads,
// which keep the default of 0, as natpair.slice's CPUWeight=1000 does for the
// daemon and conntrackd.
const OwnNice = -10

// pfKthread is the PF_KTHREAD bit of the flags field in /proc/<pid>/stat,
// which only kernel threads have.
const pfKthread = 0x00200000

// task is one entry of /proc.
type task struct {
	pid    int
	name   string
	kernel bool
	nice   int
}

// parseStat parses the contents of /proc/<pid>/stat, such as
// "812 (napi/ens5-8193) S 2 0 0 0 -1 2129984 ... 20 0 1 0 ...". The name can
// hold spaces and parentheses, so the fields after it are found from the last
// ")". See proc_pid_stat(5) for the fields.
func parseStat(stat string) (task, error) {
	open, end := strings.IndexByte(stat, '('), strings.LastIndexByte(stat, ')')
	if open < 0 || end < open {
		return task{}, fmt.Errorf("failed to find the name in %q", stat)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(stat[:open]))
	if err != nil {
		return task{}, fmt.Errorf("failed to parse the PID in %q: %w", stat, err)
	}
	// fields[0] is field 3 of proc_pid_stat(5), state.
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 17 {
		return task{}, fmt.Errorf("too few fields in %q", stat)
	}
	flags, err := strconv.ParseUint(fields[6], 10, 64)
	if err != nil {
		return task{}, fmt.Errorf("failed to parse the flags in %q: %w", stat, err)
	}
	nice, err := strconv.Atoi(fields[16])
	if err != nil {
		return task{}, fmt.Errorf("failed to parse the nice value in %q: %w", stat, err)
	}
	return task{pid: pid, name: stat[open+1 : end], kernel: flags&pfKthread != 0, nice: nice}, nil
}

// primaryThreads returns the PIDs of the kernel threads that process
// primary's receive queues and don't yet run at OwnNice. Any process can
// name itself "napi/...", so only kernel threads count.
func primaryThreads(tasks []task, primary string) []int {
	var pids []int
	for _, t := range tasks {
		if t.kernel && strings.HasPrefix(t.name, "napi/"+primary+"-") && t.nice != OwnNice {
			pids = append(pids, t.pid)
		}
	}
	return pids
}
