package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// pfKthread is the kernel's PF_KTHREAD flag in /proc/<pid>/stat. Any
// process can name itself like a receive thread, but only kernel threads
// have this flag.
const pfKthread = 0x00200000

// receiveThreads returns the process IDs of the threaded NAPI receive
// threads of iface, which the kernel names "napi/<iface>-<id>", from the
// proc filesystem at root.
func receiveThreads(root, iface string) ([]int, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("failed to list processes: %w", err)
	}
	prefix := "napi/" + iface + "-"
	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		stat, err := os.ReadFile(filepath.Join(root, entry.Name(), "stat"))
		if err != nil {
			// It exited.
			continue
		}
		if comm, flags, ok := parseStat(string(stat)); ok && strings.HasPrefix(comm, prefix) && flags&pfKthread != 0 {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// parseStat returns the command name and flags from /proc/<pid>/stat. The
// name is in parentheses and may itself contain spaces or parentheses, so
// the fields after it start at the last ')'.
func parseStat(stat string) (string, uint64, bool) {
	open, end := strings.IndexByte(stat, '('), strings.LastIndexByte(stat, ')')
	if open < 0 || end < open {
		return "", 0, false
	}
	// state ppid pgrp session tty_nr tpgid flags
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 7 {
		return "", 0, false
	}
	flags, err := strconv.ParseUint(fields[6], 10, 64)
	if err != nil {
		return "", 0, false
	}
	return stat[open+1 : end], flags, true
}

// parseRings returns the receive ring's maximum and current size from the
// output of `ethtool -g <iface>`.
func parseRings(output string) (maximum, current int, err error) {
	section := ""
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Pre-set maximums"):
			section = "maximum"
		case strings.HasPrefix(line, "Current hardware settings"):
			section = "current"
		case strings.HasPrefix(line, "RX:"):
			value, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "RX:")))
			if err != nil {
				return 0, 0, fmt.Errorf("failed to parse the receive ring size %q: %w", line, err)
			}
			switch section {
			case "maximum":
				maximum = value
			case "current":
				current = value
			}
			section = ""
		}
	}
	if maximum == 0 || current == 0 {
		return 0, 0, fmt.Errorf("ethtool reported no receive ring size")
	}
	return maximum, current, nil
}
