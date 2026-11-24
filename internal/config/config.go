// Package config loads and validates the NAT configuration file.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/artie-labs/natpair/internal/instance"
	"github.com/artie-labs/natpair/internal/probe"
)

const (
	// StateDir holds the maintenance request file and conntrackd's files.
	StateDir = "/var/lib/natpair"
	// BPFDir is where the fence pins its BPF objects.
	BPFDir = "/sys/fs/bpf/natpair"
	// ConntrackdConfigPath is where bootstrap writes conntrackd's configuration.
	ConntrackdConfigPath = StateDir + "/conntrackd.conf"
	// BootedReleasePath is where bootstrap records its release. /run is
	// cleared at every boot, so the file names the release that prepared
	// this boot.
	BootedReleasePath = "/run/natpair/release"
	// DefaultReleaseURL is where releases are downloaded from when the
	// configuration doesn't set release_url: natpair's GitHub releases.
	DefaultReleaseURL = "https://github.com/artie-labs/natpair/releases/download"
	// fallbackMaxConnections is the connection limit when the configuration
	// doesn't set max_connections and the instance's memory couldn't be read:
	// the limit sized for 2 GiB, and natpair's default before it sized the
	// limit from memory.
	fallbackMaxConnections = 262144
	// peakBytesPerConnection is the memory counted per connection at a NAT's
	// peak, right after a takeover. On AWS a NAT used about 2.3 KB, and 2.6 KB
	// leaves room. Without max_connections, the limit is the largest whose
	// peak fits in half of the instance's memory.
	peakBytesPerConnection = 2600
	// gatewayCapMbps is AWS's cap on an instance's traffic to an internet
	// gateway when it has fewer than 32 vCPUs. From 32 vCPUs, the cap is half
	// the instance's bandwidth. Every worker upload a NAT forwards goes there.
	gatewayCapMbps = 5000
	// gatewayCapVCPUs is the smallest vCPU count whose internet gateway cap
	// is half the instance's bandwidth instead of gatewayCapMbps.
	gatewayCapVCPUs = 32
	// gatewayCapPercent and baselinePercent set the computed upload rate:
	// 95% of the gateway cap or 90% of the baseline bandwidth, whichever is
	// lower. AWS holds traffic over the gateway cap back without dropping it,
	// so 95% passed with no drops on AWS. Over the baseline, once the burst
	// is spent, AWS drops. It counts what the NAT receives as well as what
	// it sends, and downloads to workers and the NAT's own traffic leave
	// through the primary interface, outside the cap. On a c7gn.medium, 95%
	// dropped when downloads were 5% of uploads, and 90% didn't.
	gatewayCapPercent = 95
	baselinePercent   = 90
)

// maxConnectionsAllowed lists the limits max_connections accepts. The owner
// holds its table twice: in the kernel, about 0.4 KB a connection on AWS, and
// in conntrackd's cache, about 0.55 KB. The standby holds conntrackd's copy.
// Right after a takeover, conntrackd holds both the table it tracks and the
// copy it received, and doesn't give memory back, so a NAT peaks at about
// 2.3 KB a connection. natpair's own memory doesn't grow with the table. On
// AWS, 2,097,152 connections on a 4 GiB NAT got conntrackd killed for lack of
// memory.
var maxConnectionsAllowed = []int{65536, 131072, 262144, 524288, 1048576, 2097152, 4194304}

// The canary subnets come from 198.18.0.0/15, which is reserved for network
// tests and so unlikely to be used in a VPC. Validate rejects protected_cidrs
// that overlap them.
var (
	ownCanaryCIDR    = netip.MustParsePrefix("198.18.0.0/30")
	sharedCanaryCIDR = netip.MustParsePrefix("198.18.0.4/30")
)

// Canary is a dedicated network namespace whose /30 subnet sends probe
// uploads through the NAT. It is exempt from the worker fence, so it can
// verify a path while workers are still blocked.
type Canary struct {
	Namespace string       `json:"namespace"`
	CIDR      netip.Prefix `json:"cidr"`
}

// Host returns the NAT side of the canary link.
func (c Canary) Host() netip.Addr {
	return c.CIDR.Masked().Addr().Next()
}

// Guest returns the namespace side of the canary link, which sends probes.
func (c Canary) Guest() netip.Addr {
	return c.Host().Next()
}

// NAT configures one NAT in the pair. Facts about the instance itself, such
// as its ID, region and addresses, come from the instance metadata service
// instead (see [NAT.Instance]).
type NAT struct {
	// LeaseTable and Pair locate the lease record.
	LeaseTable string `json:"lease_table"`
	Pair       string `json:"pair"`

	// SharedENI moves between the NATs. Worker route tables target it, and the
	// shared Elastic IP is associated with its private IP.
	SharedENI string `json:"shared_eni"`
	// SharedAddress is the shared ENI's private IP with its subnet's prefix
	// length, such as "10.0.1.100/24".
	SharedAddress netip.Prefix `json:"shared_address"`
	// SharedPublicIP is the shared Elastic IP, seen by the receiver while serving.
	SharedPublicIP netip.Addr `json:"shared_public_ip"`

	// ProtectedCIDRs are the sources this NAT forwards and translates to the
	// shared address, all behind the fence. They may hold this NAT's own
	// addresses, such as when they are the whole VPC.
	ProtectedCIDRs []netip.Prefix `json:"protected_cidrs"`

	// ProbeURL is the probe receiver, the Terraform module's receiver_url.
	ProbeURL string `json:"probe_url"`

	// PeerIP is the other NAT's primary private IP, which conntrackd copies
	// connections to. It must be in this NAT's own subnet, because the NAT
	// routes to it directly, without a gateway. The Terraform module puts both
	// NATs in one subnet.
	PeerIP netip.Addr `json:"peer_ip"`

	// MaxConnections is the most connections conntrackd copies and the
	// kernel's connection table holds. Zero sizes it from the instance's
	// memory (see ConnectionLimit). Bootstrap applies it at every boot.
	MaxConnections int `json:"max_connections,omitempty"`

	// Shaping, when set, caps uploads through the shared ENI and shares them
	// fairly between workers. Nil, the default, leaves uploads unshaped.
	Shaping *Shaping `json:"shaping,omitempty"`

	// ReleaseURL is where the updater downloads releases from: an https:// or
	// s3:// prefix that holds "<tag>/natpair_linux_arm64.tar.gz". Empty means
	// DefaultReleaseURL.
	ReleaseURL string `json:"release_url,omitempty"`

	// Instance holds facts read from the instance metadata service at
	// startup. It is not part of the file.
	Instance instance.Facts `json:"-"`
}

// Shaping caps the owner's uploads, the traffic workers send out through the
// shared ENI, below the instance's network limits, and shares the cap fairly
// between workers by their address before NAT. Without it, AWS drops or holds
// back packets at those limits, whichever worker sent them, so one worker's
// backfill can slow every other worker's connections.
type Shaping struct {
	// RateMbps is the cap in Mbit/s. Zero computes it from the instance type
	// (see UploadRate).
	RateMbps int `json:"rate_mbps,omitempty"`
}

// LoadNAT reads and validates a NAT configuration.
func LoadNAT(path string) (NAT, error) {
	var cfg NAT
	if err := load(path, &cfg); err != nil {
		return NAT{}, err
	}
	return cfg, cfg.Validate()
}

// Validate reports the first invalid or missing setting.
func (c NAT) Validate() error {
	required := map[string]string{"lease_table": c.LeaseTable, "pair": c.Pair, "shared_eni": c.SharedENI}
	for name, value := range required {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	for name, addr := range map[string]netip.Addr{"shared_public_ip": c.SharedPublicIP, "peer_ip": c.PeerIP} {
		if !addr.Is4() {
			return fmt.Errorf("%s must be an IPv4 address", name)
		}
	}
	if len(c.ProtectedCIDRs) == 0 {
		return fmt.Errorf("protected_cidrs is required")
	}
	for _, prefix := range c.ProtectedCIDRs {
		if !prefix.Addr().Is4() || prefix != prefix.Masked() {
			return fmt.Errorf("protected_cidrs entry %s must be an IPv4 network address", prefix)
		}
		if prefix.Overlaps(ownCanaryCIDR) || prefix.Overlaps(sharedCanaryCIDR) {
			return fmt.Errorf("protected_cidrs entry %s overlaps the canary subnets in 198.18.0.0/29", prefix)
		}
	}
	if c.ReleaseURL != "" && !strings.HasPrefix(c.ReleaseURL, "https://") && !strings.HasPrefix(c.ReleaseURL, "s3://") {
		return fmt.Errorf("release_url must start with https:// or s3://")
	}
	if c.MaxConnections != 0 && !slices.Contains(maxConnectionsAllowed, c.MaxConnections) {
		return fmt.Errorf("max_connections must be one of %v", maxConnectionsAllowed)
	}
	if c.Shaping != nil && c.Shaping.RateMbps < 0 {
		return fmt.Errorf("shaping.rate_mbps must be 0, to compute it from the instance type, or more")
	}
	if !c.SharedAddress.Addr().Is4() || c.SharedAddress.Bits() < 16 || c.SharedAddress.Bits() > 28 {
		return fmt.Errorf("shared_address must be an IPv4 address with its subnet prefix length, such as 10.0.1.100/24")
	}
	return checkReceiver("probe_url", c.ProbeURL)
}

// Releases returns ReleaseURL without a trailing slash, or DefaultReleaseURL if
// unset.
func (c NAT) Releases() string {
	if c.ReleaseURL == "" {
		return DefaultReleaseURL
	}
	return strings.TrimRight(c.ReleaseURL, "/")
}

// ConnectionLimit returns MaxConnections if set. Otherwise it returns the
// largest of maxConnectionsAllowed whose peak memory, peakBytesPerConnection
// each, fits in half of Instance.MemoryBytes, or the smallest if none does:
// 262,144 for 2 GiB, 524,288 for 4 GiB and 1,048,576 for 8 GiB. Without a
// memory reading it returns fallbackMaxConnections.
func (c NAT) ConnectionLimit() int {
	limit, _ := c.connectionLimit()
	return limit
}

// LogConnectionLimit logs ConnectionLimit and why it was chosen.
func (c NAT) LogConnectionLimit() {
	limit, reason := c.connectionLimit()
	slog.Info("connection limit", slog.Int("max_connections", limit), slog.String("reason", reason),
		slog.Uint64("memory_bytes", c.Instance.MemoryBytes))
}

func (c NAT) connectionLimit() (int, string) {
	switch {
	case c.MaxConnections != 0:
		return c.MaxConnections, "set by max_connections"
	case c.Instance.MemoryBytes == 0:
		return fallbackMaxConnections, "the instance's memory couldn't be read"
	}
	limit := maxConnectionsAllowed[0]
	for _, allowed := range maxConnectionsAllowed {
		if uint64(allowed)*peakBytesPerConnection <= c.Instance.MemoryBytes/2 {
			limit = allowed
		}
	}
	return limit, "the largest whose peak memory fits in half of the instance's"
}

// UploadRate returns the rate in Mbit/s the owner caps uploads at, or 0 to
// leave them unshaped: 0 without Shaping, Shaping.RateMbps if set, and
// otherwise 95% of the instance's internet gateway cap or 90% of its baseline
// bandwidth, whichever is lower. That is 2,812 for a c7gn.medium and 4,750
// for a c7gn.large or c7gn.xlarge. Without Instance.Bandwidth it returns 0,
// since a cap computed from a wrong guess could slow every worker.
func (c NAT) UploadRate() int {
	rate, _ := c.uploadRate()
	return rate
}

// LogUploadRate logs UploadRate and why it was chosen.
func (c NAT) LogUploadRate() {
	rate, reason := c.uploadRate()
	attrs := []any{slog.Int("rate_mbps", rate), slog.String("reason", reason)}
	if c.Instance.Bandwidth.BaselineMbps > 0 {
		attrs = append(attrs, slog.String("instance_type", c.Instance.Type), slog.Int("baseline_mbps", c.Instance.Bandwidth.BaselineMbps), slog.Int("vcpus", c.Instance.Bandwidth.VCPUs))
	}
	if rate == 0 && c.Shaping != nil {
		slog.Warn("uploads aren't shaped", attrs...)
		return
	}
	slog.Info("upload rate", attrs...)
}

func (c NAT) uploadRate() (int, string) {
	bandwidth := c.Instance.Bandwidth
	switch {
	case c.Shaping == nil:
		return 0, "shaping isn't set"
	case c.Shaping.RateMbps != 0:
		return c.Shaping.RateMbps, "set by shaping.rate_mbps"
	case bandwidth.BaselineMbps <= 0:
		return 0, "the instance type's bandwidth couldn't be read"
	}
	gateway := gatewayCapMbps
	if bandwidth.VCPUs >= gatewayCapVCPUs {
		gateway = bandwidth.BaselineMbps / 2
	}
	return min(gateway*gatewayCapPercent/100, bandwidth.BaselineMbps*baselinePercent/100),
		"95% of the internet gateway cap or 90% of the baseline bandwidth, whichever is lower"
}

// OwnCanary sends probes out through this NAT's own public IP.
func (c NAT) OwnCanary() Canary {
	return Canary{Namespace: "natpair-own", CIDR: ownCanaryCIDR}
}

// SharedCanary sends probes out through the shared Elastic IP.
func (c NAT) SharedCanary() Canary {
	return Canary{Namespace: "natpair-shared", CIDR: sharedCanaryCIDR}
}

// OwnProbe sends uploads out through this NAT's own public IP.
func (c NAT) OwnProbe() probe.Target {
	return c.target(c.OwnCanary(), c.Instance.PublicIP)
}

// SharedProbe sends uploads out through the shared Elastic IP.
func (c NAT) SharedProbe() probe.Target {
	return c.target(c.SharedCanary(), c.SharedPublicIP)
}

func (c NAT) target(canary Canary, expected netip.Addr) probe.Target {
	return probe.Target{URL: c.ProbeURL, ExpectedIP: expected, Namespace: canary.Namespace, Source: canary.Guest()}
}

// LeaseRecordID returns the DynamoDB key for a record in this pair.
func (c NAT) LeaseRecordID(name string) string {
	return recordID(c.Pair, name)
}

// recordID returns the DynamoDB key for a record in pair. The Terraform
// module's IAM policy grants access to these exact keys, so change both
// together.
func recordID(pair, name string) string {
	return pair + "/v3/" + name
}

const (
	// BoardRecord names the record where the NATs post reports.
	BoardRecord = "health"
	// ReleaseRecord names the record where Terraform pins the pair's release.
	ReleaseRecord = "release"
)

// checkReceiver requires an HTTPS receiver URL.
func checkReceiver(name, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return fmt.Errorf("%s %q must be an HTTPS URL", name, raw)
	}
	return nil
}

func load(path string, value any) error {
	contents, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("failed to parse config %q: %w", path, err)
	}
	return nil
}
