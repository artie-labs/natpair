// Package config loads and validates the NAT configuration file.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/artie-labs/natpair/internal/instance"
	"github.com/artie-labs/natpair/internal/probe"
)

const (
	// StateDir holds the maintenance request file and conntrackd's files.
	StateDir = "/var/lib/natpair"
	// BPFDir is where the fence pins its BPF objects.
	BPFDir = "/sys/fs/bpf/natpair"
	// PacingBPFDir is where pacing pins its BPF programs.
	PacingBPFDir = BPFDir + "/pacing"
	// PacingOffPath turns pacing off while it exists. `natpair pacing-off`
	// creates it.
	PacingOffPath = StateDir + "/pacing-off"
	// ConntrackdConfigPath is where bootstrap writes conntrackd's configuration.
	ConntrackdConfigPath = StateDir + "/conntrackd.conf"
	// BootedReleasePath is where bootstrap records its release. /run is
	// cleared at every boot, so the file names the release that prepared
	// this boot.
	BootedReleasePath = "/run/natpair/release"
	// DefaultReleaseURL is where releases are downloaded from when the
	// configuration doesn't set release_url: natpair's GitHub releases.
	DefaultReleaseURL = "https://github.com/artie-labs/natpair/releases/download"
	// DefaultMaxConnections is the connection limit when the configuration
	// doesn't set max_connections.
	DefaultMaxConnections = 262144
	// DefaultPacingPoll is how often pacing reads the instance's allowance
	// counters when the configuration doesn't set poll_interval_ms. ENA
	// refreshes them at least every millisecond, and one read takes about
	// 0.2 ms and 40 µs of CPU, so a cut follows AWS's first drops within tens
	// of milliseconds.
	DefaultPacingPoll = 10 * time.Millisecond
)

// maxConnectionsAllowed lists the limits max_connections accepts. The hash
// tables are a quarter of the limit, so powers of two keep them even. A full
// table costs about 80 MB in the kernel per 262,144 connections, and about
// as much again in conntrackd.
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
	// connections to.
	PeerIP netip.Addr `json:"peer_ip"`

	// MaxConnections is the most connections conntrackd copies and the
	// kernel's connection table holds. Zero means DefaultMaxConnections.
	// Bootstrap applies it at every boot.
	MaxConnections int `json:"max_connections,omitempty"`

	// ReleaseURL is where the updater downloads releases from: an https:// or
	// s3:// prefix that holds "<tag>/natpair_linux_arm64.tar.gz". Empty means
	// DefaultReleaseURL.
	ReleaseURL string `json:"release_url,omitempty"`

	// Pacing paces forwarded worker traffic just under the instance's network
	// allowances. Nil means off.
	Pacing *Pacing `json:"pacing,omitempty"`

	// Instance holds facts read from the instance metadata service at
	// startup. It is not part of the file.
	Instance instance.Facts `json:"-"`
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
	if !c.SharedAddress.Addr().Is4() || c.SharedAddress.Bits() < 16 || c.SharedAddress.Bits() > 28 {
		return fmt.Errorf("shared_address must be an IPv4 address with its subnet prefix length, such as 10.0.1.100/24")
	}
	if err := c.Pacing.validate(); err != nil {
		return err
	}
	return checkReceiver("probe_url", c.ProbeURL)
}

// Pacing configures traffic pacing. The daemon reads it at startup.
type Pacing struct {
	// Enabled turns pacing on. Off, natpair installs nothing.
	Enabled bool `json:"enabled"`
	// StartMbps is the bandwidth cap, in megabits per second, that a NAT
	// starts from. Zero starts with no bandwidth cap until the instance first
	// reports exceeding its bandwidth allowance.
	StartMbps int `json:"start_mbps,omitempty"`
	// StartKpps is the packet rate cap, in thousands of packets per second,
	// that a NAT starts from. Zero starts with no packet rate cap until the
	// instance first reports exceeding its packet rate allowance.
	StartKpps int `json:"start_kpps,omitempty"`
	// PollIntervalMS is how often, in milliseconds, the NAT reads the
	// instance's allowance counters. Zero means DefaultPacingPoll.
	PollIntervalMS int `json:"poll_interval_ms,omitempty"`
}

// On reports whether pacing is configured on. A nil Pacing is off.
func (p *Pacing) On() bool {
	return p != nil && p.Enabled
}

// Poll returns PollIntervalMS as a duration, or DefaultPacingPoll if unset.
func (p *Pacing) Poll() time.Duration {
	if p == nil || p.PollIntervalMS == 0 {
		return DefaultPacingPoll
	}
	return time.Duration(p.PollIntervalMS) * time.Millisecond
}

func (p *Pacing) validate() error {
	if p == nil {
		return nil
	}
	if p.StartMbps < 0 || p.StartKpps < 0 {
		return fmt.Errorf("pacing start_mbps and start_kpps must not be negative")
	}
	if p.PollIntervalMS != 0 && (p.PollIntervalMS < 1 || p.PollIntervalMS > 60000) {
		return fmt.Errorf("pacing poll_interval_ms must be from 1 to 60000")
	}
	return nil
}

// Releases returns ReleaseURL without a trailing slash, or DefaultReleaseURL if
// unset.
func (c NAT) Releases() string {
	if c.ReleaseURL == "" {
		return DefaultReleaseURL
	}
	return strings.TrimRight(c.ReleaseURL, "/")
}

// ConnectionLimit returns MaxConnections, or DefaultMaxConnections if unset.
func (c NAT) ConnectionLimit() int {
	if c.MaxConnections == 0 {
		return DefaultMaxConnections
	}
	return c.MaxConnections
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
