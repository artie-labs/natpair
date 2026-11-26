// Package instance reads facts about this EC2 instance from the instance
// metadata service and the kernel, so they never have to be copied into a
// config file.
package instance

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// Facts describe this instance.
type Facts struct {
	ID     string
	Region string
	// Type is the instance type, such as c7gn.medium.
	Type string
	// PrivateIP is the primary private IP, on Interface.
	PrivateIP netip.Addr
	// PublicIP is the public IP of the primary interface.
	PublicIP netip.Addr
	// Interface is the primary network interface's name, such as ens5.
	Interface string
	// VPCCIDRs are the IPv4 CIDRs of the instance's VPC.
	VPCCIDRs []netip.Prefix
	// MemoryBytes is the instance's memory, MemTotal in /proc/meminfo, or 0
	// if it couldn't be read.
	MemoryBytes uint64
	// Bandwidth is the instance type's network limits. Discover leaves it
	// zero. ReadBandwidth fills it, only when traffic shaping needs it.
	Bandwidth Bandwidth
}

// Bandwidth is an instance type's network limits, from the EC2 API.
type Bandwidth struct {
	// BaselineMbps is the baseline bandwidth of the network card that holds
	// the primary interface, in Mbit/s: 3,125 for a c7gn.medium.
	BaselineMbps int
	// VCPUs is the instance type's default number of vCPUs.
	VCPUs int
}

// InstanceTypes is the part of the EC2 client ReadBandwidth uses.
type InstanceTypes interface {
	DescribeInstanceTypes(ctx context.Context, params *ec2.DescribeInstanceTypesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstanceTypesOutput, error)
}

// The memory a read of /proc/meminfo may report. Anything outside it, such as
// a misparsed unit, is treated as unreadable. The smallest arm64 instance has
// 512 MiB, and the largest a few TiB.
const (
	minMemoryBytes = 256 << 20
	maxMemoryBytes = 64 << 40
)

// meminfoPath is where Discover reads the instance's memory. Tests point it
// at a fixture.
var meminfoPath = "/proc/meminfo"

// Discover reads the facts from the instance metadata service. The AWS SDK's
// AWS_EC2_METADATA_SERVICE_ENDPOINT variable points it elsewhere, as the local
// campaign does.
func Discover(ctx context.Context, cfg aws.Config) (Facts, error) {
	client := imds.NewFromConfig(cfg)
	get := func(path string) (string, error) {
		return getMetadata(ctx, client, path)
	}
	var facts Facts
	var values [6]string
	for i, path := range []string{"instance-id", "placement/region", "local-ipv4", "public-ipv4", "mac", "instance-type"} {
		value, err := get(path)
		if err != nil {
			return Facts{}, err
		}
		values[i] = value
	}
	facts.ID, facts.Region, facts.Type = values[0], values[1], values[5]
	var err error
	if facts.PrivateIP, err = netip.ParseAddr(values[2]); err != nil {
		return Facts{}, fmt.Errorf("invalid private IP from the instance metadata service: %w", err)
	}
	if facts.PublicIP, err = netip.ParseAddr(values[3]); err != nil {
		return Facts{}, fmt.Errorf("invalid public IP from the instance metadata service: %w", err)
	}
	if facts.Interface, err = interfaceWithMAC(values[4]); err != nil {
		return Facts{}, err
	}
	cidrs, err := get("network/interfaces/macs/" + values[4] + "/vpc-ipv4-cidr-blocks")
	if err != nil {
		return Facts{}, err
	}
	for _, cidr := range strings.Fields(cidrs) {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return Facts{}, fmt.Errorf("invalid VPC CIDR from the instance metadata service: %w", err)
		}
		facts.VPCCIDRs = append(facts.VPCCIDRs, prefix)
	}
	if len(facts.VPCCIDRs) == 0 {
		return Facts{}, fmt.Errorf("the instance metadata service listed no VPC CIDRs")
	}
	facts.MemoryBytes = readMemory(meminfoPath)
	return facts, nil
}

// ReadBandwidth reads an instance type's baseline bandwidth and vCPUs from
// the EC2 API.
func ReadBandwidth(ctx context.Context, client InstanceTypes, instanceType string) (Bandwidth, error) {
	output, err := client.DescribeInstanceTypes(ctx, &ec2.DescribeInstanceTypesInput{InstanceTypes: []types.InstanceType{types.InstanceType(instanceType)}})
	if err != nil {
		return Bandwidth{}, fmt.Errorf("failed to describe instance type %s: %w", instanceType, err)
	}
	if len(output.InstanceTypes) != 1 {
		return Bandwidth{}, fmt.Errorf("EC2 described %d instance types for %s, not 1", len(output.InstanceTypes), instanceType)
	}
	info := output.InstanceTypes[0]
	if info.NetworkInfo == nil || info.VCpuInfo == nil || aws.ToInt32(info.VCpuInfo.DefaultVCpus) <= 0 {
		return Bandwidth{}, fmt.Errorf("EC2 didn't describe the network or vCPUs of instance type %s", instanceType)
	}
	card := aws.ToInt32(info.NetworkInfo.DefaultNetworkCardIndex)
	for _, nic := range info.NetworkInfo.NetworkCards {
		baseline := aws.ToFloat64(nic.BaselineBandwidthInGbps)
		if aws.ToInt32(nic.NetworkCardIndex) != card || baseline <= 0 {
			continue
		}
		return Bandwidth{BaselineMbps: int(math.Round(baseline * 1000)), VCPUs: int(aws.ToInt32(info.VCpuInfo.DefaultVCpus))}, nil
	}
	return Bandwidth{}, fmt.Errorf("EC2 didn't describe the baseline bandwidth of network card %d of instance type %s", card, instanceType)
}

// getMetadata reads one path from the instance metadata service.
func getMetadata(ctx context.Context, client *imds.Client, path string) (string, error) {
	output, err := client.GetMetadata(ctx, &imds.GetMetadataInput{Path: path})
	if err != nil {
		return "", fmt.Errorf("failed to read %s from the instance metadata service: %w", path, err)
	}
	defer output.Content.Close()
	value, err := io.ReadAll(output.Content)
	return strings.TrimSpace(string(value)), err
}

// readMemory returns MemTotal from the meminfo file at path in bytes, or 0
// after logging why it couldn't.
func readMemory(path string) uint64 {
	file, err := os.Open(path)
	if err == nil {
		defer file.Close()
		var memory uint64
		if memory, err = parseMemTotal(file); err == nil {
			return memory
		}
	}
	slog.Warn("failed to read this instance's memory", slog.String("path", path), slog.Any("err", err))
	return 0
}

// parseMemTotal returns the MemTotal line of /proc/meminfo, such as
// "MemTotal:        3884368 kB", in bytes.
func parseMemTotal(r io.Reader) (uint64, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || fields[0] != "MemTotal:" {
			continue
		}
		if len(fields) != 3 || fields[2] != "kB" {
			return 0, fmt.Errorf("unexpected MemTotal line %q", scanner.Text())
		}
		kilobytes, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("unexpected MemTotal line %q: %w", scanner.Text(), err)
		}
		if kilobytes < minMemoryBytes/1024 || kilobytes > maxMemoryBytes/1024 {
			return 0, fmt.Errorf("MemTotal of %d kB is outside %d to %d kB", kilobytes, minMemoryBytes/1024, maxMemoryBytes/1024)
		}
		return kilobytes * 1024, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("no MemTotal line")
}

// interfaceWithMAC returns the name of the local interface with mac.
func interfaceWithMAC(mac string) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to list network interfaces: %w", err)
	}
	for _, iface := range interfaces {
		if strings.EqualFold(iface.HardwareAddr.String(), mac) {
			return iface.Name, nil
		}
	}
	return "", fmt.Errorf("no network interface has the primary MAC address %s", mac)
}
