// Package instance reads facts about this EC2 instance from the instance
// metadata service, so they never have to be copied into a config file.
package instance

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

// Facts describe this instance.
type Facts struct {
	ID     string
	Region string
	// PrivateIP is the primary private IP, on Interface.
	PrivateIP netip.Addr
	// PublicIP is the public IP of the primary interface.
	PublicIP netip.Addr
	// Interface is the primary network interface's name, such as ens5.
	Interface string
	// VPCCIDRs are the IPv4 CIDRs of the instance's VPC.
	VPCCIDRs []netip.Prefix
}

// Discover reads the facts from the instance metadata service. The AWS SDK's
// AWS_EC2_METADATA_SERVICE_ENDPOINT variable points it elsewhere, as the local
// campaign does.
func Discover(ctx context.Context, cfg aws.Config) (Facts, error) {
	client := imds.NewFromConfig(cfg)
	get := func(path string) (string, error) {
		output, err := client.GetMetadata(ctx, &imds.GetMetadataInput{Path: path})
		if err != nil {
			return "", fmt.Errorf("failed to read %s from the instance metadata service: %w", path, err)
		}
		defer output.Content.Close()
		value, err := io.ReadAll(output.Content)
		return strings.TrimSpace(string(value)), err
	}
	var facts Facts
	var values [5]string
	for i, path := range []string{"instance-id", "placement/region", "local-ipv4", "public-ipv4", "mac"} {
		value, err := get(path)
		if err != nil {
			return Facts{}, err
		}
		values[i] = value
	}
	facts.ID, facts.Region = values[0], values[1]
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
	return facts, nil
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
