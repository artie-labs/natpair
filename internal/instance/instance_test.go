package instance

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeMetadata serves the instance metadata paths Discover reads, with the
// IMDSv2 token exchange.
func fakeMetadata(t *testing.T, mac string) {
	values := map[string]string{
		"instance-id":      "i-0123456789abcdef0",
		"placement/region": "us-east-2",
		"local-ipv4":       "10.0.1.10",
		"public-ipv4":      "192.0.2.10",
		"mac":              mac,
		// A VPC can have several CIDRs, one per line.
		"network/interfaces/macs/" + mac + "/vpc-ipv4-cidr-blocks": "10.0.0.0/16\n100.64.0.0/16",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/latest/api/token" {
			w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "21600")
			w.Write([]byte("token"))
			return
		}
		value, ok := values[r.URL.Path[len("/latest/meta-data/"):]]
		if !ok || r.Header.Get("X-Aws-Ec2-Metadata-Token") != "token" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(value))
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", server.URL)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "")
}

func TestDiscover(t *testing.T) {
	interfaces, err := net.Interfaces()
	require.NoError(t, err)
	var primary net.Interface
	for _, iface := range interfaces {
		if len(iface.HardwareAddr) > 0 {
			primary = iface
			break
		}
	}
	if primary.Name == "" {
		t.Skip("no interface with a MAC address")
	}
	{
		fakeMetadata(t, primary.HardwareAddr.String())
		cfg, err := awsconfig.LoadDefaultConfig(t.Context())
		require.NoError(t, err)
		facts, err := Discover(t.Context(), cfg)
		require.NoError(t, err)
		assert.Equal(t, Facts{
			ID:        "i-0123456789abcdef0",
			Region:    "us-east-2",
			PrivateIP: netip.MustParseAddr("10.0.1.10"),
			PublicIP:  netip.MustParseAddr("192.0.2.10"),
			Interface: primary.Name,
			VPCCIDRs:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16"), netip.MustParsePrefix("100.64.0.0/16")},
		}, facts)
	}
	{
		// The primary MAC must belong to a local interface
		fakeMetadata(t, "02:ff:ff:ff:ff:ff")
		cfg, err := awsconfig.LoadDefaultConfig(t.Context())
		require.NoError(t, err)
		_, err = Discover(t.Context(), cfg)
		assert.ErrorContains(t, err, "no network interface has the primary MAC address 02:ff:ff:ff:ff:ff")
	}
}

func TestParseMemTotal(t *testing.T) {
	{
		// /proc/meminfo on a c7g.large
		memory, err := parseMemTotal(strings.NewReader("MemTotal:        3898756 kB\nMemFree:         3021488 kB\nMemAvailable:    3412372 kB\n"))
		require.NoError(t, err)
		assert.Equal(t, uint64(3898756*1024), memory)
	}
	for _, c := range []struct{ meminfo, err string }{
		{"MemFree:         3021488 kB\n", "no MemTotal line"},
		{"", "no MemTotal line"},
		{"MemTotal:        3807 MB\n", `unexpected MemTotal line "MemTotal:        3807 MB"`},
		{"MemTotal:        3898756\n", `unexpected MemTotal line "MemTotal:        3898756"`},
		{"MemTotal:        -1 kB\n", `unexpected MemTotal line "MemTotal:        -1 kB": strconv.ParseUint: parsing "-1": invalid syntax`},
		{"MemTotal:        0 kB\n", "MemTotal of 0 kB is outside 262144 to 68719476736 kB"},
		{"MemTotal:        3898756000000 kB\n", "MemTotal of 3898756000000 kB is outside 262144 to 68719476736 kB"},
	} {
		_, err := parseMemTotal(strings.NewReader(c.meminfo))
		assert.EqualError(t, err, c.err, c.meminfo)
	}
	{
		// A file that can't be read gives 0, which ConnectionLimit treats as unknown
		assert.Zero(t, readMemory(filepath.Join(t.TempDir(), "missing")))
	}
}
