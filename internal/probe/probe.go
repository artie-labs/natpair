// Package probe sends verified HTTPS uploads through a NAT and checks that
// they arrived intact from the expected public IP.
//
// A probe posts random bytes with a nonce. The receiver replies with the
// nonce, the byte count, the SHA-256 of the body, the source IP it saw, and
// the body itself. A path can pass small requests while dropping full-size
// packets, so the upload spans several of them, and the echo checks the
// download direction the same way.
package probe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/artie-labs/natpair/internal/netns"
)

const (
	// uploadBytes is the upload size. 2 KiB is enough to catch a path that drops
	// full-size packets, and 4 KiB leaves margin for TLS and header overhead.
	uploadBytes = 4096
	// maxReplyBytes bounds the receiver's JSON reply, which carries the
	// upload base64-encoded.
	maxReplyBytes = 4 * uploadBytes
	// timeout bounds a whole upload, from the DNS lookup to the reply.
	timeout = time.Second
	// fallbackLookupTimeout bounds the DNS lookup once the host has resolved
	// before, so a lookup that hangs leaves time to upload to the last
	// address. VPC DNS answers in milliseconds, and uploads within the
	// region take about 25 ms.
	fallbackLookupTimeout = 250 * time.Millisecond
	nonceHeader           = "X-Nat-Probe-Nonce"
)

// Target describes one upload check.
type Target struct {
	// URL is an HTTPS receiver, such as the Lambda in terraform/receiver.
	URL string `json:"url"`
	// ExpectedIP is the public IP the receiver must observe.
	ExpectedIP netip.Addr `json:"expected_ip"`
	// Namespace is the network namespace to send from. Empty means the
	// current namespace.
	Namespace string `json:"namespace,omitempty"`
	// Source is the local IPv4 address to send from.
	Source netip.Addr `json:"source"`
}

// Flow identifies the probe's TCP connection as seen locally.
type Flow struct {
	Src     netip.Addr `json:"src"`
	Dst     netip.Addr `json:"dst"`
	SrcPort uint16     `json:"sport"`
	DstPort uint16     `json:"dport"`
}

type reply struct {
	Nonce    string     `json:"nonce"`
	Bytes    int        `json:"bytes"`
	SHA256   string     `json:"sha256"`
	SourceIP netip.Addr `json:"source_ip"`
	// Echo is the uploaded body, sent back so the reply spans full-size
	// packets too.
	Echo []byte `json:"echo"`
}

// rootCAs replaces the system roots in tests. Otherwise it is nil, and the
// system roots, or SSL_CERT_FILE, decide whether to trust the receiver.
var rootCAs *x509.CertPool

// lookupNetIP resolves the receiver's host. Tests replace it.
var lookupNetIP = net.DefaultResolver.LookupNetIP

// Client sends uploads. Use it through a pointer, because it remembers
// resolved addresses.
type Client struct {
	// Credentials sign uploads to a Lambda function URL receiver, which
	// requires IAM authentication.
	Credentials aws.CredentialsProvider

	mu sync.Mutex
	// resolved holds each receiver host's last resolved address. The DNS
	// lookup goes through this NAT's own ENI, not the path the upload tests,
	// so a failed lookup falls back to it instead of failing the upload. VPC
	// DNS lookups can time out for 3 s on the owner alone, which would
	// otherwise make a healthy owner step down.
	resolved map[string]netip.Addr
}

// Upload sends one verified upload to target and returns its connection. It
// fails unless checkReply accepts the receiver's reply.
func (c *Client) Upload(ctx context.Context, target Target) (Flow, error) {
	address, err := url.Parse(target.URL)
	if err != nil {
		return Flow{}, fmt.Errorf("failed to parse probe URL %q: %w", target.URL, err)
	}
	if address.Scheme != "https" || address.Hostname() == "" || address.User != nil || address.Fragment != "" {
		return Flow{}, fmt.Errorf("probe URL %q must be a plain HTTPS URL", target.URL)
	}
	tlsConfig := &tls.Config{ServerName: address.Hostname(), MinVersion: tls.VersionTLS12}
	if rootCAs != nil {
		tlsConfig.RootCAs = rootCAs
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// Resolve outside the namespace, then dial a literal address so the socket
	// is created on the namespace's thread.
	remote, err := c.resolve(ctx, address)
	if err != nil {
		return Flow{}, err
	}
	var conn net.Conn
	err = netns.Do(target.Namespace, func() error {
		dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: target.Source.AsSlice()}}
		var dialErr error
		conn, dialErr = dialer.DialContext(ctx, "tcp4", remote.String())
		return dialErr
	})
	if err != nil {
		return Flow{}, fmt.Errorf("failed to connect to probe receiver %s: %w", remote, err)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return Flow{}, fmt.Errorf("failed to set probe deadline: %w", err)
	}
	flow := Flow{
		Src:     conn.LocalAddr().(*net.TCPAddr).AddrPort().Addr().Unmap(),
		Dst:     remote.Addr(),
		SrcPort: conn.LocalAddr().(*net.TCPAddr).AddrPort().Port(),
		DstPort: remote.Port(),
	}

	payload := make([]byte, uploadBytes)
	rand.Read(payload)
	digest := sha256.Sum256(payload)
	nonce := rand.Text()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.URL, bytes.NewReader(payload))
	if err != nil {
		return Flow{}, fmt.Errorf("failed to build probe request: %w", err)
	}
	request.Header.Set(nonceHeader, nonce)
	request.Header.Set("Content-Type", "application/octet-stream")
	if region, ok := lambdaRegion(address.Hostname()); ok {
		if err := c.sign(ctx, request, digest[:], region); err != nil {
			return Flow{}, err
		}
	}

	secure := tls.Client(conn, tlsConfig)
	if err := request.Write(secure); err != nil {
		return Flow{}, fmt.Errorf("failed to send probe upload: %w", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(secure), request)
	if err != nil {
		return Flow{}, fmt.Errorf("failed to read probe reply: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxReplyBytes+1))
	if err != nil {
		return Flow{}, fmt.Errorf("failed to read probe reply: %w", err)
	}
	if response.StatusCode != http.StatusOK || len(body) > maxReplyBytes {
		return Flow{}, fmt.Errorf("probe receiver returned status %d with %d bytes", response.StatusCode, len(body))
	}
	if err := checkReply(body, nonce, payload, target.ExpectedIP); err != nil {
		return Flow{}, err
	}
	return flow, nil
}

// checkReply returns an error unless a receiver's reply confirms the nonce,
// size, checksum and contents of the upload, and the expected source IP.
func checkReply(body []byte, nonce string, payload []byte, expectedIP netip.Addr) error {
	var confirmed reply
	if err := json.Unmarshal(body, &confirmed); err != nil {
		return fmt.Errorf("failed to decode probe reply: %w", err)
	}
	digest := sha256.Sum256(payload)
	if confirmed.Nonce != nonce || confirmed.Bytes != len(payload) || confirmed.SHA256 != hex.EncodeToString(digest[:]) || !bytes.Equal(confirmed.Echo, payload) {
		return fmt.Errorf("probe receiver did not confirm the upload contents")
	}
	if confirmed.SourceIP != expectedIP {
		return fmt.Errorf("probe receiver saw source IP %s, expected %s", confirmed.SourceIP, expectedIP)
	}
	return nil
}

// lambdaURLPattern matches a Lambda function URL's host, such as
// abc123.lambda-url.us-east-2.on.aws, and captures its region.
var lambdaURLPattern = regexp.MustCompile(`^[a-z0-9]+\.lambda-url\.([a-z0-9-]+)\.on\.aws$`)

// lambdaRegion returns the region of a Lambda function URL host.
func lambdaRegion(host string) (string, bool) {
	match := lambdaURLPattern.FindStringSubmatch(host)
	if match == nil {
		return "", false
	}
	return match[1], true
}

// sign adds an AWS Signature Version 4 for the Lambda service, which a
// function URL with IAM authentication requires.
func (c *Client) sign(ctx context.Context, request *http.Request, payloadDigest []byte, region string) error {
	if c.Credentials == nil {
		return fmt.Errorf("probe target in %s requires AWS credentials to sign uploads", region)
	}
	credentials, err := c.Credentials.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("failed to get AWS credentials for the probe: %w", err)
	}
	if err := v4.NewSigner().SignHTTP(ctx, credentials, request, hex.EncodeToString(payloadDigest), "lambda", region, time.Now()); err != nil {
		return fmt.Errorf("failed to sign probe upload: %w", err)
	}
	return nil
}

// resolve returns the receiver's address, or the host's last resolved
// address if the lookup fails.
func (c *Client) resolve(ctx context.Context, address *url.URL) (netip.AddrPort, error) {
	port := uint16(443)
	if value := address.Port(); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("invalid probe port %q: %w", value, err)
		}
		port = uint16(parsed)
	}
	if ip, err := netip.ParseAddr(address.Hostname()); err == nil {
		return netip.AddrPortFrom(ip.Unmap(), port), nil
	}
	host := address.Hostname()
	c.mu.Lock()
	last, known := c.resolved[host]
	c.mu.Unlock()
	lookupCtx := ctx
	if known {
		var cancel context.CancelFunc
		lookupCtx, cancel = context.WithTimeout(ctx, fallbackLookupTimeout)
		defer cancel()
	}
	ips, err := lookupNetIP(lookupCtx, "ip4", host)
	switch {
	case err == nil && len(ips) > 0:
		ip := ips[0].Unmap()
		c.mu.Lock()
		if c.resolved == nil {
			c.resolved = map[string]netip.Addr{}
		}
		c.resolved[host] = ip
		c.mu.Unlock()
		return netip.AddrPortFrom(ip, port), nil
	case known:
		slog.Warn("failed to resolve probe receiver, using its last address", slog.String("host", host), slog.String("address", last.String()), slog.Any("err", err))
		return netip.AddrPortFrom(last, port), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("failed to resolve probe receiver %q: %w", host, err)
	}
}
