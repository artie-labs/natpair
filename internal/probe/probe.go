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
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"sync/atomic"
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
	// handshakeTimeout bounds [Client.Handshakes]. Within a region a
	// handshake with the receiver takes a few milliseconds, and Linux resends
	// an unanswered SYN only after 1 s, so each attempt sends one SYN.
	handshakeTimeout = 500 * time.Millisecond
	nonceHeader      = "X-Nat-Probe-Nonce"
)

// ErrTimeout marks an upload that failed because it ran out of time, as
// when the path loses or delays its packets.
var ErrTimeout = errors.New("probe upload timed out")

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
// fails unless checkReply accepts the receiver's reply. A failure once the
// upload's time is up wraps [ErrTimeout], unless the receiver's reply came
// back and was wrong.
func (c *Client) Upload(ctx context.Context, target Target) (Flow, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	flow, err := c.upload(ctx, target)
	var wrong replyError
	switch {
	case errors.As(err, &wrong):
		// The reply came back over the path, so no packets were lost, even
		// if a starved CPU checked it after the deadline.
		return Flow{}, wrong.err
	case err != nil && timedOut(ctx):
		return Flow{}, fmt.Errorf("%w: %w", ErrTimeout, err)
	}
	return flow, err
}

// replyError marks a reply that came back but was wrong.
type replyError struct{ err error }

func (e replyError) Error() string { return e.err.Error() }

// timedOut reports whether ctx's deadline has passed. A failed connection
// attempt or upload decides by the clock, not by its error, because the cause
// doesn't always survive on the way up: net/http reports a write that hit the
// connection's deadline without wrapping the deadline error. Nor by ctx.Err:
// the connection's deadline is the same instant, and the timer that sets
// ctx.Err can run after the I/O error comes back.
func timedOut(ctx context.Context) bool {
	deadline, ok := ctx.Deadline()
	return ok && !clock().Before(deadline)
}

// clock tells the time for timedOut. Tests replace it.
var clock = time.Now

func (c *Client) upload(ctx context.Context, target Target) (Flow, error) {
	address, err := parseURL(target.URL)
	if err != nil {
		return Flow{}, err
	}
	tlsConfig := &tls.Config{ServerName: address.Hostname(), MinVersion: tls.VersionTLS12}
	if rootCAs != nil {
		tlsConfig.RootCAs = rootCAs
	}
	// Resolve outside the namespace, then dial a literal address so the socket
	// is created on the namespace's thread.
	remote, err := c.resolve(ctx, address)
	if err != nil {
		return Flow{}, err
	}
	conn, err := dial(ctx, target, remote)
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
		return Flow{}, replyError{fmt.Errorf("probe receiver returned status %d with %d bytes", response.StatusCode, len(body))}
	}
	if err := checkReply(body, nonce, payload, target.ExpectedIP); err != nil {
		return Flow{}, replyError{err}
	}
	return flow, nil
}

// Handshakes opens attempts TCP connections to target's receiver at once and
// returns how many connected. Each starts like [Client.Upload]'s, from the
// same namespace and source address, to the address the last upload used, so
// it takes the same route and address translation. Each closes with a reset
// as soon as it connects, without TLS, so it leaves no socket behind. Only an
// attempt that runs out of time counts as lost. Any other failure, such as a
// refused connection or one this host couldn't start, says nothing about
// lost packets, so Handshakes then returns that error.
//
// A completed handshake shows the path delivers packets both ways, because
// the answer must acknowledge the random sequence number the kernel chose
// for the SYN, which only a host that saw the SYN knows.
func (c *Client) Handshakes(ctx context.Context, target Target, attempts int) (int, error) {
	address, err := parseURL(target.URL)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	remote, err := c.lastResolved(ctx, address)
	if err != nil {
		return 0, err
	}
	var completed atomic.Int64
	var mu sync.Mutex
	var failure error
	var wg sync.WaitGroup
	for range attempts {
		wg.Go(func() {
			conn, err := dial(ctx, target, remote)
			if err != nil {
				if !timedOut(ctx) {
					mu.Lock()
					failure = cmp.Or(failure, err)
					mu.Unlock()
				}
				return
			}
			if tcp, ok := conn.(*net.TCPConn); ok {
				_ = tcp.SetLinger(0)
			}
			_ = conn.Close()
			completed.Add(1)
		})
	}
	wg.Wait()
	if failure != nil {
		return 0, fmt.Errorf("failed to try a handshake with probe receiver %s: %w", remote, failure)
	}
	return int(completed.Load()), nil
}

// lastResolved returns the receiver's address the last upload used, so the
// handshakes go where the upload went and don't spend their time on another
// lookup. It resolves the host only if no upload has.
func (c *Client) lastResolved(ctx context.Context, address *url.URL) (netip.AddrPort, error) {
	c.mu.Lock()
	ip, known := c.resolved[address.Hostname()]
	c.mu.Unlock()
	if !known {
		return c.resolve(ctx, address)
	}
	port, err := receiverPort(address)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip, port), nil
}

// parseURL parses a receiver's URL, which must be a plain HTTPS URL.
func parseURL(raw string) (*url.URL, error) {
	address, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse probe URL %q: %w", raw, err)
	}
	if address.Scheme != "https" || address.Hostname() == "" || address.User != nil || address.Fragment != "" {
		return nil, fmt.Errorf("probe URL %q must be a plain HTTPS URL", raw)
	}
	return address, nil
}

// dial opens a TCP connection to remote from target's namespace and source
// address. The socket is created on the namespace's thread.
func dial(ctx context.Context, target Target, remote netip.AddrPort) (net.Conn, error) {
	var conn net.Conn
	err := netns.Do(target.Namespace, func() error {
		dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: target.Source.AsSlice()}}
		var dialErr error
		conn, dialErr = dialer.DialContext(ctx, "tcp4", remote.String())
		return dialErr
	})
	return conn, err
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

// receiverPort returns the receiver's port, 443 unless its URL names one.
func receiverPort(address *url.URL) (uint16, error) {
	value := address.Port()
	if value == "" {
		return 443, nil
	}
	port, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid probe port %q: %w", value, err)
	}
	return uint16(port), nil
}

// resolve returns the receiver's address, or the host's last resolved
// address if the lookup fails.
func (c *Client) resolve(ctx context.Context, address *url.URL) (netip.AddrPort, error) {
	port, err := receiverPort(address)
	if err != nil {
		return netip.AddrPort{}, err
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
