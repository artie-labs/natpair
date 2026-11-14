package probe

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/probe/probetest"
)

func startReceiver(t *testing.T, handler http.Handler) Target {
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	rootCAs = x509.NewCertPool()
	rootCAs.AddCert(server.Certificate())
	localhost := netip.MustParseAddr("127.0.0.1")
	return Target{URL: server.URL + "/nat", ExpectedIP: localhost, Source: localhost}
}

func TestUpload(t *testing.T) {
	{
		// Verified upload
		target := startReceiver(t, probetest.Handler())
		flow, err := (&Client{}).Upload(t.Context(), target)
		require.NoError(t, err)
		assert.Equal(t, target.Source, flow.Src)
		assert.Equal(t, target.Source, flow.Dst)
		assert.NotZero(t, flow.SrcPort)
	}
	{
		// The receiver saw a different public IP, so traffic left through the wrong NAT
		target := startReceiver(t, probetest.Handler())
		target.ExpectedIP = netip.MustParseAddr("192.0.2.10")
		_, err := (&Client{}).Upload(t.Context(), target)
		assert.ErrorContains(t, err, "probe receiver saw source IP 127.0.0.1, expected 192.0.2.10")
	}
	{
		// A receiver that does not confirm the exact contents fails the check
		target := startReceiver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"nonce":"other","bytes":4096,"sha256":"","source_ip":"127.0.0.1"}`))
		}))
		_, err := (&Client{}).Upload(t.Context(), target)
		assert.ErrorContains(t, err, "probe receiver did not confirm the upload contents")
	}
	{
		// A reply that confirms the upload but does not carry it back fails, so
		// a path that drops large replies is caught
		target := startReceiver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			recorder := httptest.NewRecorder()
			probetest.Handler().ServeHTTP(recorder, r)
			var confirmed map[string]any
			require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &confirmed))
			delete(confirmed, "echo")
			require.NoError(t, json.NewEncoder(w).Encode(confirmed))
		}))
		_, err := (&Client{}).Upload(t.Context(), target)
		assert.ErrorContains(t, err, "probe receiver did not confirm the upload contents")
	}
	{
		// Error status
		target := startReceiver(t, http.NotFoundHandler())
		_, err := (&Client{}).Upload(t.Context(), target)
		assert.ErrorContains(t, err, "probe receiver returned status 404")
	}
	{
		// Plain HTTP is rejected
		_, err := (&Client{}).Upload(t.Context(), Target{URL: "http://127.0.0.1/nat"})
		assert.ErrorContains(t, err, "must be a plain HTTPS URL")
	}
}

func TestUploadResolve(t *testing.T) {
	t.Cleanup(func() { lookupNetIP = net.DefaultResolver.LookupNetIP })
	// The test certificate covers example.com, so the stub can resolve it to
	// the local receiver.
	target := startReceiver(t, probetest.Handler())
	address, err := url.Parse(target.URL)
	require.NoError(t, err)
	target.URL = "https://example.com:" + address.Port() + "/nat"
	resolvesTo := func(ip string) func(context.Context, string, string) ([]netip.Addr, error) {
		return func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr(ip)}, nil
		}
	}
	// hangs answers only once the lookup's time limit runs out. VPC DNS can
	// time out like this for several rounds, which would demote a healthy
	// owner without the fallback.
	hangs := func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	{
		// A lookup that hangs falls back to the last address, with time left for the upload
		client := &Client{}
		lookupNetIP = resolvesTo("127.0.0.1")
		_, err := client.Upload(t.Context(), target)
		require.NoError(t, err)
		lookupNetIP = hangs
		_, err = client.Upload(t.Context(), target)
		require.NoError(t, err)
	}
	{
		// Each successful lookup replaces the address to fall back to
		client := &Client{}
		lookupNetIP = resolvesTo("192.0.2.1")
		_, err := client.Upload(t.Context(), target)
		require.ErrorContains(t, err, "failed to connect to probe receiver 192.0.2.1:")
		lookupNetIP = resolvesTo("127.0.0.1")
		_, err = client.Upload(t.Context(), target)
		require.NoError(t, err)
		lookupNetIP = hangs
		_, err = client.Upload(t.Context(), target)
		require.NoError(t, err)
	}
	{
		// With no earlier address, a failed lookup fails the upload
		failed := errors.New("no such host")
		lookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) { return nil, failed }
		_, err := (&Client{}).Upload(t.Context(), target)
		assert.ErrorIs(t, err, failed)
		assert.EqualError(t, err, `failed to resolve probe receiver "example.com": no such host`)
	}
}

// TestLambdaReceiver runs the Lambda receiver in terraform/receiver and checks
// that its replies pass the same verification as the test receiver's.
func TestLambdaReceiver(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	receiver, err := filepath.Abs("../../terraform/receiver/index.mjs")
	require.NoError(t, err)
	invoke := func(event map[string]any) (int, []byte) {
		encoded, err := json.Marshal(event)
		require.NoError(t, err)
		cmd := exec.Command(node, "--input-type=module", "-e",
			"import { pathToFileURL } from 'node:url'; import { readFileSync } from 'node:fs';"+
				"const { handler } = await import(pathToFileURL(process.argv[1]).href);"+
				"process.stdout.write(JSON.stringify(await handler(JSON.parse(readFileSync(0, 'utf8')))));", receiver)
		cmd.Stdin = bytes.NewReader(encoded)
		output, err := cmd.Output()
		require.NoError(t, err)
		var response struct {
			StatusCode int    `json:"statusCode"`
			Body       string `json:"body"`
		}
		require.NoError(t, json.Unmarshal(output, &response))
		return response.StatusCode, []byte(response.Body)
	}
	request := func(method string, headers map[string]string, payload []byte) map[string]any {
		return map[string]any{
			"requestContext":  map[string]any{"http": map[string]any{"method": method, "sourceIp": "192.0.2.10"}},
			"headers":         headers,
			"body":            base64.StdEncoding.EncodeToString(payload),
			"isBase64Encoded": true,
		}
	}
	payload := bytes.Repeat([]byte{0, 1, 2, 255}, uploadBytes/4)
	{
		// A verified upload, as the NATs check it
		status, body := invoke(request("POST", map[string]string{"X-Nat-Probe-Nonce": "abc"}, payload))
		assert.Equal(t, 200, status)
		require.NoError(t, checkReply(body, "abc", payload, netip.MustParseAddr("192.0.2.10")))
		assert.ErrorContains(t, checkReply(body, "abc", payload, netip.MustParseAddr("192.0.2.11")), "saw source IP 192.0.2.10")
	}
	{
		// Requests that are not probe uploads are refused
		status, _ := invoke(request("POST", map[string]string{}, payload))
		assert.Equal(t, 400, status)
		status, _ = invoke(request("GET", map[string]string{"X-Nat-Probe-Nonce": "abc"}, nil))
		assert.Equal(t, 400, status)
		status, _ = invoke(request("POST", map[string]string{"X-Nat-Probe-Nonce": "abc"}, make([]byte, 65537)))
		assert.Equal(t, 400, status)
	}
}

func TestLambdaRegion(t *testing.T) {
	region, ok := lambdaRegion("abc123def.lambda-url.us-east-2.on.aws")
	assert.True(t, ok)
	assert.Equal(t, "us-east-2", region)
	// Other hosts are not signed
	_, ok = lambdaRegion("probe.example.com")
	assert.False(t, ok)
	_, ok = lambdaRegion("abc.lambda-url.us-east-2.on.aws.example.com")
	assert.False(t, ok)
}

func TestSign(t *testing.T) {
	newRequest := func() *http.Request {
		request, err := http.NewRequest(http.MethodPost, "https://abc123.lambda-url.us-east-2.on.aws/", strings.NewReader("upload"))
		require.NoError(t, err)
		return request
	}
	digest := []byte("0123456789abcdef0123456789abcdef")
	{
		// Uploads to a Lambda receiver carry a Signature Version 4 for its region
		request := newRequest()
		client := &Client{Credentials: credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "secret", "")}
		require.NoError(t, client.sign(t.Context(), request, digest, "us-east-2"))
		authorization := request.Header.Get("Authorization")
		assert.True(t, strings.HasPrefix(authorization, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"), authorization)
		assert.Contains(t, authorization, "/us-east-2/lambda/aws4_request")
	}
	{
		// Without credentials, the upload fails instead of going out unsigned
		assert.ErrorContains(t, (&Client{}).sign(t.Context(), newRequest(), digest, "us-east-2"), "requires AWS credentials")
	}
}

func TestHandshakes(t *testing.T) {
	{
		// Every attempt connects to a listening receiver, without TLS
		target := startReceiver(t, probetest.Handler())
		completed, err := (&Client{}).Handshakes(t.Context(), target, 40)
		require.NoError(t, err)
		assert.Equal(t, 40, completed)
	}
	{
		// None connects where nothing listens
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		require.NoError(t, listener.Close())
		target := Target{URL: "https://" + listener.Addr().String() + "/nat", Source: netip.MustParseAddr("127.0.0.1")}
		completed, err := (&Client{}).Handshakes(t.Context(), target, 40)
		require.NoError(t, err)
		assert.Zero(t, completed)
	}
	{
		_, err := (&Client{}).Handshakes(t.Context(), Target{URL: "http://127.0.0.1/nat"}, 40)
		assert.EqualError(t, err, `probe URL "http://127.0.0.1/nat" must be a plain HTTPS URL`)
	}
}

func TestUploadTimeout(t *testing.T) {
	{
		// A receiver that never answers runs the upload out of time, and
		// net/http's write error alone wouldn't show it
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = listener.Close() })
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				t.Cleanup(func() { _ = conn.Close() })
			}
		}()
		target := Target{URL: "https://" + listener.Addr().String() + "/nat", Source: netip.MustParseAddr("127.0.0.1")}
		_, err = (&Client{}).Upload(t.Context(), target)
		assert.ErrorIs(t, err, ErrTimeout)
	}
	{
		// A failure that came back in time isn't a timeout
		target := startReceiver(t, http.NotFoundHandler())
		_, err := (&Client{}).Upload(t.Context(), target)
		assert.EqualError(t, err, "probe receiver returned status 404 with 19 bytes")
		assert.NotErrorIs(t, err, ErrTimeout)
	}
}
