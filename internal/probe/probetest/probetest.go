// Package probetest serves the receiver side of a probe for tests. Production
// uses the Lambda receiver in terraform/receiver, which speaks the same
// protocol.
package probetest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
)

// maxBytes matches MAX_BYTES in terraform/receiver/index.mjs.
const maxBytes = 65536

// Handler replies to a probe upload with its nonce, size, SHA-256, the source
// IP it saw, and the upload itself.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.Header.Get("X-Nat-Probe-Nonce")
		if r.Method != http.MethodPost || nonce == "" || len(nonce) > 64 {
			http.Error(w, "expected a probe upload", http.StatusBadRequest)
			return
		}
		upload, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
		if err != nil || len(upload) > maxBytes {
			http.Error(w, "invalid probe upload", http.StatusBadRequest)
			return
		}
		digest := sha256.Sum256(upload)
		source, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "unknown source address", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"nonce":     nonce,
			"bytes":     len(upload),
			"sha256":    hex.EncodeToString(digest[:]),
			"source_ip": source.Addr().Unmap(),
			"echo":      upload,
		})
	})
}
