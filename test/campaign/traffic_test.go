//go:build linux && campaign

package campaign

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net"
	"time"

	"github.com/artie-labs/natpair/internal/netns"
)

// The upload protocol sends length-prefixed frames over one TCP connection.
// The receiver acknowledges each frame with one byte, and a zero-length frame
// asks for a JSON summary of everything received on that connection.
const (
	maxFrameBytes = 8192
	// framePause paces a long upload so it spans the fault and the takeover.
	framePause = 20 * time.Millisecond
)

var payload = func() []byte {
	block := make([]byte, 256)
	for i := range block {
		block[i] = byte(i)
	}
	return bytes.Repeat(block, maxFrameBytes/256)
}()

type uploadSummary struct {
	Bytes    int    `json:"bytes"`
	SHA256   string `json:"sha256"`
	SourceIP string `json:"source_ip"`
}

// uploadResult describes one upload. SameConnection means every frame used
// the original TCP connection, so the connection survived any takeover.
type uploadResult struct {
	OK              bool          `json:"ok"`
	Bytes           int           `json:"bytes"`
	MaxProgressGap  float64       `json:"max_progress_gap_s"`
	SameConnection  bool          `json:"same_connection"`
	Receiver        uploadSummary `json:"receiver"`
	Error           string        `json:"error,omitempty"`
	LocalPort       int           `json:"local_port"`
	DurationSeconds float64       `json:"duration_s"`
}

// serveUploads answers uploads on listener until it is closed.
func serveUploads(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go receiveUpload(conn)
	}
}

func receiveUpload(conn net.Conn) {
	defer conn.Close()
	// Long enough for a connection that idles through a standby restart and a
	// handover.
	if err := conn.SetDeadline(time.Now().Add(90 * time.Second)); err != nil {
		return
	}
	hash := sha256.New()
	total := 0
	header := make([]byte, 4)
	for {
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		size := binary.BigEndian.Uint32(header)
		if size == 0 {
			break
		}
		if size > maxFrameBytes {
			return
		}
		block := make([]byte, size)
		if _, err := io.ReadFull(conn, block); err != nil {
			return
		}
		hash.Write(block)
		total += int(size)
		if _, err := conn.Write([]byte{1}); err != nil {
			return
		}
	}
	source, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	reply, _ := json.Marshal(uploadSummary{Bytes: total, SHA256: hex.EncodeToString(hash.Sum(nil)), SourceIP: source})
	binary.BigEndian.PutUint32(header, uint32(len(reply)))
	// The uploader reports a missing reply, so a failed write needs no handling here.
	_, _ = conn.Write(append(header, reply...))
}

// upload sends frames from namespace to address for duration (at least one
// frame), waiting at most timeout for each step. ready, if set, receives the
// local port once connected.
func upload(namespace, address string, duration, timeout time.Duration, ready func(port int)) uploadResult {
	u, err := dialUpload(namespace, address, timeout)
	if err != nil {
		return uploadResult{Error: err.Error()}
	}
	if ready != nil {
		ready(u.result.LocalPort)
	}
	if err := u.send(duration); err != nil {
		return u.fail(err)
	}
	return u.finish()
}

// uploader is one upload connection. A case can send some frames, leave the
// connection idle, and send more later.
type uploader struct {
	conn     net.Conn
	timeout  time.Duration
	started  time.Time
	previous time.Time
	hash     hash.Hash
	result   uploadResult
}

func dialUpload(namespace, address string, timeout time.Duration) (*uploader, error) {
	var conn net.Conn
	err := netns.Do(namespace, func() error {
		var dialErr error
		conn, dialErr = net.DialTimeout("tcp4", address, timeout)
		return dialErr
	})
	if err != nil {
		return nil, err
	}
	now := time.Now()
	u := &uploader{conn: conn, timeout: timeout, started: now, previous: now, hash: sha256.New()}
	u.result.LocalPort = conn.LocalAddr().(*net.TCPAddr).Port
	return u, nil
}

// send sends frames for duration, and at least one frame.
func (u *uploader) send(duration time.Duration) error {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	frame := append(header, payload...)
	ack := make([]byte, 1)
	started := time.Now()
	for sent := false; !sent || time.Since(started) < duration; sent = true {
		if err := u.conn.SetDeadline(time.Now().Add(u.timeout)); err != nil {
			return err
		}
		if _, err := u.conn.Write(frame); err != nil {
			return err
		}
		if _, err := io.ReadFull(u.conn, ack); err != nil {
			return err
		}
		now := time.Now()
		u.result.MaxProgressGap = max(u.result.MaxProgressGap, now.Sub(u.previous).Seconds())
		u.previous = now
		u.hash.Write(payload)
		u.result.Bytes += len(payload)
		if duration > 0 {
			time.Sleep(framePause)
		}
	}
	return nil
}

// skipIdle restarts progress tracking, so a deliberate idle period does not
// count as a pause.
func (u *uploader) skipIdle() {
	u.previous = time.Now()
}

// finish asks the receiver for its summary and closes the connection.
func (u *uploader) finish() uploadResult {
	defer u.conn.Close()
	header := make([]byte, 4)
	if err := u.conn.SetDeadline(time.Now().Add(u.timeout)); err != nil {
		return u.fail(err)
	}
	if _, err := u.conn.Write(header); err != nil {
		return u.fail(err)
	}
	if _, err := io.ReadFull(u.conn, header); err != nil {
		return u.fail(err)
	}
	reply := make([]byte, binary.BigEndian.Uint32(header))
	if _, err := io.ReadFull(u.conn, reply); err != nil {
		return u.fail(err)
	}
	if err := json.Unmarshal(reply, &u.result.Receiver); err != nil {
		return u.fail(err)
	}
	u.result.SameConnection = true
	u.result.OK = u.result.Receiver.Bytes == u.result.Bytes && u.result.Receiver.SHA256 == hex.EncodeToString(u.hash.Sum(nil))
	if !u.result.OK {
		u.result.Error = fmt.Sprintf("receiver confirmed %d bytes, sent %d", u.result.Receiver.Bytes, u.result.Bytes)
	}
	u.result.DurationSeconds = time.Since(u.started).Seconds()
	return u.result
}

func (u *uploader) fail(err error) uploadResult {
	_ = u.conn.Close()
	u.result.Error = err.Error()
	u.result.DurationSeconds = time.Since(u.started).Seconds()
	return u.result
}
