package command

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStream(t *testing.T) {
	{
		// read gets the whole output
		var output []byte
		require.NoError(t, Stream(t.Context(), 10*time.Second, func(r io.Reader) error {
			var err error
			output, err = io.ReadAll(r)
			return err
		}, "sh", "-c", "printf 'a\\nb\\n'"))
		assert.Equal(t, "a\nb\n", string(output))
	}
	{
		// A command that outlives the timeout is killed, with whatever it
		// started, and its partial output is reported as a failure, so a
		// caller never takes it for the whole
		started := time.Now()
		err := Stream(t.Context(), 200*time.Millisecond, func(r io.Reader) error {
			_, err := io.ReadAll(r)
			return err
		}, "sh", "-c", "echo partial; sleep 30 & wait")
		assert.EqualError(t, err, "sh failed: signal: killed: ")
		assert.Less(t, time.Since(started), 20*time.Second, "the command and its child weren't killed")
	}
	{
		// An error from read stops the command and is returned
		boom := errors.New("boom")
		err := Stream(t.Context(), time.Minute, func(io.Reader) error { return boom }, "sh", "-c", "sleep 30 & wait")
		assert.ErrorIs(t, err, boom)
		assert.EqualError(t, err, "failed to read the output of sh: boom")
	}
}
