// Package client dials a remote-shell agent and drives shell runs over QUIC.
package client

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/quic-go/quic-go"
	"remote-shell/execution"
	"remote-shell/identity"
	"remote-shell/protocol"
)

const (
	// dialTimeout bounds the QUIC handshake so a silent peer cannot hang a call.
	dialTimeout = 10 * time.Second
	// cancelGrace is how long a cancelled run may still return its final
	// result, so the caller learns whether the command really stopped.
	cancelGrace = 5 * time.Second
)

// Client is one QUIC connection to an agent. A connection carries a single
// run per call and is cheap to recreate, so callers dial per operation.
type Client struct {
	conn *quic.Conn
}

// Dial connects to an agent at address (host:port). An empty private key
// connects without a client certificate, which an agent allows only when it
// runs with --allow-unauthenticated.
func Dial(ctx context.Context, address string, privateKey ed25519.PrivateKey) (*Client, error) {
	if address == "" {
		return nil, fmt.Errorf("agent address is required")
	}
	tlsConfig, err := identity.ClientTLSConfig(privateKey)
	if err != nil {
		return nil, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	connection, err := quic.DialAddr(dialCtx, address, tlsConfig, &quic.Config{
		MaxIdleTimeout:        45 * time.Second,
		KeepAlivePeriod:       15 * time.Second,
		HandshakeIdleTimeout:  dialTimeout,
		MaxIncomingStreams:    -1,
		MaxIncomingUniStreams: -1,
	})
	if err != nil {
		return nil, fmt.Errorf("dial agent %s: %w", address, err)
	}
	return &Client{conn: connection}, nil
}

func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.CloseWithError(0, "client finished")
}

// ListShells asks the agent which shells it can run.
func (c *Client) ListShells(ctx context.Context) ([]execution.Shell, error) {
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open shell-list stream: %w", err)
	}
	defer stream.Close()
	defer stream.CancelRead(0)
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetReadDeadline(deadline)
	}
	frame, err := protocol.MarshalFrame(protocol.FrameListShells, struct{}{})
	if err != nil {
		return nil, err
	}
	if err := protocol.WriteFrame(stream, frame); err != nil {
		return nil, fmt.Errorf("send shell-list request: %w", err)
	}
	response, err := protocol.ReadFrame(stream)
	if err != nil {
		return nil, fmt.Errorf("read shell-list response: %w", err)
	}
	switch response.Type {
	case protocol.FrameShellList:
		var list protocol.ShellList
		if err := protocol.UnmarshalPayload(response, &list); err != nil {
			return nil, err
		}
		return list.Shells, nil
	case protocol.FrameError:
		return nil, decodeError(response)
	default:
		return nil, fmt.Errorf("unexpected frame type %d in shell-list response", response.Type)
	}
}

// Run is one shell run in flight on the agent. Output is drained by a
// goroutine started by StartShell, so a slow caller cannot stall the agent.
type Run struct {
	ID string
	// Name is the human-readable label the agent reports for itself.
	Name   string
	stream *quic.Stream
	done   chan runOutcome
}

type runOutcome struct {
	result execution.Result
	err    error
}

// StartShell opens a run and returns once the agent has accepted it and
// assigned a run ID. Output produced from then on is forwarded to emit.
func (c *Client) StartShell(ctx context.Context, command execution.Command, emit func(execution.Output) error) (*Run, error) {
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open run stream: %w", err)
	}
	request, err := protocol.MarshalFrame(protocol.FrameShellRequest, protocol.NewCommandSpec(command))
	if err != nil {
		_ = stream.Close()
		stream.CancelRead(0)
		return nil, err
	}
	if err := protocol.WriteFrame(stream, request); err != nil {
		_ = stream.Close()
		stream.CancelRead(0)
		return nil, fmt.Errorf("send shell request: %w", err)
	}
	response, err := protocol.ReadFrame(stream)
	if err != nil {
		_ = stream.Close()
		stream.CancelRead(0)
		return nil, fmt.Errorf("read run start: %w", err)
	}
	switch response.Type {
	case protocol.FrameShellStarted:
		var started protocol.ShellStarted
		if err := protocol.UnmarshalPayload(response, &started); err != nil {
			_ = stream.Close()
			stream.CancelRead(0)
			return nil, err
		}
		run := &Run{ID: started.RunID, Name: started.Name, stream: stream, done: make(chan runOutcome, 1)}
		go run.drain(ctx, emit)
		return run, nil
	case protocol.FrameError:
		_ = stream.Close()
		stream.CancelRead(0)
		return nil, decodeError(response)
	default:
		_ = stream.Close()
		stream.CancelRead(0)
		return nil, fmt.Errorf("unexpected frame type %d before a run started", response.Type)
	}
}

// drain forwards output until the agent reports the result or the stream ends.
// Cancelling the caller's context closes the write side, which is how the agent
// is told to stop the run.
func (r *Run) drain(ctx context.Context, emit func(execution.Output) error) {
	defer r.stream.CancelRead(0)
	cancelled := make(chan struct{})
	defer close(cancelled)
	go func() {
		select {
		case <-ctx.Done():
			_ = r.stream.Close()
			_ = r.stream.SetReadDeadline(time.Now().Add(cancelGrace))
		case <-cancelled:
		}
	}()
	for {
		frame, err := protocol.ReadFrame(r.stream)
		if err != nil {
			r.done <- runOutcome{err: fmt.Errorf("read run response: %w", err)}
			return
		}
		switch frame.Type {
		case protocol.FrameOutput:
			chunk, err := protocol.DecodeOutput(frame.Payload)
			if err != nil {
				r.done <- runOutcome{err: err}
				return
			}
			if emit == nil {
				continue
			}
			if err := emit(execution.Output{
				RunID:  r.ID,
				Stream: chunk.Stream,
				Data:   chunk.Data,
				At:     time.Now(),
			}); err != nil {
				r.done <- runOutcome{err: err}
				return
			}
		case protocol.FrameShellResult:
			var result execution.Result
			if err := protocol.UnmarshalPayload(frame, &result); err != nil {
				r.done <- runOutcome{err: err}
				return
			}
			r.done <- runOutcome{result: result}
			return
		case protocol.FrameError:
			r.done <- runOutcome{err: decodeError(frame)}
			return
		default:
			r.done <- runOutcome{err: fmt.Errorf("unexpected frame type %d in run response", frame.Type)}
			return
		}
	}
}

// Wait blocks until the run ends or ctx is done.
func (r *Run) Wait(ctx context.Context) (execution.Result, error) {
	select {
	case outcome := <-r.done:
		return outcome.result, outcome.err
	case <-ctx.Done():
		return execution.Result{}, ctx.Err()
	}
}

// Cancel tells the agent to stop the run.
func (r *Run) Cancel() error {
	return r.stream.Close()
}

func decodeError(frame protocol.Frame) error {
	var message protocol.ErrorMessage
	if err := protocol.UnmarshalPayload(frame, &message); err != nil {
		return err
	}
	return fmt.Errorf("agent error: %s", message.Message)
}
