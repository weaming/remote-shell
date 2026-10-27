// Package client dials a remote-shell agent and drives tasks over QUIC.
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
	// cancelGrace is how long a cancelled task may still return its final
	// result, so the caller learns whether the command really stopped.
	cancelGrace = 5 * time.Second
)

// Client is one QUIC connection to an agent. A connection carries a single
// task per call and is cheap to recreate, so callers dial per operation.
type Client struct {
	conn     *quic.Conn
	clientID string
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
	// The agent derives the same ID from the certificate it just verified.
	clientID := ""
	if len(privateKey) == ed25519.PrivateKeySize {
		clientID = identity.ClientID(privateKey.Public().(ed25519.PublicKey))
	}
	return &Client{conn: connection, clientID: clientID}, nil
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

// RunTask executes one task and streams its output to emit as it arrives. It
// returns once the agent reports the task result, which also happens for a
// cancelled task: cancelling ctx closes the stream write side, the agent stops
// the commands, and the result carries the cancellation flags.
func (c *Client) RunTask(ctx context.Context, task execution.Task, emit func(execution.Output) error) (execution.TaskResult, error) {
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return execution.TaskResult{}, fmt.Errorf("open task stream: %w", err)
	}
	defer stream.Close()
	defer stream.CancelRead(0)
	request, err := protocol.MarshalFrame(protocol.FrameTaskRequest, protocol.TaskRequest{
		ClientID: c.clientID,
		Task:     protocol.NewTaskSpec(task),
	})
	if err != nil {
		return execution.TaskResult{}, err
	}
	if err := protocol.WriteFrame(stream, request); err != nil {
		return execution.TaskResult{}, fmt.Errorf("send task request: %w", err)
	}
	// A task stream accepts exactly one control frame, so the write side stays
	// open until the caller cancels; closing it is the cancellation signal.
	cancelled := make(chan struct{})
	defer close(cancelled)
	go func() {
		select {
		case <-ctx.Done():
			_ = stream.Close()
			_ = stream.SetReadDeadline(time.Now().Add(cancelGrace))
		case <-cancelled:
		}
	}()
	for {
		frame, readErr := protocol.ReadFrame(stream)
		if readErr != nil {
			return execution.TaskResult{}, fmt.Errorf("read task response: %w", readErr)
		}
		switch frame.Type {
		case protocol.FrameOutput:
			chunk, decodeErr := protocol.DecodeOutput(frame.Payload)
			if decodeErr != nil {
				return execution.TaskResult{}, decodeErr
			}
			if emit == nil {
				continue
			}
			if err := emit(execution.Output{
				TaskID:    task.ID,
				CommandID: chunk.CommandID,
				Seq:       chunk.Seq,
				Stream:    chunk.Stream,
				Data:      chunk.Data,
				At:        time.Now(),
			}); err != nil {
				return execution.TaskResult{}, err
			}
		case protocol.FrameTaskResult:
			var result execution.TaskResult
			if err := protocol.UnmarshalPayload(frame, &result); err != nil {
				return execution.TaskResult{}, err
			}
			return result, nil
		case protocol.FrameError:
			return execution.TaskResult{}, decodeError(frame)
		default:
			return execution.TaskResult{}, fmt.Errorf("unexpected frame type %d in task response", frame.Type)
		}
	}
}

func decodeError(frame protocol.Frame) error {
	var message protocol.ErrorMessage
	if err := protocol.UnmarshalPayload(frame, &message); err != nil {
		return err
	}
	return fmt.Errorf("agent error: %s", message.Message)
}
