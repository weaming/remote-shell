package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"remote-shell/execution"
)

const (
	Version      = "remote-shell/1"
	ServiceType  = "_remote-shell._udp"
	MaxFrameSize = 4 << 20
	frameHeader  = 5
)

type FrameType byte

const (
	// FrameShellRequest opens a run and carries exactly one command.
	FrameShellRequest FrameType = iota + 1
	// FrameShellStarted carries the run ID the agent assigned, before any
	// output, so the client can query the run while it is still going.
	FrameShellStarted
	FrameListShells
	FrameOutput
	FrameShellResult
	FrameError
	FrameShellList
)

type Frame struct {
	Type    FrameType
	Payload []byte
}

// ShellRequest asks the agent to run one command. The run ID is assigned by the
// agent, not by the caller.
type ShellRequest struct {
	ClientID string      `json:"client_id,omitempty"`
	Command  CommandSpec `json:"command"`
}

// ShellStarted is the first frame the agent sends for an accepted run.
type ShellStarted struct {
	RunID string `json:"run_id"`
}

type CommandSpec struct {
	Shell     execution.Shell   `json:"shell"`
	Script    string            `json:"script"`
	CWD       string            `json:"cwd"`
	Env       map[string]string `json:"env,omitempty"`
	Stdin     []byte            `json:"stdin,omitempty"`
	TimeoutMS int64             `json:"timeout_ms,omitempty"`
}

// ExecutionCommand decodes the wire command. A zero timeout becomes the agent
// default.
func (spec CommandSpec) ExecutionCommand() (execution.Command, error) {
	if spec.TimeoutMS < 0 || spec.TimeoutMS > int64(execution.MaxTimeout/time.Millisecond) {
		return execution.Command{}, fmt.Errorf("timeout_ms must be between 0 and %d", execution.MaxTimeout.Milliseconds())
	}
	timeout := time.Duration(spec.TimeoutMS) * time.Millisecond
	if spec.TimeoutMS == 0 {
		timeout = execution.DefaultTimeout
	}
	return execution.Command{
		Shell:   spec.Shell,
		Script:  spec.Script,
		CWD:     spec.CWD,
		Env:     spec.Env,
		Stdin:   spec.Stdin,
		Timeout: timeout,
	}, nil
}

// NewCommandSpec encodes a command for the wire. A zero timeout is sent as 0,
// which the agent resolves to its own default.
func NewCommandSpec(command execution.Command) CommandSpec {
	return CommandSpec{
		Shell:     command.Shell,
		Script:    command.Script,
		CWD:       command.CWD,
		Env:       command.Env,
		Stdin:     command.Stdin,
		TimeoutMS: command.Timeout.Milliseconds(),
	}
}

type ErrorMessage struct {
	Message string `json:"message"`
}

type ShellList struct {
	Shells []execution.Shell `json:"shells"`
}

// OutputChunk is one decoded output frame; the run it belongs to is implied by
// the stream it arrived on.
type OutputChunk struct {
	Seq    uint64
	Stream execution.Stream
	Data   []byte
}

func ReadFrame(reader io.Reader) (Frame, error) {
	var header [frameHeader]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return Frame{}, err
	}
	length := binary.BigEndian.Uint32(header[1:])
	if length > MaxFrameSize {
		return Frame{}, fmt.Errorf("frame length %d exceeds limit %d", length, MaxFrameSize)
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return Frame{}, err
	}
	return Frame{Type: FrameType(header[0]), Payload: payload}, nil
}

func WriteFrame(writer io.Writer, frame Frame) error {
	if len(frame.Payload) > MaxFrameSize {
		return fmt.Errorf("frame length %d exceeds limit %d", len(frame.Payload), MaxFrameSize)
	}
	var header [frameHeader]byte
	header[0] = byte(frame.Type)
	binary.BigEndian.PutUint32(header[1:], uint32(len(frame.Payload)))
	if err := writeFull(writer, header[:]); err != nil {
		return err
	}
	return writeFull(writer, frame.Payload)
}

func MarshalFrame(frameType FrameType, value any) (Frame, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return Frame{}, fmt.Errorf("encode frame: %w", err)
	}
	if len(payload) > MaxFrameSize {
		return Frame{}, fmt.Errorf("frame length %d exceeds limit %d", len(payload), MaxFrameSize)
	}
	return Frame{Type: frameType, Payload: payload}, nil
}

func UnmarshalPayload(frame Frame, target any) error {
	if err := json.Unmarshal(frame.Payload, target); err != nil {
		return fmt.Errorf("decode frame type %d: %w", frame.Type, err)
	}
	return nil
}

// EncodeOutput packs one output chunk as stream code, sequence and raw bytes.
func EncodeOutput(chunk execution.Output) ([]byte, error) {
	if chunk.Stream != execution.StreamStdout && chunk.Stream != execution.StreamStderr {
		return nil, fmt.Errorf("unsupported output stream %q", chunk.Stream)
	}
	streamCode := byte(1)
	if chunk.Stream == execution.StreamStderr {
		streamCode = 2
	}
	payload := make([]byte, 9+len(chunk.Data))
	payload[0] = streamCode
	binary.BigEndian.PutUint64(payload[1:9], chunk.Seq)
	copy(payload[9:], chunk.Data)
	return payload, nil
}

func DecodeOutput(payload []byte) (OutputChunk, error) {
	if len(payload) < 9 {
		return OutputChunk{}, fmt.Errorf("output frame is shorter than its header")
	}
	stream := execution.StreamStdout
	switch payload[0] {
	case 1:
	case 2:
		stream = execution.StreamStderr
	default:
		return OutputChunk{}, fmt.Errorf("unknown output stream code %d", payload[0])
	}
	return OutputChunk{
		Seq:    binary.BigEndian.Uint64(payload[1:9]),
		Stream: stream,
		Data:   append([]byte(nil), payload[9:]...),
	}, nil
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
