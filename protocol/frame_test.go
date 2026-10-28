package protocol

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"remote-shell/execution"
)

func TestFrameRoundTrip(t *testing.T) {
	want := Frame{Type: FrameShellStarted, Payload: []byte(`{"run_id":"a2ddddf2f663"}`)}
	var encoded bytes.Buffer
	if err := WriteFrame(&encoded, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("frame = %#v, want %#v", got, want)
	}
}

func TestOutputFrameRoundTrip(t *testing.T) {
	want := execution.Output{
		RunID:  "a2ddddf2f663",
		Stream: execution.StreamStderr,
		Data:   []byte{0, 1, 2, 255},
	}
	encoded, err := EncodeOutput(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeOutput(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.Stream != want.Stream || !bytes.Equal(got.Data, want.Data) {
		t.Fatalf("decoded output = %#v, want %#v", got, want)
	}
}

func TestReadFrameRejectsOversizedFrame(t *testing.T) {
	encoded := []byte{byte(FrameShellRequest), 0, 64, 0, 1}
	if _, err := ReadFrame(bytes.NewReader(encoded)); err == nil {
		t.Fatal("expected oversized frame rejection")
	}
}

func TestCommandSpecRoundTrip(t *testing.T) {
	command := execution.Command{
		Shell:       execution.ShellBash,
		Script:      "true",
		CWD:         t.TempDir(),
		Env:         map[string]string{"A": "b"},
		EnableProxy: true,
		Stdin:       []byte("in"),
		Timeout:     2 * time.Second,
	}
	spec := NewCommandSpec(command)
	if spec.Timeout != 2 {
		t.Fatalf("timeout = %d, want 2 seconds", spec.Timeout)
	}
	decoded, err := spec.ExecutionCommand()
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Timeout != command.Timeout || decoded.Script != command.Script || decoded.CWD != command.CWD {
		t.Fatalf("decoded = %+v, want %+v", decoded, command)
	}
	if !decoded.EnableProxy {
		t.Fatal("enable_proxy was not preserved")
	}
	if string(decoded.Stdin) != "in" || decoded.Env["A"] != "b" {
		t.Fatalf("decoded stdin/env = %q/%v", decoded.Stdin, decoded.Env)
	}

	// A zero timeout is sent as 0 and resolved by the agent.
	zero, err := (CommandSpec{}).ExecutionCommand()
	if err == nil {
		if zero.Timeout != execution.DefaultTimeout {
			t.Fatalf("zero timeout = %s, want %s", zero.Timeout, execution.DefaultTimeout)
		}
	}
	_, err = (CommandSpec{Timeout: 3601}).ExecutionCommand()
	if err == nil {
		t.Fatal("expected timeout above one hour to be rejected")
	}
}
