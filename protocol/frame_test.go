package protocol

import (
	"bytes"
	"reflect"
	"testing"

	"remote-shell/execution"
)

func TestFrameRoundTrip(t *testing.T) {
	want := Frame{Type: FrameCancel, Payload: []byte("cancel")}
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
		CommandID: "cmd-1",
		Seq:       42,
		Stream:    execution.StreamStderr,
		Data:      []byte{0, 1, 2, 255},
	}
	encoded, err := EncodeOutput(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeOutput(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.Seq != want.Seq || got.CommandID != want.CommandID || got.Stream != want.Stream || !bytes.Equal(got.Data, want.Data) {
		t.Fatalf("decoded output = %#v, want %#v", got, want)
	}
}

func TestReadFrameRejectsOversizedFrame(t *testing.T) {
	encoded := []byte{byte(FrameTaskRequest), 0, 64, 0, 1}
	if _, err := ReadFrame(bytes.NewReader(encoded)); err == nil {
		t.Fatal("expected oversized frame rejection")
	}
}

func TestTaskSpecTimeoutIsInMilliseconds(t *testing.T) {
	task, err := (TaskSpec{
		ID: "task-1",
		Commands: []CommandSpec{{
			ID: "command-1", Shell: execution.ShellBash, Script: "true", CWD: t.TempDir(),
		}},
	}).ExecutionTask()
	if err != nil {
		t.Fatal(err)
	}
	if got := task.Commands[0].Timeout; got != execution.DefaultTimeout {
		t.Fatalf("timeout = %s, want %s", got, execution.DefaultTimeout)
	}
	_, err = (TaskSpec{
		ID: "task-2",
		Commands: []CommandSpec{{
			ID: "command-1", Shell: execution.ShellBash, Script: "true", CWD: t.TempDir(), TimeoutMS: 3600001,
		}},
	}).ExecutionTask()
	if err == nil {
		t.Fatal("expected timeout above one hour to be rejected")
	}
}
