package mcpserver

import (
	"testing"

	"remote-shell/execution"
)

func TestOutputBufferKeepsArrivalOrderAndStreamViews(t *testing.T) {
	buffer := newOutputBuffer(0)
	buffer.Append(execution.StreamStdout, []byte("hello"))
	buffer.Append(execution.StreamStderr, []byte("problem"))
	buffer.Append(execution.StreamStdout, []byte("world"))

	mixed, start, next, more := buffer.read("", 0, 0)
	if string(mixed) != "helloproblemworld" || start != 0 || next != 17 || more {
		t.Fatalf("mixed=%q start=%d next=%d more=%t", mixed, start, next, more)
	}
	stdout, start, next, more := buffer.read(execution.StreamStdout, 0, 0)
	if string(stdout) != "helloworld" || start != 0 || next != 10 || more {
		t.Fatalf("stdout=%q start=%d next=%d more=%t", stdout, start, next, more)
	}
	stderr, _, next, more := buffer.read(execution.StreamStderr, 0, 0)
	if string(stderr) != "problem" || next != 7 || more {
		t.Fatalf("stderr=%q next=%d more=%t", stderr, next, more)
	}
}

func TestOutputBufferPagesWithLimit(t *testing.T) {
	buffer := newOutputBuffer(0)
	buffer.Append(execution.StreamStdout, []byte("0123456789"))

	first, start, next, more := buffer.read("", 0, 4)
	if string(first) != "0123" || start != 0 || next != 4 || !more {
		t.Fatalf("first=%q start=%d next=%d more=%t", first, start, next, more)
	}
	second, _, next, more := buffer.read("", next, 4)
	if string(second) != "4567" || next != 8 || !more {
		t.Fatalf("second=%q next=%d more=%t", second, next, more)
	}
	last, _, next, more := buffer.read("", next, 4)
	if string(last) != "89" || next != 10 || more {
		t.Fatalf("last=%q next=%d more=%t", last, next, more)
	}
}

func TestOutputBufferTrimsOldestBytesAndReportsOffsets(t *testing.T) {
	buffer := newOutputBuffer(8)
	buffer.Append(execution.StreamStdout, []byte("aaaa"))
	buffer.Append(execution.StreamStdout, []byte("bbbb"))
	buffer.Append(execution.StreamStdout, []byte("cccc"))

	if data, start, _, _ := buffer.read("", 0, 0); len(data) != 8 || start != 4 {
		t.Fatalf("retained=%q start=%d, want 8 bytes from offset 4", data, start)
	}
	if got := buffer.trimmed(""); got != 4 {
		t.Fatalf("trimmed=%d, want 4", got)
	}
	data, start, next, more := buffer.read("", 0, 0)
	if string(data) != "bbbbcccc" || start != 4 || next != 12 || more {
		t.Fatalf("data=%q start=%d next=%d more=%t", data, start, next, more)
	}
	// A stream view keeps its own offset base, so filtering does not shift it.
	stdout, start, _, _ := buffer.read(execution.StreamStdout, 0, 0)
	if string(stdout) != "bbbbcccc" || start != 4 {
		t.Fatalf("stdout=%q start=%d", stdout, start)
	}
}

func TestOutputBufferPartialTrimKeepsByteAccounting(t *testing.T) {
	buffer := newOutputBuffer(5)
	buffer.Append(execution.StreamStdout, []byte("0123456789"))

	if data, start, _, _ := buffer.read("", 0, 0); len(data) != 5 || start != 5 {
		t.Fatalf("retained=%q start=%d, want 5 bytes from offset 5", data, start)
	}
	if got := buffer.trimmed(""); got != 5 {
		t.Fatalf("trimmed=%d, want 5", got)
	}
	data, start, next, more := buffer.read("", 0, 0)
	if string(data) != "56789" || start != 5 || next != 10 || more {
		t.Fatalf("data=%q start=%d next=%d more=%t", data, start, next, more)
	}
}

func TestOutputBufferFiltersStreamBesideTrimmedMix(t *testing.T) {
	buffer := newOutputBuffer(22)
	buffer.Append(execution.StreamStdout, []byte("stdout-one"))
	buffer.Append(execution.StreamStderr, []byte("stderr-one"))

	// The oldest stdout bytes are dropped, which shifts only the stdout view.
	buffer.Append(execution.StreamStdout, []byte("stdout-two"))

	stderr, start, next, more := buffer.read(execution.StreamStderr, 0, 0)
	if string(stderr) != "stderr-one" || start != 0 || next != 10 || more {
		t.Fatalf("stderr=%q start=%d next=%d more=%t", stderr, start, next, more)
	}
	stdout, stdoutStart, _, _ := buffer.read(execution.StreamStdout, 0, 0)
	if string(stdout) != "nestdout-two" || stdoutStart != 8 {
		t.Fatalf("stdout=%q start=%d, want %q start=8", stdout, stdoutStart, "nestdout-two")
	}
}
