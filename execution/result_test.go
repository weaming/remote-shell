package execution

import (
	"context"
	"errors"
	"os/exec"
	"testing"
)

func TestClassifyResult(t *testing.T) {
	exitError := func(script string) error {
		command := exec.Command("sh", "-c", script)
		return command.Run()
	}
	plainError := errors.New("wait failed")

	tests := []struct {
		name         string
		shellExited  bool
		waitErr      error
		ctxErr       error
		currentErr   string
		wantExit     int
		wantCancel   bool
		wantTimedOut bool
		wantErr      string
	}{
		{name: "clean exit", shellExited: true, wantExit: 0},
		{name: "exit code", shellExited: true, waitErr: exitError("exit 3"), wantExit: 3},
		{name: "wait failure", shellExited: true, waitErr: plainError, wantExit: -1, wantErr: "wait failed"},
		{name: "shell exit beats cancel", shellExited: true, ctxErr: context.Canceled, wantExit: 0},
		{name: "shell exit beats timeout", shellExited: true, ctxErr: context.DeadlineExceeded, wantExit: 0},
		{name: "cancelled", ctxErr: context.Canceled, wantExit: -1, wantCancel: true, wantErr: "context canceled"},
		{name: "timed out", ctxErr: context.DeadlineExceeded, wantExit: -1, wantTimedOut: true, wantErr: "context deadline exceeded"},
		{
			name: "timeout survives later cancellation", shellExited: false,
			ctxErr: context.DeadlineExceeded, wantExit: -1, wantTimedOut: true,
			wantErr: "context deadline exceeded",
		},
		{
			name: "shell exit wins over cancellation", shellExited: true,
			waitErr: exitError("exit 4"), ctxErr: context.Canceled, wantExit: 4,
		},
		{
			name: "output failure keeps timeout", ctxErr: context.DeadlineExceeded,
			currentErr: "forward stdout output: broken pipe", wantExit: -1, wantTimedOut: true,
			wantErr: "forward stdout output: broken pipe",
		},
		{
			name: "output failure beats wait text", shellExited: true, waitErr: plainError,
			currentErr: "forward stderr output: broken pipe", wantExit: -1,
			wantErr: "forward stderr output: broken pipe",
		},
		{
			name: "signal wait error does not override cancel", ctxErr: context.Canceled,
			waitErr: exitError("kill -9 $$"), wantExit: -1, wantCancel: true,
			wantErr: "context canceled",
		},
		{
			name: "signal kill without cancel", shellExited: true,
			waitErr: exitError("kill -9 $$"), wantExit: -1,
		},
		{
			name: "clean exit keeps output failure", shellExited: true,
			currentErr: "forward stdout output: broken pipe", wantExit: 0,
			wantErr: "forward stdout output: broken pipe",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exitCode, cancelled, timedOut, errText := classifyResult(
				test.shellExited, test.waitErr, test.ctxErr, test.currentErr,
			)
			if exitCode != test.wantExit || cancelled != test.wantCancel || timedOut != test.wantTimedOut || errText != test.wantErr {
				t.Fatalf(
					"got exit=%d cancelled=%v timedOut=%v err=%q, want exit=%d cancelled=%v timedOut=%v err=%q",
					exitCode, cancelled, timedOut, errText,
					test.wantExit, test.wantCancel, test.wantTimedOut, test.wantErr,
				)
			}
		})
	}
}
