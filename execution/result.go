package execution

import (
	"context"
	"errors"
	"os/exec"
)

// classifyResult maps how a command ended onto a command result.
//
// A shell that already exited has an authoritative exit status, even when the
// task context was cancelled meanwhile. Otherwise the first observed context
// error decides between cancellation and timeout, so a parent cancellation
// arriving during the termination grace cannot erase an observed timeout.
// A non-empty currentErr (for example an output forwarding failure) wins over
// context text, because it carries more specific information.
func classifyResult(shellExited bool, waitErr, ctxErr error, currentErr string) (exitCode int, cancelled, timedOut bool, errText string) {
	exitCode = -1
	errText = currentErr

	if !shellExited && ctxErr != nil {
		switch {
		case errors.Is(ctxErr, context.Canceled):
			cancelled = true
		case errors.Is(ctxErr, context.DeadlineExceeded):
			timedOut = true
		}
		if errText == "" {
			errText = ctxErr.Error()
		}
		return exitCode, cancelled, timedOut, errText
	}

	if waitErr == nil {
		return 0, false, false, errText
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return exitErr.ExitCode(), false, false, errText
	}
	if errText == "" {
		errText = waitErr.Error()
	}
	return exitCode, false, false, errText
}
