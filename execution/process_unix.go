//go:build darwin || linux || freebsd || openbsd || netbsd || dragonfly

package execution

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sync"
	"syscall"
	"time"
)

const outputChunkSize = 32 * 1024

// Tests override these graces, so keep them unexported and free of concurrent
// writes.
var (
	// terminateGrace is how long a terminated process group may take to exit.
	terminateGrace = 10 * time.Second
	// readerDrainGrace bounds how long a leaked pipe holder may delay a result.
	readerDrainGrace = 5 * time.Second
)

func runCommand(parent context.Context, command Command, emitter *outputEmitter) Result {
	result := Result{ExitCode: -1, StartedAt: time.Now()}
	ctx, cancel := context.WithTimeout(parent, command.Timeout)
	defer cancel()

	cmd, err := shellCommand(command.Shell, command.Script)
	if err != nil {
		result.Error = err.Error()
		result.EndedAt = time.Now()
		return result
	}
	cmd.Dir = command.CWD
	cmd.Env = mergedEnvironment(command.Env)
	cmd.Stdin = bytes.NewReader(command.Stdin)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		result.Error = fmt.Sprintf("create stdout pipe: %v", err)
		result.EndedAt = time.Now()
		return result
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		result.Error = fmt.Sprintf("create stderr pipe: %v", err)
		result.EndedAt = time.Now()
		return result
	}
	cmd.Stdout = stdoutWriter
	cmd.Stderr = stderrWriter

	if err := ctx.Err(); err != nil {
		closePipes(stdoutReader, stdoutWriter, stderrReader, stderrWriter)
		result.ExitCode, result.Cancelled, result.TimedOut, result.Error =
			classifyResult(false, nil, err, result.Error)
		result.EndedAt = time.Now()
		return result
	}
	if err := cmd.Start(); err != nil {
		closePipes(stdoutReader, stdoutWriter, stderrReader, stderrWriter)
		result.Error = fmt.Sprintf("start command: %v", err)
		result.EndedAt = time.Now()
		return result
	}
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	processGroupID := cmd.Process.Pid

	var readers sync.WaitGroup
	readers.Add(2)
	readerErrors := make(chan error, 2)
	go copyOutput(ctx, stdoutReader, StreamStdout, emitter, cancel, &readers, readerErrors)
	go copyOutput(ctx, stderrReader, StreamStderr, emitter, cancel, &readers, readerErrors)

	waitResult := make(chan error, 1)
	go func() { waitResult <- cmd.Wait() }()

	var waitErr error
	shellExited := false
	select {
	case waitErr = <-waitResult:
		shellExited = true
	case <-ctx.Done():
		waitErr = stopProcessGroup(processGroupID, waitResult)
	}
	readersDone := make(chan struct{})
	go func() {
		defer close(readersDone)
		readers.Wait()
	}()
	drainOutput(readersDone, stdoutReader, stderrReader, processGroupID, shellExited)
	select {
	case readerErr := <-readerErrors:
		if readerErr != nil {
			result.Error = readerErr.Error()
		}
	default:
	}

	result.ExitCode, result.Cancelled, result.TimedOut, result.Error =
		classifyResult(shellExited, waitErr, ctx.Err(), result.Error)
	result.EndedAt = time.Now()
	return result
}

func copyOutput(ctx context.Context, reader *os.File, stream Stream, emitter *outputEmitter, cancel context.CancelFunc, wait *sync.WaitGroup, errs chan<- error) {
	defer wait.Done()
	defer reader.Close()
	buffer := make([]byte, outputChunkSize)
	for {
		count, err := reader.Read(buffer)
		if count > 0 {
			if writeErr := emitter.emit(ctx, stream, buffer[:count]); writeErr != nil {
				cancel()
				select {
				case errs <- fmt.Errorf("forward %s output: %w", stream, writeErr):
				default:
				}
				return
			}
		}
		if err != nil {
			if isClosedRead(err) {
				// The agent closed its own read end to release a leaked pipe
				// holder; the command output simply ends here.
				return
			}
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				cancel()
				select {
				case errs <- fmt.Errorf("read %s output: %w", stream, err):
				default:
				}
			}
			return
		}
	}
}

func isClosedRead(err error) bool {
	return errors.Is(err, os.ErrClosed) || errors.Is(err, fs.ErrClosed)
}

func stopProcessGroup(processGroupID int, waitResult <-chan error) error {
	_ = signalProcessGroup(processGroupID, syscall.SIGTERM)
	return waitForGroup(processGroupID, nil, false, waitResult)
}

// waitReaderDrain reports whether the output readers finished within grace.
func waitReaderDrain(done <-chan struct{}, grace time.Duration) bool {
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

// drainOutput terminates whatever is left of the process group and returns only
// after the output readers finished, so a leaked pipe holder can never block a
// run result forever.
func drainOutput(readersDone <-chan struct{}, stdout, stderr *os.File, processGroupID int, shellExited bool) {
	if shellExited {
		// The shell is gone but descendants may still hold the pipes or run.
		if processGroupExists(processGroupID) {
			_ = signalProcessGroup(processGroupID, syscall.SIGTERM)
		}
	}
	if waitReaderDrain(readersDone, readerDrainGrace) {
		if shellExited && processGroupExists(processGroupID) {
			_ = signalProcessGroup(processGroupID, syscall.SIGKILL)
		}
		return
	}
	_ = signalProcessGroup(processGroupID, syscall.SIGKILL)
	if waitReaderDrain(readersDone, readerDrainGrace) {
		return
	}
	// A descendant escaped the process group while still holding the pipe.
	// Closing our read ends is the only way left to unblock the readers.
	_ = stdout.Close()
	_ = stderr.Close()
	<-readersDone
}

func waitForGroup(processGroupID int, waitErr error, processFinished bool, waitResult <-chan error) error {
	deadline := time.NewTimer(terminateGrace)
	defer deadline.Stop()
	poll := time.NewTicker(25 * time.Millisecond)
	defer poll.Stop()
	for {
		if !processFinished {
			select {
			case waitErr = <-waitResult:
				processFinished = true
			default:
			}
		}
		if processFinished && !processGroupExists(processGroupID) {
			return waitErr
		}
		select {
		case waitErr = <-waitResult:
			processFinished = true
		case <-poll.C:
		case <-deadline.C:
			_ = signalProcessGroup(processGroupID, syscall.SIGKILL)
			if !processFinished {
				waitErr = <-waitResult
			}
			return waitErr
		}
	}
}

func processGroupExists(processGroupID int) bool {
	err := syscall.Kill(-processGroupID, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func signalProcessGroup(processGroupID int, signal syscall.Signal) error {
	err := syscall.Kill(-processGroupID, signal)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

func closePipes(files ...*os.File) {
	for _, file := range files {
		_ = file.Close()
	}
}
