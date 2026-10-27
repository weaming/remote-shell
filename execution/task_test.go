package execution

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTaskDefaultsToParallelAndCommandTimeout(t *testing.T) {
	task := Task{
		ID: "task-1",
		Commands: []Command{{
			ID: "command-1", Shell: ShellBash, Script: "true", CWD: t.TempDir(),
		}},
	}
	mode, commands, err := task.validate()
	if err != nil {
		t.Fatal(err)
	}
	if mode != ModeParallel {
		t.Fatalf("default mode = %q, want %q", mode, ModeParallel)
	}
	if commands[0].Timeout != DefaultTimeout {
		t.Fatalf("default timeout = %s, want %s", commands[0].Timeout, DefaultTimeout)
	}
}

func TestDefaultModeRunsCommandsConcurrently(t *testing.T) {
	if _, err := shellCommand(ShellBash, "true"); err != nil {
		t.Skip("bash is not installed")
	}
	cwd := t.TempDir()
	result, err := Run(context.Background(), Task{
		ID: "parallel-task",
		Commands: []Command{
			{ID: "first", Shell: ShellBash, Script: "touch first; while [ ! -e second ]; do sleep 0.01; done", CWD: cwd, Timeout: 2 * time.Second},
			{ID: "second", Shell: ShellBash, Script: "touch second; while [ ! -e first ]; do sleep 0.01; done", CWD: cwd, Timeout: 2 * time.Second},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range result.Commands {
		if command.ExitCode != 0 || command.TimedOut {
			t.Fatalf("command %q did not run concurrently: %+v", command.CommandID, command)
		}
	}
}

func TestRunStreamsStdoutAndStderrWithSequence(t *testing.T) {
	if _, err := shellCommand(ShellBash, "true"); err != nil {
		t.Skip("bash is not installed")
	}

	var mu sync.Mutex
	var outputs []Output
	result, err := Run(context.Background(), Task{
		ID: "task-1",
		Commands: []Command{{
			ID: "command-1", Shell: ShellBash,
			Script: "printf stdout; printf stderr >&2",
			CWD:    t.TempDir(),
		}},
	}, func(_ context.Context, output Output) error {
		mu.Lock()
		outputs = append(outputs, output)
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Commands[0].ExitCode; got != 0 {
		t.Fatalf("exit code = %d, want 0; result=%+v", got, result.Commands[0])
	}

	mu.Lock()
	defer mu.Unlock()
	if len(outputs) < 2 {
		t.Fatalf("got %d output chunks, want stdout and stderr", len(outputs))
	}
	streams := map[Stream]string{}
	for index, output := range outputs {
		if output.Seq != uint64(index+1) {
			t.Fatalf("chunk %d has sequence %d", index, output.Seq)
		}
		streams[output.Stream] += string(output.Data)
	}
	if streams[StreamStdout] != "stdout" || streams[StreamStderr] != "stderr" {
		t.Fatalf("unexpected output streams: %#v", streams)
	}
}

func TestRunCancellationTerminatesProcessGroup(t *testing.T) {
	if _, err := shellCommand(ShellBash, "true"); err != nil {
		t.Skip("bash is not installed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	started := time.Now()
	result, err := Run(ctx, Task{
		ID: "task-cancel",
		Commands: []Command{{
			ID: "command-1", Shell: ShellBash,
			Script: "sleep 30 & wait",
			CWD:    t.TempDir(),
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("cancellation took %s, expected prompt process-group cleanup", elapsed)
	}
	if !result.Commands[0].Cancelled {
		t.Fatalf("command was not marked cancelled: %+v", result.Commands[0])
	}
}

func TestRunTimeoutIsReported(t *testing.T) {
	if _, err := shellCommand(ShellBash, "true"); err != nil {
		t.Skip("bash is not installed")
	}
	result, err := Run(context.Background(), Task{
		ID: "task-timeout",
		Commands: []Command{{
			ID: "command-1", Shell: ShellBash, Script: "sleep 30", CWD: t.TempDir(), Timeout: 100 * time.Millisecond,
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Commands[0].TimedOut || result.Commands[0].Cancelled {
		t.Fatalf("unexpected timeout status: %+v", result.Commands[0])
	}
}

func TestRunReportsNonzeroExitCode(t *testing.T) {
	if _, err := shellCommand(ShellBash, "true"); err != nil {
		t.Skip("bash is not installed")
	}
	result, err := Run(context.Background(), Task{
		ID: "task-failure",
		Commands: []Command{{
			ID: "command-1", Shell: ShellBash, Script: "exit 7", CWD: t.TempDir(),
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Commands[0].ExitCode; got != 7 {
		t.Fatalf("exit code = %d, want 7", got)
	}
	if strings.TrimSpace(result.Commands[0].Err) != "" {
		t.Fatalf("nonzero exit should be represented by exit code, got error %q", result.Commands[0].Err)
	}
}

func TestBackgroundChildDoesNotDelayResult(t *testing.T) {
	if _, err := shellCommand(ShellBash, "true"); err != nil {
		t.Skip("bash is not installed")
	}
	started := time.Now()
	result, err := Run(context.Background(), Task{
		ID: "task-background",
		Commands: []Command{{
			ID: "command-1", Shell: ShellBash,
			Script: `( sleep 30 ) & exit 0`,
			CWD:    t.TempDir(), Timeout: 20 * time.Second,
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > readerDrainGrace+3*time.Second {
		t.Fatalf("background child delayed the result by %s", elapsed)
	}
	if result.Commands[0].ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", result.Commands[0].ExitCode)
	}
}

func TestTermIgnoringBackgroundChildDoesNotMarkCommandCancelled(t *testing.T) {
	if _, err := shellCommand(ShellBash, "true"); err != nil {
		t.Skip("bash is not installed")
	}
	original := readerDrainGrace
	readerDrainGrace = 200 * time.Millisecond
	defer func() { readerDrainGrace = original }()

	result, err := Run(context.Background(), Task{
		ID: "task-stubborn-child",
		Commands: []Command{{
			ID: "command-1", Shell: ShellBash,
			// The descendant stays in the group, ignores TERM and holds the pipe.
			Script: `trap '' TERM; ( sleep 30 ) & printf hi`,
			CWD:    t.TempDir(), Timeout: 20 * time.Second,
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := result.Commands[0]
	if got.Cancelled || got.TimedOut {
		t.Fatalf("normal exit was reported as cancelled/timed out: %+v", got)
	}
	if got.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0 (err %q)", got.ExitCode, got.Err)
	}
}

func TestCancellationRacingExitKeepsResultCoherent(t *testing.T) {
	if _, err := shellCommand(ShellBash, "true"); err != nil {
		t.Skip("bash is not installed")
	}
	for iteration := 0; iteration < 60; iteration++ {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(time.Duration(2+iteration%8)*time.Millisecond, cancel)
		result, err := Run(ctx, Task{
			ID: "task-race",
			Commands: []Command{{
				ID: "command-1", Shell: ShellBash, Script: "true", CWD: t.TempDir(), Timeout: 5 * time.Second,
			}},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		got := result.Commands[0]
		if got.Cancelled || got.TimedOut {
			continue
		}
		if got.ExitCode != 0 || got.Err != "" {
			t.Fatalf("iteration %d reported a partial result: %+v", iteration, got)
		}
	}
}

func TestTimeoutSurvivesLateParentCancellation(t *testing.T) {
	if _, err := shellCommand(ShellBash, "true"); err != nil {
		t.Skip("bash is not installed")
	}
	originalGrace := terminateGrace
	terminateGrace = 300 * time.Millisecond
	defer func() { terminateGrace = originalGrace }()

	ctx, cancel := context.WithCancel(context.Background())
	type outcome struct {
		result TaskResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := Run(ctx, Task{
			ID: "task-timeout-then-cancel",
			Commands: []Command{{
				ID: "command-1", Shell: ShellBash,
				// Ignores TERM so the termination grace is still running when
				// the parent cancellation arrives.
				Script:  `trap '' TERM; while :; do sleep 0.05; done`,
				CWD:     t.TempDir(),
				Timeout: 100 * time.Millisecond,
			}},
		}, nil)
		done <- outcome{result: result, err: err}
	}()
	// Arrive while the timeout cleanup is still waiting for the stubborn shell.
	time.Sleep(300 * time.Millisecond)
	cancel()
	finished := <-done
	if finished.err != nil {
		t.Fatal(finished.err)
	}
	result := finished.result
	got := result.Commands[0]
	if !got.TimedOut {
		t.Fatalf("timeout was lost: %+v", got)
	}
}

func TestEscapedPipeHolderDoesNotMarkCommandCancelled(t *testing.T) {
	if _, err := shellCommand(ShellBash, "true"); err != nil {
		t.Skip("bash is not installed")
	}
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid is not installed")
	}
	original := readerDrainGrace
	readerDrainGrace = 200 * time.Millisecond
	defer func() { readerDrainGrace = original }()

	result, err := Run(context.Background(), Task{
		ID: "task-escaped",
		Commands: []Command{{
			ID: "command-1", Shell: ShellBash,
			// The descendant leaves the process group, ignores TERM and keeps the
			// pipe open; the sleep gives it time to call setsid().
			Script: `trap '' TERM HUP INT; setsid sleep 5 & sleep 1; printf hi`,
			CWD:    t.TempDir(), Timeout: 20 * time.Second,
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := result.Commands[0]
	if got.Cancelled || got.TimedOut {
		t.Fatalf("normal exit was reported as cancelled/timed out: %+v", got)
	}
	if got.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0 (err %q)", got.ExitCode, got.Err)
	}
}

func TestRunPassesEnvironmentAndStdin(t *testing.T) {
	if _, err := shellCommand(ShellBash, "true"); err != nil {
		t.Skip("bash is not installed")
	}
	var output strings.Builder
	result, err := Run(context.Background(), Task{
		ID: "task-input",
		Commands: []Command{{
			ID: "command-1", Shell: ShellBash,
			Script: `IFS= read -r input; printf '%s:%s' "$CUSTOM_VALUE" "$input"`,
			CWD:    t.TempDir(),
			Env:    map[string]string{"CUSTOM_VALUE": "from-env"},
			Stdin:  []byte("from-stdin\n"),
		}},
	}, func(_ context.Context, chunk Output) error {
		output.Write(chunk.Data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Commands[0].ExitCode; got != 0 {
		t.Fatalf("exit code = %d, want 0", got)
	}
	if got, want := output.String(), "from-env:from-stdin"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestOutputFailureCancelsCommand(t *testing.T) {
	if _, err := shellCommand(ShellBash, "true"); err != nil {
		t.Skip("bash is not installed")
	}
	result, err := Run(context.Background(), Task{
		ID: "task-output-error",
		Commands: []Command{{
			ID: "command-1", Shell: ShellBash,
			Script: "while true; do printf x; done",
			CWD:    t.TempDir(),
		}},
	}, func(_ context.Context, _ Output) error {
		return errors.New("client disconnected")
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Commands[0].Cancelled {
		t.Fatalf("command was not marked cancelled: %+v", result.Commands[0])
	}
	if !strings.Contains(result.Commands[0].Err, "client disconnected") {
		t.Fatalf("missing output forwarding error: %+v", result.Commands[0])
	}
}
