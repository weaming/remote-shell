package execution

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRunStreamsStdoutAndStderrWithSequence(t *testing.T) {
	if _, err := shellCommand(ShellBash, "true"); err != nil {
		t.Skip("bash is not installed")
	}

	var mu sync.Mutex
	var outputs []Output
	result, err := Run(context.Background(), "run-1", Command{
		Shell:  ShellBash,
		Script: "printf stdout; printf stderr >&2",
		CWD:    t.TempDir(),
	}, func(_ context.Context, output Output) error {
		mu.Lock()
		outputs = append(outputs, output)
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.ExitCode; got != 0 {
		t.Fatalf("exit code = %d, want 0; result=%+v", got, result)
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
	result, err := Run(ctx, "run-cancel", Command{
		Shell:  ShellBash,
		Script: "sleep 30 & wait",
		CWD:    t.TempDir(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("cancellation took %s, expected prompt process-group cleanup", elapsed)
	}
	if !result.Cancelled {
		t.Fatalf("command was not marked cancelled: %+v", result)
	}
}

func TestRunTimeoutIsReported(t *testing.T) {
	if _, err := shellCommand(ShellBash, "true"); err != nil {
		t.Skip("bash is not installed")
	}
	result, err := Run(context.Background(), "run-timeout", Command{
		Shell: ShellBash, Script: "sleep 30", CWD: t.TempDir(), Timeout: 100 * time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.TimedOut || result.Cancelled {
		t.Fatalf("unexpected timeout status: %+v", result)
	}
}

func TestRunReportsNonzeroExitCode(t *testing.T) {
	if _, err := shellCommand(ShellBash, "true"); err != nil {
		t.Skip("bash is not installed")
	}
	result, err := Run(context.Background(), "run-failure", Command{
		Shell: ShellBash, Script: "exit 7", CWD: t.TempDir(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := result.ExitCode; got != 7 {
		t.Fatalf("exit code = %d, want 7", got)
	}
	if strings.TrimSpace(result.Error) != "" {
		t.Fatalf("nonzero exit should be represented by exit code, got error %q", result.Error)
	}
}

func TestBackgroundChildDoesNotDelayResult(t *testing.T) {
	if _, err := shellCommand(ShellBash, "true"); err != nil {
		t.Skip("bash is not installed")
	}
	started := time.Now()
	result, err := Run(context.Background(), "run-background", Command{
		Shell:  ShellBash,
		Script: `( sleep 30 ) & exit 0`,
		CWD:    t.TempDir(), Timeout: 20 * time.Second,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > readerDrainGrace+3*time.Second {
		t.Fatalf("background child delayed the result by %s", elapsed)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", result.ExitCode)
	}
}

func TestTermIgnoringBackgroundChildDoesNotMarkCommandCancelled(t *testing.T) {
	if _, err := shellCommand(ShellBash, "true"); err != nil {
		t.Skip("bash is not installed")
	}
	original := readerDrainGrace
	readerDrainGrace = 200 * time.Millisecond
	defer func() { readerDrainGrace = original }()

	result, err := Run(context.Background(), "run-stubborn-child", Command{
		Shell: ShellBash,
		// The descendant stays in the group, ignores TERM and holds the pipe.
		Script: `trap '' TERM; ( sleep 30 ) & printf hi`,
		CWD:    t.TempDir(), Timeout: 20 * time.Second,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := result
	if got.Cancelled || got.TimedOut {
		t.Fatalf("normal exit was reported as cancelled/timed out: %+v", got)
	}
	if got.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0 (err %q)", got.ExitCode, got.Error)
	}
}

func TestCancellationRacingExitKeepsResultCoherent(t *testing.T) {
	if _, err := shellCommand(ShellBash, "true"); err != nil {
		t.Skip("bash is not installed")
	}
	for iteration := 0; iteration < 60; iteration++ {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(time.Duration(2+iteration%8)*time.Millisecond, cancel)
		result, err := Run(ctx, "run-race", Command{
			Shell: ShellBash, Script: "true", CWD: t.TempDir(), Timeout: 5 * time.Second,
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		got := result
		if got.Cancelled || got.TimedOut {
			continue
		}
		if got.ExitCode != 0 || got.Error != "" {
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
		result Result
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := Run(ctx, "run-timeout-then-cancel", Command{
			Shell: ShellBash,
			// Ignores TERM so the termination grace is still running when
			// the parent cancellation arrives.
			Script:  `trap '' TERM; while :; do sleep 0.05; done`,
			CWD:     t.TempDir(),
			Timeout: 100 * time.Millisecond,
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
	got := result
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

	result, err := Run(context.Background(), "run-escaped", Command{
		Shell: ShellBash,
		// The descendant leaves the process group, ignores TERM and keeps the
		// pipe open; the sleep gives it time to call setsid().
		Script: `trap '' TERM HUP INT; setsid sleep 5 & sleep 1; printf hi`,
		CWD:    t.TempDir(), Timeout: 20 * time.Second,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := result
	if got.Cancelled || got.TimedOut {
		t.Fatalf("normal exit was reported as cancelled/timed out: %+v", got)
	}
	if got.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0 (err %q)", got.ExitCode, got.Error)
	}
}

func TestRunPassesEnvironmentAndStdin(t *testing.T) {
	if _, err := shellCommand(ShellBash, "true"); err != nil {
		t.Skip("bash is not installed")
	}
	var output strings.Builder
	result, err := Run(context.Background(), "run-input", Command{
		Shell:  ShellBash,
		Script: `IFS= read -r input; printf '%s:%s' "$CUSTOM_VALUE" "$input"`,
		CWD:    t.TempDir(),
		Env:    map[string]string{"CUSTOM_VALUE": "from-env"},
		Stdin:  []byte("from-stdin\n"),
	}, func(_ context.Context, chunk Output) error {
		output.Write(chunk.Data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.ExitCode; got != 0 {
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
	result, err := Run(context.Background(), "run-output-error", Command{
		Shell:  ShellBash,
		Script: "while true; do printf x; done",
		CWD:    t.TempDir(),
	}, func(_ context.Context, _ Output) error {
		return errors.New("client disconnected")
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Cancelled {
		t.Fatalf("command was not marked cancelled: %+v", result)
	}
	if !strings.Contains(result.Error, "client disconnected") {
		t.Fatalf("missing output forwarding error: %+v", result)
	}
}

func TestRunExpandsHomeInCWD(t *testing.T) {
	if _, err := shellCommand(ShellBash, "true"); err != nil {
		t.Skip("bash is not installed")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home directory")
	}
	var output strings.Builder
	result, err := Run(context.Background(), "run-home", Command{
		Shell:  ShellBash,
		Script: "pwd",
		CWD:    "~/",
	}, func(_ context.Context, chunk Output) error {
		output.Write(chunk.Data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", result.ExitCode)
	}
	if got := strings.TrimSpace(output.String()); got != home {
		t.Fatalf("pwd = %q, want the agent home %q", got, home)
	}
}

func TestRunRejectsRelativeCWD(t *testing.T) {
	_, err := Run(context.Background(), "run-relative", Command{
		Shell:  ShellBash,
		Script: "true",
		CWD:    "tmp",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("err = %v, want a rejection of the relative cwd", err)
	}
}
