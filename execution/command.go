package execution

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	DefaultTimeout = 5 * time.Minute
	MaxTimeout     = time.Hour
)

type Shell string

const (
	ShellBash Shell = "bash"
	ShellFish Shell = "fish"
	ShellZsh  Shell = "zsh"
)

type Stream string

const (
	StreamStdout Stream = "stdout"
	StreamStderr Stream = "stderr"
)

// Command is one shell invocation, which is the only unit of work an agent
// runs.
type Command struct {
	Shell   Shell
	Script  string
	CWD     string
	Env     map[string]string
	Stdin   []byte
	Timeout time.Duration
}

// Output is one chunk forwarded from a running command.
type Output struct {
	RunID  string
	Seq    uint64
	Stream Stream
	Data   []byte
	At     time.Time
}

// Result is how one run ended.
type Result struct {
	RunID     string    `json:"run_id"`
	ExitCode  int       `json:"exit_code"`
	Error     string    `json:"error,omitempty"`
	TimedOut  bool      `json:"timed_out"`
	Cancelled bool      `json:"cancelled"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
}

type OutputFunc func(context.Context, Output) error

type outputEmitter struct {
	runID string
	seq   uint64
	mu    sync.Mutex
	write OutputFunc
}

func (e *outputEmitter) emit(ctx context.Context, stream Stream, data []byte) error {
	if e.write == nil || len(data) == 0 {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seq++
	return e.write(ctx, Output{
		RunID:  e.runID,
		Seq:    e.seq,
		Stream: stream,
		Data:   append([]byte(nil), data...),
		At:     time.Now(),
	})
}

// Run validates the command, runs it in its own process group, and reports how
// it ended. The error is reserved for validation and infrastructure failures; a
// cancelled or timed-out command still returns a result.
func Run(ctx context.Context, runID string, command Command, output OutputFunc) (Result, error) {
	if strings.TrimSpace(runID) == "" {
		return Result{}, fmt.Errorf("run ID is required")
	}
	normalized, err := command.normalize()
	if err != nil {
		return Result{}, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	forward := output
	if output != nil {
		forward = func(ctx context.Context, chunk Output) error {
			writeErr := output(ctx, chunk)
			if writeErr != nil {
				cancel()
			}
			return writeErr
		}
	}
	result := runCommand(runCtx, normalized, &outputEmitter{runID: runID, write: forward})
	result.RunID = runID
	return result, nil
}

// normalize fills defaults and rejects a command the agent cannot run.
func (c Command) normalize() (Command, error) {
	command := c
	command.Env = c.Env
	if strings.TrimSpace(command.Script) == "" {
		return Command{}, fmt.Errorf("script is required")
	}
	if strings.TrimSpace(command.CWD) == "" {
		return Command{}, fmt.Errorf("cwd is required")
	}
	command.CWD = expandHome(command.CWD)
	if !filepath.IsAbs(command.CWD) {
		return Command{}, fmt.Errorf("cwd must be an absolute path or start with ~")
	}
	if command.Shell != ShellBash && command.Shell != ShellFish && command.Shell != ShellZsh {
		return Command{}, fmt.Errorf("unsupported shell %q", command.Shell)
	}
	if command.Timeout == 0 {
		command.Timeout = DefaultTimeout
	}
	if command.Timeout < 0 || command.Timeout > MaxTimeout {
		return Command{}, fmt.Errorf("timeout must be between 1ns and %s", MaxTimeout)
	}
	for key, value := range command.Env {
		if key == "" || strings.ContainsAny(key, "=\x00") || strings.ContainsRune(value, '\x00') {
			return Command{}, fmt.Errorf("invalid environment variable %q", key)
		}
	}
	info, err := os.Stat(command.CWD)
	if err != nil {
		return Command{}, fmt.Errorf("inspect cwd: %w", err)
	}
	if !info.IsDir() {
		return Command{}, fmt.Errorf("cwd is not a directory")
	}
	return command, nil
}

// expandHome turns "~" and "~/…" into the agent user's home directory. Only the
// leading form is expanded, so a literal "~" inside a path is left alone.
func expandHome(path string) string {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return path
	}
	if path == "~" {
		return home
	}
	return filepath.Join(home, path[2:])
}

func mergedEnvironment(overrides map[string]string) []string {
	values := make(map[string]string)
	for _, item := range os.Environ() {
		key, value, ok := strings.Cut(item, "=")
		if ok {
			values[key] = value
		}
	}
	for key, value := range overrides {
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+values[key])
	}
	return env
}
