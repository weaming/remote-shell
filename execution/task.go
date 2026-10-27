package execution

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	DefaultTimeout = 5 * time.Minute
	MaxTimeout     = time.Hour
)

type Mode string

const (
	ModeParallel Mode = "parallel"
	ModeSerial   Mode = "serial"
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

type Command struct {
	ID      string
	Shell   Shell
	Script  string
	CWD     string
	Env     map[string]string
	Stdin   []byte
	Timeout time.Duration
}

type Task struct {
	ID       string
	Mode     Mode
	Commands []Command
}

type Output struct {
	TaskID    string
	CommandID string
	Seq       uint64
	Stream    Stream
	Data      []byte
	At        time.Time
}

type CommandResult struct {
	CommandID string    `json:"command_id"`
	ExitCode  int       `json:"exit_code"`
	Err       string    `json:"error,omitempty"`
	TimedOut  bool      `json:"timed_out"`
	Cancelled bool      `json:"cancelled"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
}

type TaskResult struct {
	TaskID   string          `json:"task_id"`
	Commands []CommandResult `json:"commands"`
}

type OutputFunc func(context.Context, Output) error

type outputEmitter struct {
	taskID string
	seq    uint64
	mu     sync.Mutex
	write  OutputFunc
}

func (e *outputEmitter) emit(ctx context.Context, commandID string, stream Stream, data []byte) error {
	if e.write == nil || len(data) == 0 {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seq++
	return e.write(ctx, Output{
		TaskID:    e.taskID,
		CommandID: commandID,
		Seq:       e.seq,
		Stream:    stream,
		Data:      append([]byte(nil), data...),
		At:        time.Now(),
	})
}

func (task Task) validate() (Mode, []Command, error) {
	if strings.TrimSpace(task.ID) == "" {
		return "", nil, fmt.Errorf("task ID is required")
	}
	if len(task.Commands) == 0 {
		return "", nil, fmt.Errorf("at least one command is required")
	}

	mode := task.Mode
	if mode == "" {
		mode = ModeParallel
	}
	if mode != ModeParallel && mode != ModeSerial {
		return "", nil, fmt.Errorf("unsupported task mode %q", mode)
	}

	commands := append([]Command(nil), task.Commands...)
	seen := make(map[string]struct{}, len(commands))
	for index := range commands {
		command := &commands[index]
		if strings.TrimSpace(command.ID) == "" {
			return "", nil, fmt.Errorf("command %d: ID is required", index)
		}
		if _, ok := seen[command.ID]; ok {
			return "", nil, fmt.Errorf("duplicate command ID %q", command.ID)
		}
		seen[command.ID] = struct{}{}
		if strings.TrimSpace(command.Script) == "" {
			return "", nil, fmt.Errorf("command %q: script is required", command.ID)
		}
		if strings.TrimSpace(command.CWD) == "" {
			return "", nil, fmt.Errorf("command %q: cwd is required", command.ID)
		}
		if command.Timeout == 0 {
			command.Timeout = DefaultTimeout
		}
		if command.Timeout < 0 || command.Timeout > MaxTimeout {
			return "", nil, fmt.Errorf("command %q: timeout must be between 1ns and %s", command.ID, MaxTimeout)
		}
		for key, value := range command.Env {
			if key == "" || strings.ContainsAny(key, "=\x00") || strings.ContainsRune(value, '\x00') {
				return "", nil, fmt.Errorf("command %q: invalid environment variable %q", command.ID, key)
			}
		}
		if command.Shell != ShellBash && command.Shell != ShellFish && command.Shell != ShellZsh {
			return "", nil, fmt.Errorf("command %q: unsupported shell %q", command.ID, command.Shell)
		}
		info, err := os.Stat(command.CWD)
		if err != nil {
			return "", nil, fmt.Errorf("command %q: inspect cwd: %w", command.ID, err)
		}
		if !info.IsDir() {
			return "", nil, fmt.Errorf("command %q: cwd is not a directory", command.ID)
		}
	}
	return mode, commands, nil
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

func Run(ctx context.Context, task Task, output OutputFunc) (TaskResult, error) {
	mode, commands, err := task.validate()
	if err != nil {
		return TaskResult{}, err
	}
	taskCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	forward := output
	if output != nil {
		forward = func(ctx context.Context, chunk Output) error {
			err := output(ctx, chunk)
			if err != nil {
				cancel()
			}
			return err
		}
	}
	emitter := &outputEmitter{taskID: task.ID, write: forward}
	results := make([]CommandResult, len(commands))
	if mode == ModeSerial {
		for index, command := range commands {
			results[index] = runCommand(taskCtx, task.ID, command, emitter)
		}
	} else {
		var wait sync.WaitGroup
		wait.Add(len(commands))
		for index, command := range commands {
			go func(index int, command Command) {
				defer wait.Done()
				results[index] = runCommand(taskCtx, task.ID, command, emitter)
			}(index, command)
		}
		wait.Wait()
	}
	return TaskResult{TaskID: task.ID, Commands: results}, nil
}
