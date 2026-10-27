package mcpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"remote-shell/execution"
)

type taskState string

const (
	stateRunning   taskState = "running"
	stateSucceeded taskState = "succeeded"
	stateFailed    taskState = "failed"
	stateCancelled taskState = "cancelled"
	stateTimedOut  taskState = "timed_out"
)

// task is one submitted run_command call. It is retained after completion so
// the caller can re-read output, switch between stdout and stderr, and inspect
// the exit code without re-running anything.
type task struct {
	id       string
	selector string
	nodeID   string
	addrs    []string
	shell    execution.Shell
	script   string
	cwd      string
	ctx      context.Context
	cancel   context.CancelFunc
	buf      *outputBuffer
	done     chan struct{}
	started  time.Time

	mu         sync.Mutex
	node       string
	state      taskState
	exitCode   int
	errText    string
	finishedAt time.Time
	finished   bool
}

func newTask(ctx context.Context, cancel context.CancelFunc, id, selector string, target dialTarget, command execution.Command, maxOutputBytes int64) *task {
	return &task{
		id:       id,
		selector: selector,
		nodeID:   target.nodeID,
		addrs:    append([]string(nil), target.addresses...),
		shell:    command.Shell,
		script:   command.Script,
		cwd:      command.CWD,
		ctx:      ctx,
		cancel:   cancel,
		buf:      newOutputBuffer(maxOutputBytes),
		done:     make(chan struct{}),
		started:  time.Now(),
		state:    stateRunning,
	}
}

// setNode records the candidate address that actually accepted the connection.
func (t *task) setNode(address string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.node = address
}

// dialAddresses returns the candidate addresses in dial order.
func (t *task) dialAddresses() []string {
	return t.addrs
}

// complete records the outcome once the transport call returns.
func (t *task) complete(result execution.TaskResult, runErr error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.finished = true
	t.finishedAt = time.Now()
	switch {
	case runErr != nil:
		if t.ctx.Err() != nil {
			t.state = stateCancelled
			t.errText = "task cancelled"
			return
		}
		t.state = stateFailed
		t.errText = runErr.Error()
	case len(result.Commands) == 0:
		t.state = stateFailed
		t.errText = "agent returned no command result"
	default:
		command := result.Commands[0]
		t.exitCode = command.ExitCode
		switch {
		case command.Cancelled:
			t.state = stateCancelled
		case command.TimedOut:
			t.state = stateTimedOut
		case command.Err != "":
			t.state = stateFailed
			t.errText = command.Err
		case command.ExitCode == 0:
			t.state = stateSucceeded
		default:
			t.state = stateFailed
		}
	}
}

type snapshot struct {
	ID           string
	Node         string
	Shell        execution.Shell
	Script       string
	CWD          string
	State        taskState
	ExitCode     int
	ErrText      string
	Started      time.Time
	Finished     time.Time
	Done         bool
	StdoutBytes  int64
	StderrBytes  int64
	TrimmedBytes int64
}

func (t *task) snapshot() snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	return snapshot{
		ID:           t.id,
		Node:         t.reportNode(),
		Shell:        t.shell,
		Script:       t.script,
		CWD:          t.cwd,
		State:        t.state,
		ExitCode:     t.exitCode,
		ErrText:      t.errText,
		Started:      t.started,
		Finished:     t.finishedAt,
		Done:         t.finished,
		StdoutBytes:  t.buf.streamBytes(execution.StreamStdout),
		StderrBytes:  t.buf.streamBytes(execution.StreamStderr),
		TrimmedBytes: t.buf.trimmed(""),
	}
}

// reportNode prefers the address that answered and falls back to the first
// candidate while the connection is still being established.
func (t *task) reportNode() string {
	if t.node != "" {
		return t.node
	}
	if len(t.addrs) == 0 {
		return ""
	}
	return t.addrs[0]
}

// registry holds recent tasks. Finished tasks expire so a long-lived MCP
// server cannot grow without bound.
type registry struct {
	mu     sync.Mutex
	tasks  map[string]*task
	order  []string
	max    int
	retain time.Duration
}

func newRegistry(max int, retain time.Duration) *registry {
	return &registry{tasks: make(map[string]*task, max), max: max, retain: retain}
}

func (r *registry) add(current *task) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	r.tasks[current.id] = current
	r.order = append(r.order, current.id)
}

func (r *registry) get(id string) (*task, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, ok := r.tasks[id]
	return current, ok
}

func (r *registry) list() []snapshot {
	r.mu.Lock()
	items := make([]*task, 0, len(r.order))
	for _, id := range r.order {
		if current, ok := r.tasks[id]; ok {
			items = append(items, current)
		}
	}
	r.mu.Unlock()
	snapshots := make([]snapshot, 0, len(items))
	for _, current := range items {
		snapshots = append(snapshots, current.snapshot())
	}
	return snapshots
}

// prune drops expired finished tasks and then the oldest finished tasks while
// the registry is over capacity. Running tasks are never dropped.
func (r *registry) prune() {
	now := time.Now()
	kept := r.order[:0]
	for _, id := range r.order {
		current, ok := r.tasks[id]
		if !ok {
			continue
		}
		if current.isExpired(now, r.retain) {
			delete(r.tasks, id)
			continue
		}
		kept = append(kept, id)
	}
	r.order = kept
	for r.max > 0 && len(r.order) > r.max {
		evicted := false
		for index, id := range r.order {
			current, ok := r.tasks[id]
			if ok && current.isFinished() {
				delete(r.tasks, id)
				r.order = append(r.order[:index], r.order[index+1:]...)
				evicted = true
				break
			}
		}
		if !evicted {
			return
		}
	}
}

func (t *task) isFinished() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.finished
}

func (t *task) isExpired(now time.Time, retain time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.finished && retain > 0 && now.Sub(t.finishedAt) > retain
}

// newTaskID returns a short random identifier for a submitted task.
func newTaskID() (string, error) {
	raw := make([]byte, 6)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate task ID: %w", err)
	}
	return "t-" + hex.EncodeToString(raw), nil
}
