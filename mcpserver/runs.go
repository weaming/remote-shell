package mcpserver

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"remote-shell/client"
	"remote-shell/execution"
)

type runState string

const (
	stateRunning   runState = "running"
	stateSucceeded runState = "succeeded"
	stateFailed    runState = "failed"
	stateCancelled runState = "cancelled"
	stateTimedOut  runState = "timed_out"
)

// run is one shell run started through the shell tool. Its ID is assigned by the
// agent, so it stays meaningful across bridge restarts. A run is kept after it
// finishes until it expires, so its output and exit code stay queryable.
type run struct {
	selector string
	nodeID   string
	addrs    []string
	shell    execution.Shell
	script   string
	cwd      string
	ctx      context.Context
	cancel   context.CancelFunc
	buf      *outputBuffer
	// ready is closed once the agent assigned the run ID and the run is
	// registered, so a caller can report the ID immediately.
	ready   chan struct{}
	done    chan struct{}
	started time.Time

	mu         sync.Mutex
	id         string
	name       string
	node       string
	handle     *client.Run
	state      runState
	exitCode   int
	errText    string
	finishedAt time.Time
	finished   bool
	readyOnce  sync.Once
}

func newRun(ctx context.Context, cancel context.CancelFunc, selector string, target dialTarget, command execution.Command, maxOutputBytes int64) *run {
	return &run{
		selector: selector,
		nodeID:   target.nodeID,
		addrs:    append([]string(nil), target.addresses...),
		shell:    command.Shell,
		script:   command.Script,
		cwd:      command.CWD,
		ctx:      ctx,
		cancel:   cancel,
		buf:      newOutputBuffer(maxOutputBytes),
		ready:    make(chan struct{}),
		done:     make(chan struct{}),
		started:  time.Now(),
		state:    stateRunning,
	}
}

// setHandle records what the agent accepted, including its run ID.
func (r *run) setHandle(handle *client.Run, node string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handle = handle
	r.id = handle.ID
	r.name = handle.Name
	r.node = node
}

// markReady publishes the run to callers waiting for its ID.
func (r *run) markReady() {
	r.readyOnce.Do(func() { close(r.ready) })
}

func (r *run) ID() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.id
}

// cancelRun asks the agent to stop the run.
func (r *run) cancelRun() {
	r.cancel()
	r.mu.Lock()
	handle := r.handle
	r.mu.Unlock()
	if handle != nil {
		_ = handle.Cancel()
	}
}

// fail records a run that never started, and unblocks anyone waiting for its ID.
func (r *run) fail(err error) {
	r.mu.Lock()
	r.state = stateFailed
	r.errText = err.Error()
	r.finished = true
	r.finishedAt = time.Now()
	r.mu.Unlock()
	r.markReady()
}

// complete records the outcome once the agent reports it.
func (r *run) complete(result execution.Result, runErr error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.finished = true
	r.finishedAt = time.Now()
	switch {
	case runErr != nil:
		if r.ctx.Err() != nil {
			r.state = stateCancelled
			r.errText = "run cancelled"
			return
		}
		r.state = stateFailed
		r.errText = runErr.Error()
	case result.Cancelled:
		r.state = stateCancelled
		r.exitCode = result.ExitCode
	case result.TimedOut:
		r.state = stateTimedOut
		r.exitCode = result.ExitCode
	case result.Error != "":
		r.state = stateFailed
		r.exitCode = result.ExitCode
		r.errText = result.Error
	case result.ExitCode != 0:
		r.state = stateFailed
		r.exitCode = result.ExitCode
	default:
		r.state = stateSucceeded
	}
	if result.RunID != "" {
		r.id = result.RunID
	}
}

type snapshot struct {
	ID           string
	Name         string
	Node         string
	Shell        execution.Shell
	Script       string
	CWD          string
	State        runState
	ExitCode     int
	ErrText      string
	Started      time.Time
	Finished     time.Time
	Done         bool
	StdoutBytes  int64
	StderrBytes  int64
	TrimmedBytes int64
}

func (r *run) snapshot() snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	node := r.node
	if node == "" {
		node = r.addrs[0]
	}
	return snapshot{
		ID:           r.id,
		Name:         r.name,
		Node:         node,
		Shell:        r.shell,
		Script:       r.script,
		CWD:          r.cwd,
		State:        r.state,
		ExitCode:     r.exitCode,
		ErrText:      r.errText,
		Started:      r.started,
		Finished:     r.finishedAt,
		Done:         r.finished,
		StdoutBytes:  r.buf.streamBytes(execution.StreamStdout),
		StderrBytes:  r.buf.streamBytes(execution.StreamStderr),
		TrimmedBytes: r.buf.trimmed(""),
	}
}

func (s snapshot) duration() time.Duration {
	if s.Finished.IsZero() {
		return time.Since(s.Started)
	}
	return s.Finished.Sub(s.Started)
}

// registry holds recent runs, keyed by the agent-assigned run ID. Finished runs
// expire so a long-lived bridge cannot grow without bound.
type registry struct {
	mu     sync.Mutex
	runs   map[string]*run
	order  []string
	max    int
	retain time.Duration
}

func newRegistry(max int, retain time.Duration) *registry {
	return &registry{runs: make(map[string]*run, max), max: max, retain: retain}
}

func (r *registry) add(current *run) {
	id := current.ID()
	if id == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	r.runs[id] = current
	r.order = append(r.order, id)
}

func (r *registry) get(id string) (*run, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, ok := r.runs[id]
	return current, ok
}

func (r *registry) list() []snapshot {
	r.mu.Lock()
	items := make([]*run, 0, len(r.order))
	for _, id := range r.order {
		if current, ok := r.runs[id]; ok {
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

// prune drops expired finished runs and then the oldest finished runs while the
// registry is over capacity. Running runs are never dropped.
func (r *registry) prune() {
	now := time.Now()
	kept := r.order[:0]
	for _, id := range r.order {
		current, ok := r.runs[id]
		if !ok {
			continue
		}
		if current.isExpired(now, r.retain) {
			delete(r.runs, id)
			continue
		}
		kept = append(kept, id)
	}
	r.order = kept
	for r.max > 0 && len(r.order) > r.max {
		evicted := false
		for index, id := range r.order {
			current, ok := r.runs[id]
			if ok && current.isFinished() {
				delete(r.runs, id)
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

func (r *run) isFinished() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.finished
}

func (r *run) isExpired(now time.Time, retain time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.finished && retain > 0 && now.Sub(r.finishedAt) > retain
}

// logValue renders one field of the key=value line, quoting it when it would
// otherwise break the space-separated format.
func logValue(value string) string {
	if value == "" || strings.ContainsAny(value, " \"") {
		return strconv.Quote(value)
	}
	return value
}

// describeRun renders a run for a prompt line.
func describeRun(snap snapshot) string {
	id := snap.ID
	if id == "" {
		return "(not started)"
	}
	label := fmt.Sprintf("run=%s", id)
	if snap.Name != "" {
		label += " name=" + logValue(snap.Name)
	}
	return fmt.Sprintf("%s state=%s exit_code=%d duration=%s shell=%s cwd=%s node=%s",
		label, snap.State, snap.ExitCode, snap.duration().Round(time.Millisecond),
		logValue(string(snap.Shell)), logValue(snap.CWD), snap.Node)
}
