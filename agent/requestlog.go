package agent

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"remote-shell/execution"
)

// requestLog carries the identity of one inbound request so its start line and
// its result line share an ID that a log reader can match on.
type requestLog struct {
	id      uint64
	started time.Time
	kind    string
	runID   string
	remote  string
	stdout  int64
	stderr  int64
	exit    int
}

func newRequestLog(id uint64) *requestLog {
	return &requestLog{id: id, started: time.Now()}
}

// countOutput accumulates what was forwarded to the client, so the result line
// shows how much data the request produced.
func (r *requestLog) countOutput(stream execution.Stream, size int) {
	if stream == execution.StreamStderr {
		r.stderr += int64(size)
		return
	}
	r.stdout += int64(size)
}

// start logs that a request is being served, with the details a reader needs to
// identify it.
func (r *requestLog) start(kind, runID string, fields ...string) {
	r.kind = kind
	r.runID = runID
	parts := append([]string{
		fmt.Sprintf("req=%d", r.id),
		"event=start",
		"kind=" + kind,
	}, fields...)
	if r.remote != "" {
		parts = append(parts, "remote="+r.remote)
	}
	if runID != "" {
		parts = append(parts, "run="+runID)
	}
	log.Print(strings.Join(parts, " "))
}

// setExit records the exit code reported for a run.
func (r *requestLog) setExit(code int) {
	r.exit = code
}

// finish logs the outcome with the request ID and the time it took.
func (r *requestLog) finish(state, detail string) {
	parts := []string{
		fmt.Sprintf("req=%d", r.id),
		"event=done",
		"kind=" + orUnknown(r.kind),
		"state=" + state,
		"duration=" + time.Since(r.started).Round(time.Millisecond).String(),
	}
	if r.runID != "" {
		parts = append(parts, "run="+r.runID)
	}
	if r.kind == "shell" {
		parts = append(parts, fmt.Sprintf("exit=%d", r.exit))
	}
	if r.stdout > 0 || r.stderr > 0 {
		parts = append(parts, fmt.Sprintf("stdout=%d", r.stdout), fmt.Sprintf("stderr=%d", r.stderr))
	}
	if detail != "" {
		parts = append(parts, "detail="+strconv.Quote(detail))
	}
	log.Print(strings.Join(parts, " "))
}

// describeCommand lists what the request asked for, without quoting the script.
func describeCommand(clientID string, command execution.Command) []string {
	fields := make([]string, 0, 5)
	if clientID != "" {
		fields = append(fields, "client="+clientID)
	}
	fields = append(fields,
		"shell="+string(command.Shell),
		"cwd="+command.CWD,
		"timeout="+command.Timeout.String(),
	)
	return fields
}

func orUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

// summarizeResult folds a run outcome into one state for the log.
func summarizeResult(result execution.Result) (state string, exitCode int, detail string) {
	switch {
	case result.Cancelled:
		return "cancelled", result.ExitCode, result.Error
	case result.TimedOut:
		return "timed_out", result.ExitCode, result.Error
	case result.Error != "":
		return "failed", result.ExitCode, result.Error
	case result.ExitCode == 0:
		return "succeeded", 0, ""
	default:
		return "failed", result.ExitCode, ""
	}
}
