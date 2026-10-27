package agent

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"remote-shell/execution"
)

// requestLog carries what a request needs for its start line and its result
// line. A shell run is identified by the run ID the agent assigned; a shell-list
// request is instantaneous and logs a single line.
type requestLog struct {
	started time.Time
	kind    string
	runID   string
	remote  string
	stdout  int64
	stderr  int64
	exit    int
}

func newRequestLog() *requestLog {
	return &requestLog{started: time.Now()}
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
	// The run ID leads the line so a reader can grep or sort by it directly.
	parts := make([]string, 0, 6+len(fields))
	if runID != "" {
		parts = append(parts, "run="+runID)
	}
	parts = append(parts, "event=start", "kind="+kind)
	parts = append(parts, fields...)
	if r.remote != "" {
		parts = append(parts, "remote="+r.remote)
	}
	log.Print(strings.Join(parts, " "))
}

// setExit records the exit code reported for a run.
func (r *requestLog) setExit(code int) {
	r.exit = code
}

// finish logs the outcome with the run ID and the time it took. Instantaneous
// requests log this line alone, so they carry their remote address here.
func (r *requestLog) finish(state, detail string) {
	parts := make([]string, 0, 8)
	if r.runID != "" {
		parts = append(parts, "run="+r.runID)
	}
	parts = append(parts,
		"event=done",
		"kind="+orUnknown(r.kind),
		"state="+state,
		"duration="+time.Since(r.started).Round(time.Millisecond).String(),
	)
	if r.runID == "" && r.remote != "" {
		parts = append(parts, "remote="+r.remote)
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
func describeCommand(command execution.Command) []string {
	return []string{
		"shell=" + string(command.Shell),
		"cwd=" + command.CWD,
		"timeout=" + command.Timeout.String(),
	}
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
