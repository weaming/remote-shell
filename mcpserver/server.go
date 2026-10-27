// Package mcpserver exposes a remote-shell agent to MCP clients.
//
// Each run_command call opens one QUIC connection to the agent, runs a single
// command, and records the output in a bounded buffer. Output can be read while
// the command is still running, split by stream, and re-read after completion.
package mcpserver

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"remote-shell/client"
	"remote-shell/execution"
	"remote-shell/protocol"
)

const (
	// DefaultMaxOutputBytes bounds retained output per task.
	DefaultMaxOutputBytes = 8 << 20
	// DefaultTaskRetention is how long a finished task stays queryable.
	DefaultTaskRetention = 30 * time.Minute
	// DefaultRetainedTasks caps how many tasks the registry keeps.
	DefaultRetainedTasks = 64
	// DefaultDiscoveryWait is the mDNS lookup budget for one call.
	DefaultDiscoveryWait = 1500 * time.Millisecond
	// MaxDiscoveryWait caps the caller-supplied discovery budget.
	MaxDiscoveryWait = 10 * time.Second
	// defaultOutputChunk is the default task_output response size.
	defaultOutputChunk = 64 << 10
	// maxOutputChunk is the largest single task_output response.
	maxOutputChunk = 1 << 20
	// dialBudget bounds the total time spent trying candidate addresses.
	dialBudget = 8 * time.Second
	// dialAttempt bounds a single candidate.
	dialAttempt = 3 * time.Second
	// reportedDialFailures caps how many failures an error message lists.
	reportedDialFailures = 3
	// maxShownAddresses caps the addresses listed in a discover_nodes reply.
	maxShownAddresses = 4
)

// supportedProtocolVersions is this bridge's support policy: the current
// revision and the previous one. Older revisions are refused instead of being
// served with semantics this bridge never exercises.
var supportedProtocolVersions = []string{"2026-07-28", "2025-11-25"}

// protocolVersionsToServe narrows the policy to what the SDK actually
// implements, so an SDK upgrade that drops a version degrades to a warning
// instead of a panic inside mcp.NewServer.
func protocolVersionsToServe() []string {
	available := mcp.SupportedProtocolVersions()
	served := make([]string, 0, len(supportedProtocolVersions))
	for _, version := range supportedProtocolVersions {
		if slices.Contains(available, version) {
			served = append(served, version)
			continue
		}
		log.Printf("protocol version %s is not implemented by the MCP SDK; not offered", version)
	}
	return served
}

// Config configures the MCP bridge. ClientKey authenticates the bridge to the
// agent and must match the key the agent trusts.
type Config struct {
	ClientKey      ed25519.PrivateKey
	DefaultNode    string
	MaxOutputBytes int64
	TaskRetention  time.Duration
	RetainedTasks  int
	DiscoveryWait  time.Duration
}

// Server serves the MCP tools for one client key.
type Server struct {
	config    Config
	tasks     *registry
	discovery *nodeCache
	// browse overrides the mDNS lookup, which tests replace to keep discovery
	// deterministic.
	browse func(context.Context) ([]cachedNode, error)
}

func New(config Config) (*Server, error) {
	if len(config.ClientKey) != 0 && len(config.ClientKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("client private key must be %d bytes", ed25519.PrivateKeySize)
	}
	config.ClientKey = append(ed25519.PrivateKey(nil), config.ClientKey...)
	config.DefaultNode = strings.TrimSpace(config.DefaultNode)
	if config.MaxOutputBytes < 0 {
		return nil, fmt.Errorf("max output bytes cannot be negative")
	}
	if config.MaxOutputBytes == 0 {
		config.MaxOutputBytes = DefaultMaxOutputBytes
	}
	if config.TaskRetention == 0 {
		config.TaskRetention = DefaultTaskRetention
	}
	if config.RetainedTasks == 0 {
		config.RetainedTasks = DefaultRetainedTasks
	}
	if config.DiscoveryWait <= 0 {
		config.DiscoveryWait = DefaultDiscoveryWait
	}
	return &Server{
		config:    config,
		tasks:     newRegistry(config.RetainedTasks, config.TaskRetention),
		discovery: newNodeCache(),
	}, nil
}

// NewMCPServer builds the MCP server and registers every tool.
func (s *Server) NewMCPServer() *mcp.Server {
	options := &mcp.ServerOptions{}
	if served := protocolVersionsToServe(); len(served) > 0 {
		options.SupportedProtocolVersions = served
	}
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "remote-shell",
		Title:   "Remote Shell",
		Version: protocol.Version,
	}, options)
	mcp.AddTool(server, &mcp.Tool{
		Name:  "discover_nodes",
		Title: "Discover agents",
		Description: "List remote-shell agents announced on the local network via mDNS. " +
			"Returns each agent's ID, host name and the host:port addresses to pass as `node`.",
	}, s.discoverNodes)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_shells",
		Title:       "List shells",
		Description: "Report which shells (bash, fish, zsh) the target agent can actually run.",
	}, s.listShells)
	mcp.AddTool(server, &mcp.Tool{
		Name:  "run_command",
		Title: "Run command",
		Description: "Run one shell script on a target agent. By default the call returns once the command " +
			"finishes, with the interleaved stdout and stderr plus the exit code. With background=true it " +
			"returns immediately with a task_id; use task_status and task_output to follow it. A non-zero exit " +
			"code is reported as a normal result, not as a tool error.",
	}, s.runCommand)
	mcp.AddTool(server, &mcp.Tool{
		Name:  "task_status",
		Title: "Task status",
		Description: "Report the state, exit code, timing and byte counters of a task started by run_command. " +
			"Works for running and finished tasks.",
	}, s.taskStatus)
	mcp.AddTool(server, &mcp.Tool{
		Name:  "task_output",
		Title: "Task output",
		Description: "Read task output by page. stream selects the interleaved view (all) or a single stream " +
			"(stdout, stderr); offset and limit page through it in bytes. next_offset tells you where to continue.",
	}, s.taskOutput)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_tasks",
		Title:       "List tasks",
		Description: "List the tasks this bridge still remembers, oldest first, with their current state.",
	}, s.listTasks)
	mcp.AddTool(server, &mcp.Tool{
		Name:  "cancel_task",
		Title: "Cancel task",
		Description: "Cancel a running task. Its process group is terminated: SIGTERM, then SIGKILL after the " +
			"agent's grace period.",
	}, s.cancelTask)
	return server
}

// ServeStdio runs the tools over the MCP stdio transport. Logs go to stderr, so
// stdout stays a clean protocol channel.
func (s *Server) ServeStdio(ctx context.Context) error {
	return s.NewMCPServer().Run(ctx, &mcp.StdioTransport{})
}

// ServeHTTP runs the tools over the MCP streamable HTTP transport. A non-empty
// token requires every request to carry it as a bearer token.
func (s *Server) ServeHTTP(ctx context.Context, address, token string) error {
	if token == "" && !isLoopbackAddress(address) {
		log.Printf("WARNING: %s is reachable from the network and no --auth-token is set", address)
	}
	httpServer := &http.Server{
		Addr:              address,
		Handler:           s.HTTPHandler(token),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Dropping the connections is enough: the agent cleans up its side.
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("mcp http shutdown: %v", err)
		}
	}()
	log.Printf("mcp HTTP listening on %s (endpoint /mcp, bearer auth %t)", address, token != "")
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve MCP over HTTP: %w", err)
	}
	return nil
}

// HTTPHandler returns the streamable HTTP handler at /mcp, so a caller can
// mount it on its own server instead of using ServeHTTP.
func (s *Server) HTTPHandler(token string) http.Handler {
	server := s.NewMCPServer()
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return server
	}, &mcp.StreamableHTTPOptions{
		// Stateless: every POST carries a complete request, so a plain curl or
		// a one-shot tool call works without an initialize handshake and
		// without echoing Mcp-Session-Id. It is also what makes the current
		// protocol revision usable: the stateful transport still stops at
		// 2025-11-25.
		Stateless: true,
	})
	mux := http.NewServeMux()
	mux.Handle("/mcp", requireBearer(token, handler))
	return mux
}

// isLoopbackAddress reports whether a listen address keeps the bridge local.
// An empty host or an unspecified address binds every interface.
func isLoopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	parsed := net.ParseIP(host)
	return parsed != nil && parsed.IsLoopback()
}

func requireBearer(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	expected := []byte("Bearer " + token)
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		provided := []byte(request.Header.Get("Authorization"))
		if subtle.ConstantTimeCompare(provided, expected) != 1 {
			response.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(response, request)
	})
}

type discoverNodesInput struct {
	WaitMS int64 `json:"wait_ms,omitempty" jsonschema:"how long to listen for mDNS announcements in milliseconds, default 1500"`
}

type nodeView struct {
	ID           string   `json:"id"`
	Instance     string   `json:"instance,omitempty"`
	Hostname     string   `json:"hostname,omitempty"`
	Addresses    []string `json:"addresses"`
	AuthRequired bool     `json:"auth_required"`
}

type discoverNodesOutput struct {
	Nodes    []nodeView `json:"nodes"`
	WaitedMS int64      `json:"waited_ms"`
}

func (s *Server) discoverNodes(ctx context.Context, _ *mcp.CallToolRequest, input discoverNodesInput) (*mcp.CallToolResult, discoverNodesOutput, error) {
	wait := s.config.DiscoveryWait
	if input.WaitMS > 0 {
		wait = min(time.Duration(input.WaitMS)*time.Millisecond, MaxDiscoveryWait)
	}
	found, err := s.browseNodesFor(ctx, wait)
	if err != nil {
		return nil, discoverNodesOutput{}, err
	}
	s.discovery.set(found)
	views := make([]nodeView, 0, len(found))
	for _, node := range found {
		addresses := preferAddresses(node.Addresses)
		views = append(views, nodeView{
			ID:           node.ID,
			Instance:     node.Instance,
			Hostname:     node.Hostname,
			Addresses:    addresses,
			AuthRequired: node.AuthRequired,
		})
	}
	slices.SortFunc(views, func(left, right nodeView) int { return strings.Compare(left.ID, right.ID) })
	lines := make([]string, 0, len(views))
	for _, view := range views {
		// An agent advertises one address per interface, which is far too noisy
		// for a prompt; the structured reply keeps them all.
		shown := view.Addresses
		suffix := ""
		if len(shown) > maxShownAddresses {
			suffix = fmt.Sprintf(" +%d more", len(shown)-maxShownAddresses)
			shown = shown[:maxShownAddresses]
		}
		lines = append(lines, fmt.Sprintf("%s auth=%t %s %s",
			view.ID, view.AuthRequired, strings.Join(shown, ",")+suffix, view.Hostname))
	}
	text := "no agent announced itself; pass an explicit host:port as node"
	if len(lines) > 0 {
		text = strings.Join(lines, "\n")
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}},
		discoverNodesOutput{Nodes: views, WaitedMS: wait.Milliseconds()}, nil
}

type nodeInput struct {
	Node string `json:"node,omitempty" jsonschema:"agent address host:port, host name, or a node ID; when omitted the bridge uses --node, otherwise the only agent it discovered on the local network"`
}

type listShellsOutput struct {
	Node   string   `json:"node"`
	Shells []string `json:"shells"`
}

func (s *Server) listShells(ctx context.Context, _ *mcp.CallToolRequest, input nodeInput) (*mcp.CallToolResult, listShellsOutput, error) {
	connection, target, err := s.dialTarget(ctx, input.Node)
	if err != nil {
		return nil, listShellsOutput{}, err
	}
	defer connection.Close()
	shells, err := connection.ListShells(ctx)
	if err != nil {
		return nil, listShellsOutput{}, err
	}
	address := target.describe()
	names := make([]string, len(shells))
	for index, shell := range shells {
		names[index] = string(shell)
	}
	text := "no supported shell is installed on " + address
	if len(names) > 0 {
		text = address + ": " + strings.Join(names, ", ")
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}},
		listShellsOutput{Node: address, Shells: names}, nil
}

type runCommandInput struct {
	Node       string            `json:"node,omitempty" jsonschema:"agent address host:port, host name, or a node ID; when omitted the bridge uses --node, otherwise the only agent it discovered on the local network"`
	Shell      string            `json:"shell" jsonschema:"shell that runs the script: bash, fish or zsh; use list_shells to see what the agent has"`
	Script     string            `json:"script" jsonschema:"script text passed to the shell with -c"`
	CWD        string            `json:"cwd" jsonschema:"absolute working directory on the agent host"`
	Env        map[string]string `json:"env,omitempty" jsonschema:"extra environment variables for the command"`
	Stdin      string            `json:"stdin,omitempty" jsonschema:"text written to the command's stdin"`
	TimeoutMS  int64             `json:"timeout_ms,omitempty" jsonschema:"command timeout in milliseconds; 0 uses the agent default of 300000, maximum 3600000"`
	Background bool              `json:"background,omitempty" jsonschema:"return immediately with a task_id instead of waiting for the command to finish"`
}

type runCommandOutput struct {
	TaskID       string `json:"task_id"`
	Node         string `json:"node"`
	State        string `json:"state"`
	ExitCode     int    `json:"exit_code"`
	Error        string `json:"error,omitempty"`
	DurationMS   int64  `json:"duration_ms"`
	StdoutBytes  int64  `json:"stdout_bytes"`
	StderrBytes  int64  `json:"stderr_bytes"`
	TrimmedBytes int64  `json:"trimmed_bytes"`
	Background   bool   `json:"background,omitempty"`
}

func (s *Server) runCommand(ctx context.Context, _ *mcp.CallToolRequest, input runCommandInput) (*mcp.CallToolResult, runCommandOutput, error) {
	shell := execution.Shell(strings.TrimSpace(input.Shell))
	if !slices.Contains([]execution.Shell{execution.ShellBash, execution.ShellFish, execution.ShellZsh}, shell) {
		return nil, runCommandOutput{}, fmt.Errorf("shell must be one of bash, fish, zsh")
	}
	if strings.TrimSpace(input.Script) == "" {
		return nil, runCommandOutput{}, fmt.Errorf("script is required")
	}
	cwd := strings.TrimSpace(input.CWD)
	if cwd == "" {
		return nil, runCommandOutput{}, fmt.Errorf("cwd is required")
	}
	if !filepath.IsAbs(cwd) {
		return nil, runCommandOutput{}, fmt.Errorf("cwd must be an absolute path")
	}
	timeout := time.Duration(input.TimeoutMS) * time.Millisecond
	if input.TimeoutMS < 0 || timeout > execution.MaxTimeout {
		return nil, runCommandOutput{}, fmt.Errorf("timeout_ms must be between 0 and %d", execution.MaxTimeout.Milliseconds())
	}
	target, err := s.resolveNode(ctx, input.Node)
	if err != nil {
		return nil, runCommandOutput{}, err
	}
	taskID, err := newTaskID()
	if err != nil {
		return nil, runCommandOutput{}, err
	}
	command := execution.Command{
		ID:      "c1",
		Shell:   shell,
		Script:  input.Script,
		CWD:     cwd,
		Env:     input.Env,
		Stdin:   []byte(input.Stdin),
		Timeout: timeout,
	}
	// A foreground task follows the requesting call, so an MCP cancellation
	// stops the command. A background task outlives the call on purpose.
	parent := ctx
	if input.Background {
		parent = context.WithoutCancel(ctx)
	}
	taskCtx, cancel := context.WithCancel(parent)
	record := newTask(taskCtx, cancel, taskID, input.Node, target, command, s.config.MaxOutputBytes)
	s.tasks.add(record)
	s.startTask(taskCtx, record, execution.Task{ID: taskID, Mode: execution.ModeParallel, Commands: []execution.Command{command}})
	if input.Background {
		message := fmt.Sprintf("started task %s on %s in the background; poll with task_status and task_output", taskID, target.describe())
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: message}}},
			runCommandOutput{TaskID: taskID, Node: target.describe(), State: string(stateRunning), Background: true}, nil
	}
	select {
	case <-record.done:
	case <-ctx.Done():
		return nil, runCommandOutput{}, ctx.Err()
	}
	return s.renderTask(record)
}

// startTask runs one task on its own connection and closes the record when it
// returns, whether that took a millisecond or an hour.
func (s *Server) startTask(ctx context.Context, record *task, task execution.Task) {
	go func() {
		defer close(record.done)
		// dialTarget resolves again from the cache and re-searches if the
		// cached addresses no longer answer.
		connection, target, err := s.dialTarget(ctx, record.selector)
		if err != nil {
			record.complete(execution.TaskResult{}, err)
			return
		}
		record.setNode(target.describe())
		defer connection.Close()
		result, runErr := connection.RunTask(ctx, task, func(output execution.Output) error {
			record.buf.Append(output.Stream, output.Data)
			return nil
		})
		record.complete(result, runErr)
	}()
}

// renderTask formats a finished task for a run_command reply.
func (s *Server) renderTask(record *task) (*mcp.CallToolResult, runCommandOutput, error) {
	snap := record.snapshot()
	data, start, _, _ := record.buf.read("", 0, 0)
	text := string(data)
	if start > 0 {
		text = fmt.Sprintf("[dropped %d earlier bytes; read the retained tail with task_output]\n", start) + text
	}
	if strings.TrimSpace(text) == "" {
		text = "(no output)"
	}
	meta := fmt.Sprintf("task=%s state=%s exit_code=%d duration=%s node=%s",
		snap.ID, snap.State, snap.ExitCode, snap.duration().Round(time.Millisecond), snap.Node)
	if snap.ErrText != "" {
		meta += " error=" + snap.ErrText
	}
	result := &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: text},
			&mcp.TextContent{Text: meta},
		},
		IsError: snap.ErrText != "" || snap.State == stateCancelled || snap.State == stateTimedOut,
	}
	return result, runCommandOutput{
		TaskID:       snap.ID,
		Node:         snap.Node,
		State:        string(snap.State),
		ExitCode:     snap.ExitCode,
		Error:        snap.ErrText,
		DurationMS:   snap.duration().Milliseconds(),
		StdoutBytes:  snap.StdoutBytes,
		StderrBytes:  snap.StderrBytes,
		TrimmedBytes: snap.TrimmedBytes,
	}, nil
}

type taskIDInput struct {
	TaskID string `json:"task_id" jsonschema:"task ID returned by run_command"`
}

type taskStatusOutput struct {
	TaskID       string `json:"task_id"`
	Node         string `json:"node"`
	Shell        string `json:"shell"`
	Script       string `json:"script"`
	CWD          string `json:"cwd"`
	State        string `json:"state"`
	Done         bool   `json:"done"`
	ExitCode     int    `json:"exit_code"`
	Error        string `json:"error,omitempty"`
	ElapsedMS    int64  `json:"elapsed_ms"`
	StdoutBytes  int64  `json:"stdout_bytes"`
	StderrBytes  int64  `json:"stderr_bytes"`
	TrimmedBytes int64  `json:"trimmed_bytes"`
}

func (s *Server) taskStatus(_ context.Context, _ *mcp.CallToolRequest, input taskIDInput) (*mcp.CallToolResult, taskStatusOutput, error) {
	record, ok := s.tasks.get(input.TaskID)
	if !ok {
		return nil, taskStatusOutput{}, fmt.Errorf("unknown task %q", input.TaskID)
	}
	snap := record.snapshot()
	text := fmt.Sprintf("%s state=%s exit_code=%d done=%t elapsed=%s stdout=%d stderr=%d trimmed=%d",
		snap.ID, snap.State, snap.ExitCode, snap.Done, snap.duration().Round(time.Millisecond),
		snap.StdoutBytes, snap.StderrBytes, snap.TrimmedBytes)
	if snap.ErrText != "" {
		text += " error=" + snap.ErrText
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, taskStatusOutput{
		TaskID:       snap.ID,
		Node:         snap.Node,
		Shell:        string(snap.Shell),
		Script:       snap.Script,
		CWD:          snap.CWD,
		State:        string(snap.State),
		Done:         snap.Done,
		ExitCode:     snap.ExitCode,
		Error:        snap.ErrText,
		ElapsedMS:    snap.duration().Milliseconds(),
		StdoutBytes:  snap.StdoutBytes,
		StderrBytes:  snap.StderrBytes,
		TrimmedBytes: snap.TrimmedBytes,
	}, nil
}

type taskOutputInput struct {
	TaskID string `json:"task_id" jsonschema:"task ID returned by run_command"`
	Stream string `json:"stream,omitempty" jsonschema:"which view to read: all (interleaved, default), stdout or stderr"`
	Offset int64  `json:"offset,omitempty" jsonschema:"byte offset to start from, as returned in next_offset"`
	Limit  int64  `json:"limit,omitempty" jsonschema:"maximum bytes to return, default 65536, maximum 1048576"`
}

type taskOutputOutput struct {
	TaskID     string `json:"task_id"`
	Stream     string `json:"stream"`
	Offset     int64  `json:"offset"`
	NextOffset int64  `json:"next_offset"`
	More       bool   `json:"more"`
	Done       bool   `json:"done"`
	Trimmed    int64  `json:"trimmed_bytes"`
	State      string `json:"state"`
	ExitCode   int    `json:"exit_code"`
	Error      string `json:"error,omitempty"`
}

func (s *Server) taskOutput(_ context.Context, _ *mcp.CallToolRequest, input taskOutputInput) (*mcp.CallToolResult, taskOutputOutput, error) {
	record, ok := s.tasks.get(input.TaskID)
	if !ok {
		return nil, taskOutputOutput{}, fmt.Errorf("unknown task %q", input.TaskID)
	}
	view, err := parseStream(input.Stream)
	if err != nil {
		return nil, taskOutputOutput{}, err
	}
	limit := input.Limit
	if limit <= 0 {
		limit = defaultOutputChunk
	}
	limit = min(limit, maxOutputChunk)
	data, start, next, more := record.buf.read(view, input.Offset, limit)
	snap := record.snapshot()
	text := printable(data)
	if start > input.Offset {
		text = fmt.Sprintf("[bytes %d..%d were dropped from the buffer]\n", input.Offset, start) + text
	}
	if text == "" {
		text = "(no output yet)"
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, taskOutputOutput{
		TaskID:     snap.ID,
		Stream:     viewName(view),
		Offset:     start,
		NextOffset: next,
		More:       more,
		Done:       snap.Done,
		Trimmed:    record.buf.trimmed(view),
		State:      string(snap.State),
		ExitCode:   snap.ExitCode,
		Error:      snap.ErrText,
	}, nil
}

type listTasksOutput struct {
	Tasks []taskStatusOutput `json:"tasks"`
}

func (s *Server) listTasks(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, listTasksOutput, error) {
	snapshots := s.tasks.list()
	entries := make([]taskStatusOutput, 0, len(snapshots))
	lines := make([]string, 0, len(snapshots))
	for _, snap := range snapshots {
		entries = append(entries, taskStatusOutput{
			TaskID:       snap.ID,
			Node:         snap.Node,
			Shell:        string(snap.Shell),
			Script:       snap.Script,
			CWD:          snap.CWD,
			State:        string(snap.State),
			Done:         snap.Done,
			ExitCode:     snap.ExitCode,
			Error:        snap.ErrText,
			ElapsedMS:    snap.duration().Milliseconds(),
			StdoutBytes:  snap.StdoutBytes,
			StderrBytes:  snap.StderrBytes,
			TrimmedBytes: snap.TrimmedBytes,
		})
		lines = append(lines, fmt.Sprintf("%s %s exit=%d %s", snap.ID, snap.State, snap.ExitCode, snap.CWD))
	}
	text := "no tasks yet"
	if len(lines) > 0 {
		text = strings.Join(lines, "\n")
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, listTasksOutput{Tasks: entries}, nil
}

type cancelTaskOutput struct {
	TaskID string `json:"task_id"`
	State  string `json:"state"`
	Note   string `json:"note"`
}

func (s *Server) cancelTask(_ context.Context, _ *mcp.CallToolRequest, input taskIDInput) (*mcp.CallToolResult, cancelTaskOutput, error) {
	record, ok := s.tasks.get(input.TaskID)
	if !ok {
		return nil, cancelTaskOutput{}, fmt.Errorf("unknown task %q", input.TaskID)
	}
	snap := record.snapshot()
	note := "task already finished"
	if !snap.Done {
		record.cancel()
		note = "cancellation requested; the agent terminates the process group and reports the final state"
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: snap.ID + ": " + note}}},
		cancelTaskOutput{TaskID: snap.ID, State: string(snap.State), Note: note}, nil
}

// dialTarget is where a call should connect: the node it resolved to, whether
// that came from discovery, plus candidate addresses in dial order.
type dialTarget struct {
	nodeID     string
	discovered bool
	addresses  []string
}

func (t dialTarget) describe() string {
	if len(t.addresses) == 0 {
		return ""
	}
	return t.addresses[0]
}

// resolveNode turns a caller-supplied selector into a dial target. An empty
// selector uses the bridge default and otherwise the only discovered agent, a
// value with a port is used verbatim, and anything else is matched against
// discovery by node ID or host name. An agent advertises one address per
// interface, so the target carries several candidates ranked for dialing.
func (s *Server) resolveNode(ctx context.Context, selector string) (dialTarget, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		if s.config.DefaultNode != "" {
			return dialTarget{addresses: []string{s.config.DefaultNode}}, nil
		}
		nodes, err := s.knownNodes(ctx)
		if err != nil {
			return dialTarget{}, err
		}
		node, err := chooseNode(nodes)
		if err != nil {
			return dialTarget{}, err
		}
		return s.targetFor(node), nil
	}
	if _, _, err := splitHostPort(selector); err == nil {
		return dialTarget{addresses: []string{selector}}, nil
	}
	// A node ID or host name: use the cached result, searching only if it is
	// absent from what we already know.
	nodes, err := s.knownNodes(ctx)
	if err != nil {
		return dialTarget{}, err
	}
	if node, found := matchNode(nodes, selector); found {
		return s.targetFor(node), nil
	}
	return dialTarget{}, fmt.Errorf("no agent matches %q; pass its address as host:port", selector)
}

// targetFor builds the dial target of a discovered node.
func (s *Server) targetFor(node cachedNode) dialTarget {
	return dialTarget{
		nodeID:     node.ID,
		discovered: true,
		addresses:  preferAddresses(s.discovery.preferred(node)),
	}
}

func matchNode(nodes []cachedNode, selector string) (cachedNode, bool) {
	for _, node := range nodes {
		if node.ID == selector || strings.EqualFold(strings.TrimSuffix(node.Hostname, "."), selector) {
			return node, true
		}
	}
	return cachedNode{}, false
}

// dialTarget connects to a resolved target. A discovered target that no longer
// answers invalidates the cached result and is resolved again from a fresh
// search, once.
func (s *Server) dialTarget(ctx context.Context, selector string) (*client.Client, dialTarget, error) {
	target, err := s.resolveNode(ctx, selector)
	if err != nil {
		return nil, target, err
	}
	connection, address, err := s.dialCandidates(ctx, target.addresses)
	if err == nil {
		s.discovery.remember(target.nodeID, address)
		return connection, target, nil
	}
	if !target.discovered {
		return nil, target, err
	}
	log.Printf("agent %s did not answer (%v); dropping the discovery cache and searching again", target.describe(), err)
	s.discovery.invalidate()
	target, resolveErr := s.resolveNode(ctx, selector)
	if resolveErr != nil {
		return nil, target, err
	}
	connection, address, err = s.dialCandidates(ctx, target.addresses)
	if err != nil {
		return nil, target, err
	}
	s.discovery.remember(target.nodeID, address)
	return connection, target, nil
}

// preferAddresses ranks dial candidates: IPv4 first, then routable IPv6, then
// link-local IPv6, which needs a scope this bridge cannot supply. IPv4 network
// addresses (last octet 0) are dropped because nothing listens on them.
func preferAddresses(addresses []string) []string {
	type ranked struct {
		address string
		rank    int
	}
	items := make([]ranked, 0, len(addresses))
	for _, address := range addresses {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			continue
		}
		rank := 0
		if parsed := net.ParseIP(host); parsed != nil {
			switch {
			case parsed.To4() != nil:
				if parsed.To4()[3] == 0 {
					continue
				}
				rank = 0
			case parsed.IsLinkLocalUnicast():
				rank = 2
			case parsed.IsLoopback():
				rank = 0
			default:
				rank = 1
			}
		}
		items = append(items, ranked{address: address, rank: rank})
	}
	slices.SortStableFunc(items, func(left, right ranked) int { return left.rank - right.rank })
	ordered := make([]string, 0, len(items))
	for _, item := range items {
		ordered = append(ordered, item.address)
	}
	return ordered
}

// dialCandidates connects to the first reachable candidate and reports which
// address answered, so later calls can reuse it.
func (s *Server) dialCandidates(ctx context.Context, addresses []string) (*client.Client, string, error) {
	if len(addresses) == 0 {
		return nil, "", fmt.Errorf("no address to dial")
	}
	budgetCtx, cancel := context.WithTimeout(ctx, dialBudget)
	defer cancel()
	var failures []string
	for _, address := range addresses {
		attemptCtx, attemptCancel := context.WithTimeout(budgetCtx, dialAttempt)
		connection, err := client.Dial(attemptCtx, address, s.config.ClientKey)
		attemptCancel()
		if err == nil {
			return connection, address, nil
		}
		failures = append(failures, fmt.Sprintf("%s (%v)", address, err))
		if budgetCtx.Err() != nil {
			break
		}
	}
	shown := failures
	if len(shown) > reportedDialFailures {
		shown = shown[:reportedDialFailures]
	}
	return nil, "", fmt.Errorf("no candidate address answered: %s", strings.Join(shown, "; "))
}

func splitHostPort(address string) (string, int, error) {
	index := strings.LastIndex(address, ":")
	if index <= 0 || index == len(address)-1 {
		return "", 0, fmt.Errorf("not a host:port address")
	}
	port, err := strconv.Atoi(address[index+1:])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("not a host:port address")
	}
	return address[:index], port, nil
}

func parseStream(value string) (execution.Stream, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "all", "mixed":
		return "", nil
	case string(execution.StreamStdout):
		return execution.StreamStdout, nil
	case string(execution.StreamStderr):
		return execution.StreamStderr, nil
	default:
		return "", fmt.Errorf("stream must be all, stdout or stderr")
	}
}

func viewName(stream execution.Stream) string {
	if stream == "" {
		return "all"
	}
	return string(stream)
}

func printable(data []byte) string {
	if utf8.Valid(data) {
		return string(data)
	}
	return strings.ToValidUTF8(string(data), "\uFFFD")
}

func (s snapshot) duration() time.Duration {
	if s.Finished.IsZero() {
		return time.Since(s.Started)
	}
	return s.Finished.Sub(s.Started)
}
