// Package mcpserver exposes a remote-shell agent to MCP clients.
//
// Each shell call opens one QUIC connection to the agent, runs a single command,
// and records the output in a bounded buffer. Output can be read while the
// command is still running, split by stream, and re-read after completion. The
// run ID comes from the agent, so every later query uses the agent's own name
// for that run.
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
	// DefaultMaxOutputBytes bounds retained output per run.
	DefaultMaxOutputBytes = 8 << 20
	// DefaultForegroundRetention keeps a finished foreground run queryable.
	DefaultForegroundRetention = time.Minute
	// DefaultBackgroundRetention does the same for a background run, which its
	// caller polled for rather than waited on.
	DefaultBackgroundRetention = 10 * time.Minute
	// DefaultRetainedRuns caps how many runs the registry keeps at once.
	DefaultRetainedRuns = 100
	// DefaultDiscoveryWait is the mDNS lookup budget for one call.
	DefaultDiscoveryWait = 1500 * time.Millisecond
	// MaxDiscoveryWait caps the caller-supplied discovery budget.
	MaxDiscoveryWait = 10 * time.Second
	// defaultOutputChunk is the default shell_output response size.
	defaultOutputChunk = 64 << 10
	// maxOutputChunk is the largest single shell_output response.
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
	// ForegroundRetention and BackgroundRetention say how long a finished run
	// stays answerable; zero selects the defaults.
	ForegroundRetention time.Duration
	BackgroundRetention time.Duration
	RetainedRuns        int
	DiscoveryWait       time.Duration
}

// Server serves the MCP tools for one client key.
type Server struct {
	config    Config
	runs      *registry
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
	if config.ForegroundRetention <= 0 {
		config.ForegroundRetention = DefaultForegroundRetention
	}
	if config.BackgroundRetention <= 0 {
		config.BackgroundRetention = DefaultBackgroundRetention
	}
	if config.RetainedRuns <= 0 {
		config.RetainedRuns = DefaultRetainedRuns
	}
	if config.DiscoveryWait <= 0 {
		config.DiscoveryWait = DefaultDiscoveryWait
	}
	return &Server{
		config:    config,
		runs:      newRegistry(config.RetainedRuns),
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
		Name:  "shell",
		Title: "Run a shell command",
		Description: "Run one shell command on an agent. The agent assigns the run ID that every later call uses. " +
			"By default this waits for the command to finish and returns the interleaved stdout and stderr plus the " +
			"exit code; with background=true it returns the run ID as soon as the agent accepts the command. A " +
			"non-zero exit code is a normal result, not a tool error.",
	}, s.runShell)
	mcp.AddTool(server, &mcp.Tool{
		Name:  "shell_status",
		Title: "Run status",
		Description: "Report the state, exit code, timing and byte counters of a run started by shell. " +
			"Works for running and finished runs.",
	}, s.shellStatus)
	mcp.AddTool(server, &mcp.Tool{
		Name:  "shell_output",
		Title: "Run output",
		Description: "Read a run's output by page. stream selects the interleaved view (all) or a single stream " +
			"(stdout, stderr); offset and limit page through it in bytes. next_offset tells you where to continue.",
	}, s.shellOutput)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "shell_cancel",
		Title:       "Cancel run",
		Description: "Cancel a running run. Its process group is terminated: SIGTERM, then SIGKILL after the agent's grace period.",
	}, s.shellCancel)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_runs",
		Title:       "List runs",
		Description: "List the runs this bridge still remembers, oldest first, with their current state.",
	}, s.listRuns)
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
		// The transport's DNS-rebinding check rejects a foreign Host on a
		// loopback connection, which breaks every proxy a container uses to
		// reach the host. It protects nothing here: a browser cannot talk to
		// this endpoint anyway, because application/json needs a preflight the
		// handler answers with 405 and any simple content type is refused with
		// 415. The real gate is the optional bearer token.
		DisableLocalhostProtection: true,
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
	Name         string   `json:"name,omitempty"`
	Instance     string   `json:"instance,omitempty"`
	Host         string   `json:"host,omitempty"`
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
	logDiscovered(found)
	views := make([]nodeView, 0, len(found))
	for _, node := range found {
		addresses := preferAddresses(node.Addresses)
		views = append(views, nodeView{
			ID:           node.ID,
			Name:         node.Name,
			Instance:     node.Instance,
			Host:         node.SystemHost,
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
		lines = append(lines, describeNodeView(view))
	}
	text := "nodes=0 message=" + strconv.Quote("no agent announced itself; pass an explicit host:port as node. "+
		"In a container mDNS often cannot reach the LAN: use host.docker.internal:<port> or host networking.")
	if len(lines) > 0 {
		text = strings.Join(lines, "\n")
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}},
		discoverNodesOutput{Nodes: views, WaitedMS: wait.Milliseconds()}, nil
}

// describeNodeView renders one discovered agent as a key=value line. The
// address list shows what a peer on this link can reach and is capped so a
// prompt is not flooded; `more` carries the rest, and the structured reply keeps
// every address.
func describeNodeView(view nodeView) string {
	shown := primaryAddresses(view.Addresses)
	if len(shown) == 0 {
		shown = view.Addresses
	}
	if len(shown) > maxShownAddresses {
		shown = shown[:maxShownAddresses]
	}
	line := "node=" + view.ID
	if view.Name != "" {
		line += " name=" + logValue(view.Name)
	}
	if view.Host != "" {
		line += " host=" + view.Host
	}
	line += fmt.Sprintf(" auth=%t addrs=%s", view.AuthRequired, strings.Join(shown, ","))
	if len(view.Addresses) > len(shown) {
		line += fmt.Sprintf(" more=%d", len(view.Addresses)-len(shown))
	}
	return line
}

type nodeInput struct {
	Node string `json:"node,omitempty" jsonschema:"agent address host:port, its --name, its host name, or a node ID; when omitted the bridge uses --node, otherwise the only agent it discovered on the local network"`
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
	text := fmt.Sprintf("node=%s shells=%s", address, strings.Join(names, ","))
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}},
		listShellsOutput{Node: address, Shells: names}, nil
}

type shellInput struct {
	Node        string            `json:"node,omitempty" jsonschema:"agent address host:port, its --name, its host name, or a node ID; when omitted the bridge uses --node, otherwise the only agent it discovered on the local network"`
	Shell       string            `json:"shell" jsonschema:"shell that runs the script: bash, fish or zsh; use list_shells to see what the agent has"`
	Script      string            `json:"script" jsonschema:"script text passed to the shell with -c"`
	CWD         string            `json:"cwd" jsonschema:"working directory on the agent host: an absolute path, or ~ / ~/sub to use the agent user's home"`
	Env         map[string]string `json:"env,omitempty" jsonschema:"extra environment variables for the command"`
	EnableProxy bool              `json:"enable_proxy,omitempty" jsonschema:"set HTTP_PROXY and HTTPS_PROXY from the agent's configured HTTP proxy; rejected if the agent has no proxy configured"`
	Stdin       string            `json:"stdin,omitempty" jsonschema:"text written to the command's stdin"`
	Timeout     int64             `json:"timeout,omitempty" jsonschema:"command timeout in seconds; 0 uses the agent default of 300 seconds, maximum 3600 seconds"`
	Background  bool              `json:"background,omitempty" jsonschema:"return the run ID as soon as the agent accepts the command instead of waiting for it to finish"`
}

type shellRunOutput struct {
	RunID        string `json:"run_id"`
	Name         string `json:"name,omitempty"`
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

func (s *Server) runShell(ctx context.Context, _ *mcp.CallToolRequest, input shellInput) (*mcp.CallToolResult, shellRunOutput, error) {
	shell := execution.Shell(strings.TrimSpace(input.Shell))
	if !slices.Contains([]execution.Shell{execution.ShellBash, execution.ShellFish, execution.ShellZsh}, shell) {
		return nil, shellRunOutput{}, fmt.Errorf("shell must be one of bash, fish, zsh")
	}
	if strings.TrimSpace(input.Script) == "" {
		return nil, shellRunOutput{}, fmt.Errorf("script is required")
	}
	cwd := strings.TrimSpace(input.CWD)
	if cwd == "" {
		return nil, shellRunOutput{}, fmt.Errorf("cwd is required")
	}
	// "~" and "~/…" are expanded by the agent, against its own user's home.
	if !filepath.IsAbs(cwd) && cwd != "~" && !strings.HasPrefix(cwd, "~/") {
		return nil, shellRunOutput{}, fmt.Errorf("cwd must be an absolute path or start with ~")
	}
	timeout := time.Duration(input.Timeout) * time.Second
	if input.Timeout < 0 || timeout > execution.MaxTimeout {
		return nil, shellRunOutput{}, fmt.Errorf("timeout must be between 0 and %d seconds", int64(execution.MaxTimeout/time.Second))
	}
	target, err := s.resolveNode(ctx, input.Node)
	if err != nil {
		return nil, shellRunOutput{}, err
	}
	command := execution.Command{
		Shell:       shell,
		Script:      input.Script,
		CWD:         cwd,
		Env:         input.Env,
		EnableProxy: input.EnableProxy,
		Stdin:       []byte(input.Stdin),
		Timeout:     timeout,
	}
	// A foreground run follows the requesting call, so an MCP cancellation
	// stops the command. A background run outlives the call on purpose.
	parent := ctx
	if input.Background {
		parent = context.WithoutCancel(ctx)
	}
	runCtx, cancel := context.WithCancel(parent)
	defer func() {
		if input.Background {
			// The run keeps using this context after the call returns.
			return
		}
	}()
	record := newRun(runCtx, cancel, input.Node, target, command, input.Background, s.config)
	s.startRun(runCtx, record, command)
	select {
	case <-record.ready:
	case <-record.done:
		return s.renderRun(record)
	case <-ctx.Done():
		cancel()
		return nil, shellRunOutput{}, ctx.Err()
	}
	if input.Background {
		text := fmt.Sprintf("started %s on %s in the background; poll with shell_status and shell_output",
			record.ID(), target.describe())
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}},
			shellRunOutput{RunID: record.ID(), Name: record.snapshot().Name, Node: target.describe(), State: string(stateRunning), Background: true}, nil
	}
	select {
	case <-record.done:
		cancel()
	case <-ctx.Done():
		cancel()
		return nil, shellRunOutput{}, ctx.Err()
	}
	return s.renderRun(record)
}

// startRun dials, hands the command to the agent, and drains the result. The run
// is registered as soon as the agent assigns its ID.
func (s *Server) startRun(ctx context.Context, record *run, command execution.Command) {
	go func() {
		defer close(record.done)
		connection, target, err := s.dialTarget(ctx, record.selector)
		if err != nil {
			record.fail(err)
			return
		}
		defer connection.Close()
		handle, err := connection.StartShell(ctx, command, func(output execution.Output) error {
			record.buf.Append(output.Stream, output.Data)
			return nil
		})
		if err != nil {
			record.fail(err)
			return
		}
		record.setHandle(handle, target.describe())
		s.runs.add(record)
		record.markReady()
		// Wait out the agent's final result even after a cancel: the run is
		// already stopped, and the read side has its own drain deadline.
		result, waitErr := handle.Wait(context.WithoutCancel(ctx))
		record.complete(result, waitErr)
	}()
}

// renderRun formats a finished or failed run for a shell reply.
func (s *Server) renderRun(record *run) (*mcp.CallToolResult, shellRunOutput, error) {
	snap := record.snapshot()
	data, start, _, _ := record.buf.read("", 0, 0)
	text := string(data)
	if start > 0 {
		text = fmt.Sprintf("[dropped %d earlier bytes; read the retained tail with shell_output]\n", start) + text
	}
	if strings.TrimSpace(text) == "" {
		text = "(no output)"
	}
	meta := describeRun(snap)
	if snap.ErrText != "" {
		meta += " error=" + snap.ErrText
	}
	// One text block keeps the run ID visible to every client, including
	// hand-written ones that only print the first block.
	result := &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text + "\n\n" + meta}},
		IsError: snap.ErrText != "" || snap.State == stateCancelled || snap.State == stateTimedOut,
	}
	return result, shellRunOutput{
		RunID:        snap.ID,
		Name:         snap.Name,
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

type runIDInput struct {
	RunID string `json:"run_id" jsonschema:"run ID assigned by the agent, returned by shell"`
}

type shellStatusOutput struct {
	RunID        string `json:"run_id"`
	Name         string `json:"name,omitempty"`
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

func statusOf(snap snapshot) shellStatusOutput {
	return shellStatusOutput{
		RunID:        snap.ID,
		Name:         snap.Name,
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
	}
}

func (s *Server) shellStatus(_ context.Context, _ *mcp.CallToolRequest, input runIDInput) (*mcp.CallToolResult, shellStatusOutput, error) {
	record, ok := s.runs.get(input.RunID)
	if !ok {
		return nil, shellStatusOutput{}, fmt.Errorf("unknown run %q", input.RunID)
	}
	snap := record.snapshot()
	text := describeRun(snap) + fmt.Sprintf(" done=%t stdout=%d stderr=%d trimmed=%d",
		snap.Done, snap.StdoutBytes, snap.StderrBytes, snap.TrimmedBytes)
	if snap.ErrText != "" {
		text += " error=" + snap.ErrText
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, statusOf(snap), nil
}

type shellOutputInput struct {
	RunID  string `json:"run_id" jsonschema:"run ID assigned by the agent, returned by shell"`
	Stream string `json:"stream,omitempty" jsonschema:"which view to read: all (interleaved, default), stdout or stderr"`
	Offset int64  `json:"offset,omitempty" jsonschema:"byte offset to start from, as returned in next_offset"`
	Limit  int64  `json:"limit,omitempty" jsonschema:"maximum bytes to return, default 65536, maximum 1048576"`
}

type shellOutputResult struct {
	RunID      string `json:"run_id"`
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

func (s *Server) shellOutput(_ context.Context, _ *mcp.CallToolRequest, input shellOutputInput) (*mcp.CallToolResult, shellOutputResult, error) {
	record, ok := s.runs.get(input.RunID)
	if !ok {
		return nil, shellOutputResult{}, fmt.Errorf("unknown run %q", input.RunID)
	}
	view, err := parseStream(input.Stream)
	if err != nil {
		return nil, shellOutputResult{}, err
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
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, shellOutputResult{
		RunID:      snap.ID,
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

type listRunsOutput struct {
	Runs []shellStatusOutput `json:"runs"`
}

func (s *Server) listRuns(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, listRunsOutput, error) {
	snapshots := s.runs.list()
	entries := make([]shellStatusOutput, 0, len(snapshots))
	lines := make([]string, 0, len(snapshots))
	for _, snap := range snapshots {
		entries = append(entries, statusOf(snap))
		lines = append(lines, describeRun(snap))
	}
	text := "no runs yet"
	if len(lines) > 0 {
		text = strings.Join(lines, "\n")
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, listRunsOutput{Runs: entries}, nil
}

type shellCancelOutput struct {
	RunID string `json:"run_id"`
	State string `json:"state"`
	Note  string `json:"note"`
}

func (s *Server) shellCancel(_ context.Context, _ *mcp.CallToolRequest, input runIDInput) (*mcp.CallToolResult, shellCancelOutput, error) {
	record, ok := s.runs.get(input.RunID)
	if !ok {
		return nil, shellCancelOutput{}, fmt.Errorf("unknown run %q", input.RunID)
	}
	snap := record.snapshot()
	note := "run already finished"
	if !snap.Done {
		record.cancelRun()
		note = "cancellation requested; the agent terminates the process group and reports the final state"
	}
	text := fmt.Sprintf("run=%s state=%s note=%s", snap.ID, snap.State, strconv.Quote(note))
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}},
		shellCancelOutput{RunID: snap.ID, State: string(snap.State), Note: note}, nil
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
	addresses := preferAddresses(s.discovery.preferred(node))
	// A local agent is reachable over loopback: no interface needs to be up and
	// no incoming-connection prompt fires for 127.0.0.1.
	if isLocalHost(node) {
		addresses = append(loopbackCandidates(node), addresses...)
	}
	return dialTarget{
		nodeID:     node.ID,
		discovered: true,
		addresses:  addresses,
	}
}

func matchNode(nodes []cachedNode, selector string) (cachedNode, bool) {
	selector = strings.TrimSuffix(selector, ".")
	for _, node := range nodes {
		switch {
		case node.ID == selector:
			return node, true
		case node.Name != "" && strings.EqualFold(node.Name, selector):
			return node, true
		case strings.EqualFold(strings.TrimSuffix(node.Hostname, "."), selector):
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

// defaultRouteIP returns the local address the kernel would use to leave this
// host. A UDP dial resolves a route without sending a packet.
func defaultRouteIP() net.IP {
	conn, err := net.Dial("udp4", "1.1.1.1:53")
	if err != nil {
		return nil
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP
	}
	return nil
}

// localSubnets lists the networks of the interface that carries target.
func localSubnets(target net.IP) []*net.IPNet {
	if target == nil {
		return nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		carries := false
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.Equal(target) {
				carries = true
				break
			}
		}
		if !carries {
			continue
		}
		subnets := make([]*net.IPNet, 0, len(addrs))
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				subnets = append(subnets, ipNet)
			}
		}
		return subnets
	}
	return nil
}

// inSubnets reports whether ip falls inside one of the networks.
func inSubnets(ip net.IP, subnets []*net.IPNet) bool {
	for _, subnet := range subnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

// onDefaultLink reports whether a peer on the link this host leaves by can
// reach the address without extra routing.
func onDefaultLink(ip, local net.IP, subnets []*net.IPNet) bool {
	return ip.IsLoopback() || (local != nil && ip.Equal(local)) || inSubnets(ip, subnets)
}

// primaryAddresses keeps the addresses a peer on the default-route link can
// reach, so a reply lists what is useful instead of every address the host owns.
func primaryAddresses(addresses []string) []string {
	local := defaultRouteIP()
	subnets := localSubnets(local)
	kept := make([]string, 0, len(addresses))
	for _, address := range addresses {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			continue
		}
		ip := net.ParseIP(host)
		// Link-local IPv6 needs a zone this bridge cannot carry, so it only
		// clutters the summary; the structured reply still lists it.
		if ip != nil && !ip.IsLinkLocalUnicast() && onDefaultLink(ip, local, subnets) {
			kept = append(kept, address)
		}
	}
	return kept
}

// preferAddresses ranks dial candidates: IPv4 first, then routable IPv6, then
// link-local IPv6, which needs a scope this bridge cannot supply. IPv4 network
// addresses (last octet 0) are dropped because nothing listens on them.
func preferAddresses(addresses []string) []string {
	local := defaultRouteIP()
	subnets := localSubnets(local)
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
		rank := 3
		if parsed := net.ParseIP(host); parsed != nil {
			switch {
			case parsed.IsLoopback():
				// Keeps its place next to the other addresses a peer can reach,
				// so the caller's ordering still decides between them.
				rank = 1
			case parsed.To4() != nil:
				if parsed.To4()[3] == 0 {
					continue
				}
				// Addresses on the link this host leaves by are the ones a peer
				// can actually answer, so they win over the rest of the host's
				// addresses (VPN, container bridges, extra NICs).
				if onDefaultLink(parsed, local, subnets) {
					rank = 1
				} else {
					rank = 2
				}
			case parsed.IsLinkLocalUnicast():
				rank = 4
			default:
				if onDefaultLink(parsed, local, subnets) {
					rank = 1
				} else {
					rank = 3
				}
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
