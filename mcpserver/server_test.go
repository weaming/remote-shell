package mcpserver

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"remote-shell/agent"
	"remote-shell/identity"
)

func TestToolsRunAndInspectOneCommand(t *testing.T) {
	requireBash(t)
	address, privateKey := startAgent(t)
	session := newSession(t, newBridge(t, address, privateKey))

	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
	}
	for _, expected := range []string{"discover_nodes", "list_shells", "run_command", "task_status", "task_output", "list_tasks", "cancel_task"} {
		if !slices.Contains(names, expected) {
			t.Fatalf("tool %q missing from %v", expected, names)
		}
	}

	shells := callTool(t, session, "list_shells", map[string]any{})
	if data := structured(t, shells); !slices.Contains(toStrings(t, data["shells"]), "bash") {
		t.Fatalf("list_shells did not report bash: %s", resultText(shells))
	}

	cwd := t.TempDir()
	run := callTool(t, session, "run_command", map[string]any{
		"shell":  "bash",
		"script": "printf out; printf err >&2; exit 3",
		"cwd":    cwd,
	})
	if run.IsError {
		t.Fatalf("a non-zero exit code must not be a tool error: %s", resultText(run))
	}
	text := resultText(run)
	if !strings.Contains(text, "out") || !strings.Contains(text, "err") {
		t.Fatalf("interleaved output missing from %q", text)
	}
	runData := structured(t, run)
	if exitCode := int(runData["exit_code"].(float64)); exitCode != 3 {
		t.Fatalf("exit_code=%d, want 3", exitCode)
	}
	taskID, _ := runData["task_id"].(string)
	if taskID == "" {
		t.Fatal("run_command did not return a task ID")
	}

	stdout := callTool(t, session, "task_output", map[string]any{"task_id": taskID, "stream": "stdout"})
	if got := strings.TrimSpace(resultText(stdout)); got != "out" {
		t.Fatalf("stdout view = %q, want %q", got, "out")
	}
	stderr := callTool(t, session, "task_output", map[string]any{"task_id": taskID, "stream": "stderr"})
	if got := strings.TrimSpace(resultText(stderr)); got != "err" {
		t.Fatalf("stderr view = %q, want %q", got, "err")
	}

	status := structured(t, callTool(t, session, "task_status", map[string]any{"task_id": taskID}))
	if status["done"] != true || int(status["exit_code"].(float64)) != 3 {
		t.Fatalf("unexpected task status: %v", status)
	}
	listed := structured(t, callTool(t, session, "list_tasks", map[string]any{}))
	if tasks, ok := listed["tasks"].([]any); !ok || len(tasks) != 1 {
		t.Fatalf("list_tasks = %v, want one task", listed["tasks"])
	}
}

func TestBackgroundTaskReportsOutputAndCancellation(t *testing.T) {
	requireBash(t)
	address, privateKey := startAgent(t)
	session := newSession(t, newBridge(t, address, privateKey))

	started := structured(t, callTool(t, session, "run_command", map[string]any{
		"shell":      "bash",
		"script":     "printf start; sleep 1; printf done",
		"cwd":        t.TempDir(),
		"background": true,
	}))
	taskID, _ := started["task_id"].(string)
	if taskID == "" {
		t.Fatal("background run did not return a task ID")
	}
	waitForState(t, session, taskID, stateSucceeded, 20*time.Second)
	output := callTool(t, session, "task_output", map[string]any{"task_id": taskID, "stream": "stdout"})
	if got := resultText(output); got != "startdone" {
		t.Fatalf("background stdout = %q, want %q", got, "startdone")
	}

	running := structured(t, callTool(t, session, "run_command", map[string]any{
		"shell":      "bash",
		"script":     "sleep 30",
		"cwd":        t.TempDir(),
		"background": true,
	}))
	cancelID, _ := running["task_id"].(string)
	cancelTool := callTool(t, session, "cancel_task", map[string]any{"task_id": cancelID})
	if cancelTool.IsError {
		t.Fatalf("cancel_task failed: %s", resultText(cancelTool))
	}
	waitForState(t, session, cancelID, stateCancelled, 25*time.Second)
}

func TestInvalidInputIsReportedAsToolError(t *testing.T) {
	bridge, err := New(Config{DefaultNode: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	session := newSession(t, bridge)
	result := callTool(t, session, "run_command", map[string]any{
		"shell":  "tcsh",
		"script": "true",
		"cwd":    t.TempDir(),
	})
	if !result.IsError {
		t.Fatalf("unsupported shell must be a tool error: %s", resultText(result))
	}
	unknown := callTool(t, session, "task_output", map[string]any{"task_id": "t-missing"})
	if !unknown.IsError {
		t.Fatalf("unknown task must be a tool error: %s", resultText(unknown))
	}
}

func TestHTTPTransportServesTools(t *testing.T) {
	requireBash(t)
	address, privateKey := startAgent(t)
	bridge := newBridge(t, address, privateKey)

	httpServer := httptest.NewServer(bridge.HTTPHandler(""))
	defer httpServer.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "http-test", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: httpServer.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result := callTool(t, session, "list_shells", map[string]any{})
	if result.IsError {
		t.Fatalf("list_shells over HTTP failed: %s", resultText(result))
	}
}

// A hand-written client often skips the initialize handshake and sends the
// current protocol revision, which requires the routing headers instead.
func TestHTTPServesOnlyTheSupportedRevisions(t *testing.T) {
	bridge, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(bridge.HTTPHandler(""))
	defer httpServer.Close()

	cases := []struct {
		version    string
		wantStatus int
	}{
		{version: "2026-07-28", wantStatus: http.StatusOK},
		{version: "2025-11-25", wantStatus: http.StatusOK},
		{version: "2025-06-18", wantStatus: http.StatusBadRequest},
		{version: "2024-11-05", wantStatus: http.StatusBadRequest},
	}
	for _, testCase := range cases {
		t.Run(testCase.version, func(t *testing.T) {
			// The current revision carries its routing metadata per request;
			// earlier ones are plain JSON-RPC.
			params := `{}`
			if testCase.version >= "2026-07-28" {
				params = `{"_meta":{` +
					`"io.modelcontextprotocol/protocolVersion":"` + testCase.version + `",` +
					`"io.modelcontextprotocol/clientInfo":{"name":"curl","version":"1"},` +
					`"io.modelcontextprotocol/clientCapabilities":{}}}`
			}
			payload := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":` + params + `}`
			request, err := http.NewRequest(http.MethodPost, httpServer.URL+"/mcp", strings.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Accept", "application/json, text/event-stream")
			request.Header.Set("MCP-Protocol-Version", testCase.version)
			request.Header.Set("Mcp-Method", "tools/list")
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != testCase.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.StatusCode, testCase.wantStatus, body)
			}
			if testCase.wantStatus != http.StatusOK {
				if !strings.Contains(string(body), "2025-11-25") {
					t.Fatalf("rejection does not list the supported versions: %s", body)
				}
				return
			}
			if !strings.Contains(string(body), "run_command") {
				t.Fatalf("tools missing from response: %s", body)
			}
			if session := response.Header.Get("Mcp-Session-Id"); session != "" {
				t.Fatalf("stateless response issued a session ID %q", session)
			}
		})
	}
}

func TestHTTPBearerTokenIsRequired(t *testing.T) {
	bridge, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(bridge.HTTPHandler("secret"))
	defer httpServer.Close()

	response, err := http.Post(httpServer.URL+"/mcp", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.StatusCode)
	}
}

func TestIsLoopbackAddress(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8765":  true,
		"localhost:8765":  true,
		"[::1]:8765":      true,
		":8765":           false,
		"0.0.0.0:8765":    false,
		"192.168.1.10:80": false,
	}
	for address, want := range cases {
		if got := isLoopbackAddress(address); got != want {
			t.Errorf("isLoopbackAddress(%q) = %t, want %t", address, got, want)
		}
	}
}

func TestPreferAddressesRanksDialableFirst(t *testing.T) {
	got := preferAddresses([]string{
		"[fe80::1]:42424",
		"172.18.0.0:42424",
		"[fd7a:115c:a1e0::6e01:533b]:42424",
		"192.168.0.3:42424",
		"127.0.0.1:42424",
	})
	want := []string{"192.168.0.3:42424", "127.0.0.1:42424", "[fd7a:115c:a1e0::6e01:533b]:42424", "[fe80::1]:42424"}
	if !slices.Equal(got, want) {
		t.Fatalf("preferAddresses = %v, want %v", got, want)
	}
}

func TestDialCandidatesFallsBackPastDeadAddress(t *testing.T) {
	requireBash(t)
	address, privateKey := startAgent(t)
	bridge := newBridge(t, address, privateKey)
	connection, used, err := bridge.dialCandidates(context.Background(), []string{"127.0.0.1:1", address})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if used != address {
		t.Fatalf("dialed %q, want %q", used, address)
	}
}

func newBridge(t *testing.T, address string, privateKey ed25519.PrivateKey) *Server {
	t.Helper()
	bridge, err := New(Config{ClientKey: privateKey, DefaultNode: address})
	if err != nil {
		t.Fatal(err)
	}
	return bridge
}

func newSession(t *testing.T, bridge *Server) *mcp.ClientSession {
	t.Helper()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	if _, err := bridge.NewMCPServer().Connect(context.Background(), serverTransport, nil); err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "in-memory-test", Version: "1"}, nil)
	session, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func callTool(t *testing.T, session *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return result
}

func waitForState(t *testing.T, session *mcp.ClientSession, taskID string, want taskState, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for {
		status := structured(t, callTool(t, session, "task_status", map[string]any{"task_id": taskID}))
		if status["state"] == string(want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("task %s stayed at %v, want %s", taskID, status["state"], want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func resultText(result *mcp.CallToolResult) string {
	parts := make([]string, 0, len(result.Content))
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			parts = append(parts, text.Text)
		}
	}
	return strings.Join(parts, "\n")
}

func structured(t *testing.T, result *mcp.CallToolResult) map[string]any {
	t.Helper()
	if decoded, ok := result.StructuredContent.(map[string]any); ok {
		return decoded
	}
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) == 0 {
		t.Fatalf("tool returned no structured content: %s", resultText(result))
	}
	return decoded
}

func toStrings(t *testing.T, value any) []string {
	t.Helper()
	items, ok := value.([]any)
	if !ok {
		t.Fatalf("expected a list, got %T", value)
	}
	values := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("expected a string element, got %T", item)
		}
		values = append(values, text)
	}
	return values
}

func requireBash(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
}

func startAgent(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := identity.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := packetConn.LocalAddr().(*net.UDPAddr).Port
	packetConn.Close()
	instance, err := agent.New(agent.Config{
		ListenAddress:    fmt.Sprintf("127.0.0.1:%d", port),
		StateDir:         t.TempDir(),
		TrustedClientKey: publicKey,
		DisableDiscovery: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("agent serve: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("agent did not stop after cancellation")
		}
	})
	return fmt.Sprintf("127.0.0.1:%d", port), privateKey
}
