package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"remote-shell/execution"
	"remote-shell/identity"
	"remote-shell/protocol"
)

func TestAgentStreamsAuthenticatedRun(t *testing.T) {
	if !containsShell(execution.AvailableShells(), execution.ShellBash) {
		t.Skip("bash is not installed")
	}
	publicKey, privateKey, err := identity.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	port, err := freeUDPPort()
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		ListenAddress:    fmt.Sprintf("127.0.0.1:%d", port),
		Name:             "test-agent",
		StateBaseDir:     t.TempDir(),
		TrustedClientKey: publicKey,
		DisableDiscovery: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(ctx) }()
	defer func() {
		cancel()
		select {
		case err := <-serveResult:
			if err != nil {
				t.Errorf("agent serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("agent did not stop after cancellation")
		}
	}()

	clientTLS, err := identity.ClientTLSConfig(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := dialAgent(t, fmt.Sprintf("127.0.0.1:%d", port), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseWithError(0, "test complete")
	stream, err := connection.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	request, err := protocol.MarshalFrame(protocol.FrameShellRequest, protocol.CommandSpec{
		Shell:     execution.ShellBash,
		Script:    "printf hello; printf problem >&2",
		CWD:       t.TempDir(),
		TimeoutMS: 5000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(stream, request); err != nil {
		t.Fatal(err)
	}
	if err := stream.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr string
responseLoop:
	for {
		frame, readErr := protocol.ReadFrame(stream)
		if readErr != nil {
			t.Fatalf("read run response: %v", readErr)
		}
		switch frame.Type {
		case protocol.FrameShellStarted:
			continue
		case protocol.FrameOutput:
			chunk, decodeErr := protocol.DecodeOutput(frame.Payload)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			if chunk.Stream == execution.StreamStdout {
				stdout += string(chunk.Data)
			} else {
				stderr += string(chunk.Data)
			}
		case protocol.FrameShellResult:
			var result execution.Result
			if err := protocol.UnmarshalPayload(frame, &result); err != nil {
				t.Fatal(err)
			}
			if result.RunID == "" || result.ExitCode != 0 {
				t.Fatalf("unexpected run result: %+v", result)
			}
			if stdout != "hello" || stderr != "problem" {
				t.Fatalf("stdout=%q stderr=%q", stdout, stderr)
			}
			break responseLoop
		case protocol.FrameError:
			var message protocol.ErrorMessage
			_ = protocol.UnmarshalPayload(frame, &message)
			t.Fatalf("agent error: %s", message.Message)
		default:
			t.Fatalf("unexpected frame type %d", frame.Type)
		}
	}
	_ = stream.Close()
	select {
	case <-connection.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("agent kept an idle connection open after run completion")
	}

	listConnection, err := dialAgent(t, fmt.Sprintf("127.0.0.1:%d", port), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer listConnection.CloseWithError(0, "test complete")
	listStream, err := listConnection.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(listStream, protocol.Frame{Type: protocol.FrameListShells}); err != nil {
		t.Fatal(err)
	}
	if err := listStream.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	listFrame, err := protocol.ReadFrame(listStream)
	if err != nil {
		t.Fatal(err)
	}
	var shellList protocol.ShellList
	if listFrame.Type != protocol.FrameShellList || protocol.UnmarshalPayload(listFrame, &shellList) != nil {
		t.Fatalf("unexpected shell list frame: %#v", listFrame)
	}
	if !containsShell(shellList.Shells, execution.ShellBash) {
		t.Fatalf("bash not reported as available: %#v", shellList.Shells)
	}
	_ = listStream.Close()

	wrongPublicKey, wrongPrivateKey, err := identity.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	wrongTLS, err := identity.ClientTLSConfig(wrongPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if wrongConnection, dialErr := dialAgent(t, fmt.Sprintf("127.0.0.1:%d", port), wrongTLS); dialErr == nil {
		wrongStream, streamErr := wrongConnection.OpenStreamSync(context.Background())
		if streamErr != nil {
			t.Fatal(streamErr)
		}
		badRequest, encodeErr := protocol.MarshalFrame(protocol.FrameShellRequest, protocol.CommandSpec{
			Shell: execution.ShellBash, Script: "exit 0", CWD: t.TempDir(),
		})
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		if writeErr := protocol.WriteFrame(wrongStream, badRequest); writeErr == nil {
			if readErr := wrongStream.SetReadDeadline(time.Now().Add(5 * time.Second)); readErr != nil {
				t.Fatal(readErr)
			}
			response, readErr := protocol.ReadFrame(wrongStream)
			if readErr == nil && response.Type != protocol.FrameError {
				t.Fatalf("untrusted client received frame type %d, want error", response.Type)
			}
		}
		_ = wrongConnection.CloseWithError(0, "untrusted client test")
	}
	if identity.ClientID(wrongPublicKey) == identity.ClientID(publicKey) {
		t.Fatal("generated client IDs should be unique")
	}

	cancelConnection, err := dialAgent(t, fmt.Sprintf("127.0.0.1:%d", port), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelConnection.CloseWithError(0, "cancel test complete")
	cancelStream, err := cancelConnection.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cancelRequest, err := protocol.MarshalFrame(protocol.FrameShellRequest, protocol.CommandSpec{
		Shell: execution.ShellBash, Script: "sleep 30", CWD: t.TempDir(), TimeoutMS: 30000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(cancelStream, cancelRequest); err != nil {
		t.Fatal(err)
	}
	if err := cancelStream.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := cancelStream.Close(); err != nil {
		t.Fatal(err)
	}
	var cancelled execution.Result
	for {
		frame, err := protocol.ReadFrame(cancelStream)
		if err != nil {
			t.Fatal(err)
		}
		if frame.Type == protocol.FrameShellStarted {
			continue
		}
		if frame.Type == protocol.FrameShellResult {
			if err := protocol.UnmarshalPayload(frame, &cancelled); err != nil {
				t.Fatal(err)
			}
			break
		}
		if frame.Type == protocol.FrameError {
			t.Fatalf("cancel run failed: %s", frame.Payload)
		}
	}
	if !cancelled.Cancelled {
		t.Fatalf("cancel was not reported: %+v", cancelled)
	}
}

func TestAgentAllowsExplicitUnauthenticatedMode(t *testing.T) {
	if !containsShell(execution.AvailableShells(), execution.ShellBash) {
		t.Skip("bash is not installed")
	}
	port, err := freeUDPPort()
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		ListenAddress:        fmt.Sprintf("127.0.0.1:%d", port),
		Name:                 "test-agent",
		StateBaseDir:         t.TempDir(),
		AllowUnauthenticated: true,
		DisableDiscovery:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(ctx) }()
	defer func() {
		cancel()
		select {
		case err := <-serveResult:
			if err != nil {
				t.Errorf("agent serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("agent did not stop after cancellation")
		}
	}()
	clientTLS, err := identity.ClientTLSConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := dialAgent(t, fmt.Sprintf("127.0.0.1:%d", port), clientTLS)
	if err != nil {
		t.Fatalf("unauthenticated connection failed: %v", err)
	}
	stream, err := connection.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	request, err := protocol.MarshalFrame(protocol.FrameShellRequest, protocol.CommandSpec{
		Shell: execution.ShellBash, Script: "exit 0", CWD: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(stream, request); err != nil {
		t.Fatal(err)
	}
	if err := stream.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// The agent announces the run first, then reports the result.
	startedFrame, err := protocol.ReadFrame(stream)
	if err != nil {
		t.Fatal(err)
	}
	if startedFrame.Type != protocol.FrameShellStarted {
		t.Fatalf("frame type = %d, want the run announcement", startedFrame.Type)
	}
	frame, err := protocol.ReadFrame(stream)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != protocol.FrameShellResult {
		t.Fatalf("frame type = %d, want the run result", frame.Type)
	}
	_ = connection.CloseWithError(0, "test complete")
}

// The agent name doubles as the state directory, so two names keep two
// identities apart and a restart reuses the same one.
func TestStateDirectoryIsNamedByAgent(t *testing.T) {
	base := t.TempDir()
	first, err := New(Config{Name: "box-a", StateBaseDir: base, AllowUnauthenticated: true, DisableDiscovery: true})
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(base, "box-a", "identity.key")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("state key %s: %v", keyPath, err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key permissions = %o, want 600", info.Mode().Perm())
	}
	second, err := New(Config{Name: "box-b", StateBaseDir: base, AllowUnauthenticated: true, DisableDiscovery: true})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID() == second.ID() {
		t.Fatalf("two names share the identity %s", first.ID())
	}
	reopened, err := New(Config{Name: "box-a", StateBaseDir: base, AllowUnauthenticated: true, DisableDiscovery: true})
	if err != nil {
		t.Fatal(err)
	}
	if reopened.ID() != first.ID() {
		t.Fatalf("restart changed the identity: %s -> %s", first.ID(), reopened.ID())
	}
	if _, err := New(Config{AllowUnauthenticated: true, DisableDiscovery: true, StateBaseDir: base}); err == nil {
		t.Fatal("an agent without a name must be refused")
	}
}

func TestNormalizeAgentName(t *testing.T) {
	if got, err := normalizeName("  Build Box  "); err != nil || got != "Build Box" {
		t.Fatalf("normalizeName = %q, %v; want the trimmed name", got, err)
	}
	for _, invalid := range []string{"", "   ", ".", "..", "a/b", `a\b`} {
		if _, err := normalizeName(invalid); err == nil {
			t.Errorf("normalizeName(%q) accepted an unusable name", invalid)
		}
	}
	cases := map[string]string{
		"Build Box":     "build-box",
		"mini_garden":   "mini_garden",
		"  a//b  ":      "a-b",
		"中文名字":          "",
		"already-fine-": "already-fine",
	}
	for input, expected := range cases {
		if got := sanitizeName(input); got != expected {
			t.Errorf("sanitizeName(%q) = %q, want %q", input, got, expected)
		}
	}
}

func TestAgentRequiresTrustedClientKey(t *testing.T) {
	if _, err := New(Config{DisableDiscovery: true}); err == nil {
		t.Fatal("expected authentication configuration error")
	}
	if _, err := New(Config{DisableDiscovery: true, AllowUnauthenticated: true, TrustedClientKey: make([]byte, 32)}); err == nil {
		t.Fatal("expected conflicting authentication configuration error")
	}
	if _, err := New(Config{DisableDiscovery: true, AllowUnauthenticated: true, MaxConcurrentRuns: MaxConfiguredRuns + 1}); err == nil {
		t.Fatal("expected oversized run concurrency to be rejected")
	}
}

func TestAgentRejectsIdleConnectionWithoutStream(t *testing.T) {
	if !containsShell(execution.AvailableShells(), execution.ShellBash) {
		t.Skip("bash is not installed")
	}
	publicKey, privateKey, err := identity.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	port, err := freeUDPPort()
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		ListenAddress:    fmt.Sprintf("127.0.0.1:%d", port),
		Name:             "test-agent",
		StateBaseDir:     t.TempDir(),
		TrustedClientKey: publicKey,
		DisableDiscovery: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(ctx) }()
	defer func() {
		cancel()
		select {
		case err := <-serveResult:
			if err != nil {
				t.Errorf("agent serve: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("agent did not stop after cancellation")
		}
	}()
	clientTLS, err := identity.ClientTLSConfig(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := dialAgent(t, fmt.Sprintf("127.0.0.1:%d", port), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	select {
	case <-connection.Context().Done():
	case <-time.After(initialIdleTimeout + 3*time.Second):
		t.Fatal("agent kept a connection without any stream open")
	}
	if elapsed := time.Since(started); elapsed < initialIdleTimeout {
		t.Fatalf("connection closed after %s, before the idle timeout", elapsed)
	}
}

func TestAgentResetsStreamWithTruncatedFirstFrame(t *testing.T) {
	if !containsShell(execution.AvailableShells(), execution.ShellBash) {
		t.Skip("bash is not installed")
	}
	publicKey, privateKey, err := identity.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	port, err := freeUDPPort()
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		ListenAddress:    fmt.Sprintf("127.0.0.1:%d", port),
		Name:             "test-agent",
		StateBaseDir:     t.TempDir(),
		TrustedClientKey: publicKey,
		DisableDiscovery: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(ctx) }()
	defer func() {
		cancel()
		select {
		case <-serveResult:
		case <-time.After(15 * time.Second):
			t.Error("agent did not stop after cancellation")
		}
	}()
	clientTLS, err := identity.ClientTLSConfig(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := dialAgent(t, fmt.Sprintf("127.0.0.1:%d", port), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseWithError(0, "test complete")
	stream, err := connection.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// A partial frame header makes the stream visible to the agent without ever
	// completing a request frame.
	if _, err := stream.Write([]byte{byte(protocol.FrameShellRequest), 0}); err != nil {
		t.Fatal(err)
	}
	if err := stream.SetReadDeadline(time.Now().Add(streamHeaderTimeout + 5*time.Second)); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	frame, err := protocol.ReadFrame(stream)
	if err != nil {
		t.Fatalf("expected an error frame after the first-frame timeout: %v", err)
	}
	if frame.Type != protocol.FrameError {
		t.Fatalf("frame type = %d, want an error frame", frame.Type)
	}
	if elapsed := time.Since(started); elapsed > streamHeaderTimeout+3*time.Second {
		t.Fatalf("agent took %s to reject a truncated request stream", elapsed)
	}
}

func TestAgentAcceptsQueuedRequestAfterStreamSlotFrees(t *testing.T) {
	if !containsShell(execution.AvailableShells(), execution.ShellBash) {
		t.Skip("bash is not installed")
	}
	publicKey, privateKey, err := identity.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	port, err := freeUDPPort()
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		ListenAddress:        fmt.Sprintf("127.0.0.1:%d", port),
		Name:                 "test-agent",
		StateBaseDir:         t.TempDir(),
		TrustedClientKey:     publicKey,
		DisableDiscovery:     true,
		MaxConcurrentStreams: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(ctx) }()
	defer func() {
		cancel()
		select {
		case <-serveResult:
		case <-time.After(15 * time.Second):
			t.Error("agent did not stop after cancellation")
		}
	}()
	clientTLS, err := identity.ClientTLSConfig(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := dialAgent(t, fmt.Sprintf("127.0.0.1:%d", port), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseWithError(0, "test complete")

	blocking, err := openRunStream(t, connection, identity.ClientID(publicKey), "blocking", "sleep 2")
	if err != nil {
		t.Fatal(err)
	}
	defer blocking.CancelRead(0)
	if err := blocking.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	overflow, err := connection.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	request, err := protocol.MarshalFrame(protocol.FrameShellRequest, protocol.CommandSpec{
		Shell: execution.ShellBash, Script: "exit 0", CWD: t.TempDir(), TimeoutMS: 5000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(overflow, request); err != nil {
		t.Fatal(err)
	}
	if err := overflow.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var result execution.Result
	for {
		frame, err := protocol.ReadFrame(overflow)
		if err != nil {
			t.Fatal(err)
		}
		if frame.Type == protocol.FrameShellStarted {
			continue
		}
		if frame.Type == protocol.FrameShellResult {
			if err := protocol.UnmarshalPayload(frame, &result); err != nil {
				t.Fatal(err)
			}
			break
		}
		if frame.Type != protocol.FrameOutput {
			t.Fatalf("frame type = %d, want output or run result", frame.Type)
		}
	}
	if result.RunID == "" || result.ExitCode != 0 {
		t.Fatalf("queued request was not executed: %+v", result)
	}
}

func TestAgentRejectsRequestWhenRunSlotsStayBusy(t *testing.T) {
	if !containsShell(execution.AvailableShells(), execution.ShellBash) {
		t.Skip("bash is not installed")
	}
	publicKey, privateKey, err := identity.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	port, err := freeUDPPort()
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		ListenAddress:        fmt.Sprintf("127.0.0.1:%d", port),
		Name:                 "test-agent",
		StateBaseDir:         t.TempDir(),
		TrustedClientKey:     publicKey,
		DisableDiscovery:     true,
		MaxConcurrentRuns:    1,
		MaxConcurrentStreams: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(ctx) }()
	defer func() {
		cancel()
		select {
		case <-serveResult:
		case <-time.After(15 * time.Second):
			t.Error("agent did not stop after cancellation")
		}
	}()
	clientTLS, err := identity.ClientTLSConfig(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := dialAgent(t, fmt.Sprintf("127.0.0.1:%d", port), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseWithError(0, "test complete")

	blocking, err := openRunStream(t, connection, identity.ClientID(publicKey), "blocking", "sleep 10")
	if err != nil {
		t.Fatal(err)
	}
	defer blocking.CancelRead(0)
	time.Sleep(200 * time.Millisecond)

	overflow, err := openRunStream(t, connection, identity.ClientID(publicKey), "overflow", "exit 0")
	if err != nil {
		t.Fatal(err)
	}
	if err := overflow.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	frame, err := protocol.ReadFrame(overflow)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != protocol.FrameError {
		t.Fatalf("frame type = %d, want an error frame when run slots stay busy", frame.Type)
	}
}

func TestAgentRejectsStreamFromSecondConnectionWhenSaturated(t *testing.T) {
	if !containsShell(execution.AvailableShells(), execution.ShellBash) {
		t.Skip("bash is not installed")
	}
	publicKey, privateKey, err := identity.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	port, err := freeUDPPort()
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		ListenAddress:        fmt.Sprintf("127.0.0.1:%d", port),
		Name:                 "test-agent",
		StateBaseDir:         t.TempDir(),
		TrustedClientKey:     publicKey,
		DisableDiscovery:     true,
		MaxConcurrentStreams: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(ctx) }()
	defer func() {
		cancel()
		select {
		case <-serveResult:
		case <-time.After(15 * time.Second):
			t.Error("agent did not stop after cancellation")
		}
	}()
	clientTLS, err := identity.ClientTLSConfig(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	address := fmt.Sprintf("127.0.0.1:%d", port)
	clientID := identity.ClientID(publicKey)

	holder, err := dialAgent(t, address, clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.CloseWithError(0, "test complete")
	busy, err := openRunStream(t, holder, clientID, "busy", "sleep 10")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.CancelRead(0)
	time.Sleep(200 * time.Millisecond)

	other, err := dialAgent(t, address, clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer other.CloseWithError(0, "test complete")
	started := time.Now()
	rejected, err := openRunStream(t, other, clientID, "rejected", "exit 0")
	if err != nil {
		t.Fatal(err)
	}
	if err := rejected.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	frame, err := protocol.ReadFrame(rejected)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != protocol.FrameError {
		t.Fatalf("frame type = %d, want an error frame from a saturated agent", frame.Type)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("rejection took %s, expected a short queue wait", elapsed)
	}
}

func TestAgentStillShutsDownAfterAbandonedStream(t *testing.T) {
	if !containsShell(execution.AvailableShells(), execution.ShellBash) {
		t.Skip("bash is not installed")
	}
	publicKey, privateKey, err := identity.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	port, err := freeUDPPort()
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		ListenAddress:        fmt.Sprintf("127.0.0.1:%d", port),
		Name:                 "test-agent",
		StateBaseDir:         t.TempDir(),
		TrustedClientKey:     publicKey,
		DisableDiscovery:     true,
		MaxConcurrentStreams: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(ctx) }()
	clientTLS, err := identity.ClientTLSConfig(privateKey)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	connection, err := dialAgent(t, fmt.Sprintf("127.0.0.1:%d", port), clientTLS)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	stream, err := connection.OpenStreamSync(context.Background())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	// Abandon the stream without ever completing a request frame.
	if _, err := stream.Write([]byte{byte(protocol.FrameShellRequest), 1}); err != nil {
		cancel()
		t.Fatal(err)
	}
	// Wait until the agent actually saw the truncated stream, otherwise the
	// agent may never take the accept path this test is meant to cover.
	if err := stream.SetReadDeadline(time.Now().Add(streamHeaderTimeout + 5*time.Second)); err != nil {
		cancel()
		t.Fatal(err)
	}
	if frame, err := protocol.ReadFrame(stream); err != nil || frame.Type != protocol.FrameError {
		cancel()
		t.Fatalf("agent did not reject the truncated stream: frame=%v err=%v", frame.Type, err)
	}
	stream.CancelRead(0)
	_ = connection.CloseWithError(0, "abandoned")
	cancel()
	select {
	case err := <-serveResult:
		if err != nil {
			t.Fatalf("agent serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not shut down after an abandoned stream")
	}
}

func openRunStream(t *testing.T, connection *quic.Conn, clientID, runID, script string) (*quic.Stream, error) {
	t.Helper()
	stream, err := connection.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}
	request, err := protocol.MarshalFrame(protocol.FrameShellRequest, protocol.CommandSpec{
		Shell: execution.ShellBash, Script: script, CWD: t.TempDir(), TimeoutMS: 5000,
	})
	if err != nil {
		return nil, err
	}
	if err := protocol.WriteFrame(stream, request); err != nil {
		return nil, err
	}
	return stream, nil
}

func freeUDPPort() (int, error) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer packetConn.Close()
	return packetConn.LocalAddr().(*net.UDPAddr).Port, nil
}

func containsShell(shells []execution.Shell, target execution.Shell) bool {
	for _, shell := range shells {
		if shell == target {
			return true
		}
	}
	return false
}

func dialAgent(t *testing.T, address string, tlsConfig *tls.Config) (*quic.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return quic.DialAddr(ctx, address, tlsConfig, &quic.Config{HandshakeIdleTimeout: 2 * time.Second})
}

// The start line and the result line of one request must share a request ID so
// a log reader can match them.
func TestAgentLogsRunStartAndResult(t *testing.T) {
	if !containsShell(execution.AvailableShells(), execution.ShellBash) {
		t.Skip("bash is not installed")
	}
	publicKey, privateKey, err := identity.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	port, err := freeUDPPort()
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		Name:             "log-probe",
		ListenAddress:    fmt.Sprintf("127.0.0.1:%d", port),
		StateBaseDir:     t.TempDir(),
		TrustedClientKey: publicKey,
		DisableDiscovery: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var captured strings.Builder
	previous := log.Writer()
	log.SetOutput(&captured)
	defer log.SetOutput(previous)

	ctx, cancel := context.WithCancel(context.Background())
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(ctx) }()
	defer func() {
		cancel()
		select {
		case err := <-serveResult:
			if err != nil {
				t.Errorf("agent serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("agent did not stop after cancellation")
		}
	}()

	clientTLS, err := identity.ClientTLSConfig(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := dialAgent(t, fmt.Sprintf("127.0.0.1:%d", port), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseWithError(0, "test complete")

	runShell := func(script string) {
		stream, err := connection.OpenStreamSync(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()
		frame, err := protocol.MarshalFrame(protocol.FrameShellRequest, protocol.CommandSpec{
			Shell:  execution.ShellBash,
			Script: script,
			CWD:    t.TempDir(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := protocol.WriteFrame(stream, frame); err != nil {
			t.Fatal(err)
		}
		_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			frame, err := protocol.ReadFrame(stream)
			if err != nil {
				t.Fatalf("read run response: %v", err)
			}
			if frame.Type == protocol.FrameShellResult {
				return
			}
		}
	}
	runShell("printf hello")
	runShell("printf boom >&2; exit 4")

	stream, err := connection.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	shellRequest, err := protocol.MarshalFrame(protocol.FrameListShells, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(stream, shellRequest); err != nil {
		t.Fatal(err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := protocol.ReadFrame(stream); err != nil {
		t.Fatalf("read shell list: %v", err)
	}
	stream.Close()

	runs, instant := parseRequestLogs(captured.String())
	if len(runs) != 2 {
		t.Fatalf("runs=%v, want two shell runs:\n%s", runs, captured.String())
	}
	for runID, lines := range runs {
		if !isRunID(runID) {
			t.Fatalf("run ID %q is not the agent-assigned form:\n%s", runID, captured.String())
		}
		if len(lines) != 2 || lines[0]["event"] != "start" || lines[1]["event"] != "done" {
			t.Fatalf("run %s logged %v, want start then result", runID, lines)
		}
		for _, line := range lines {
			if !strings.HasPrefix(line["_line"], "run="+runID+" ") {
				t.Fatalf("line does not start with its run ID: %q", line["_line"])
			}
		}
	}
	states := map[string]int{}
	for _, lines := range runs {
		states[lines[1]["state"]]++
	}
	if states["succeeded"] != 1 || states["failed"] != 1 {
		t.Fatalf("states = %v, want one succeeded and one failed:\n%s", states, captured.String())
	}
	if len(instant) != 1 {
		t.Fatalf("shell-list logged %d lines, want one:\n%s", len(instant), captured.String())
	}
	if instant[0]["kind"] != "shells" || instant[0]["state"] != "succeeded" || instant[0]["remote"] == "" {
		t.Fatalf("shell-list line is incomplete: %v", instant[0])
	}
	if !strings.Contains(captured.String(), "exit=4") {
		t.Fatalf("failing run did not log its exit code:\n%s", captured.String())
	}
}

// isRunID reports whether value looks like an agent-assigned run ID: 24 lower-case
// hex characters, 96 bits of randomness.
func isRunID(value string) bool {
	if len(value) != 24 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

// parseRequestLogs splits the captured log into shell runs keyed by their run ID
// and the single-line records of instantaneous requests.
func parseRequestLogs(output string) (map[string][]map[string]string, []map[string]string) {
	runs := make(map[string][]map[string]string)
	var instant []map[string]string
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "event=") {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if index := strings.Index(trimmed, "run="); index >= 0 {
			trimmed = trimmed[index:]
		} else if index := strings.Index(trimmed, "event="); index >= 0 {
			trimmed = trimmed[index:]
		}
		fields := map[string]string{"_line": trimmed}
		for _, token := range strings.Fields(line) {
			key, value, ok := strings.Cut(token, "=")
			if ok {
				fields[key] = value
			}
		}
		if fields["run"] != "" {
			runs[fields["run"]] = append(runs[fields["run"]], fields)
			continue
		}
		instant = append(instant, fields)
	}
	return runs, instant
}
