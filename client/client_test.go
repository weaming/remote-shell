package client

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"remote-shell/agent"
	"remote-shell/execution"
	"remote-shell/identity"
)

func TestClientListsShellsAndRunsTask(t *testing.T) {
	address, privateKey := startAgent(t)
	connection := dialClient(t, address, privateKey)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	shells, err := connection.ListShells(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(shells) == 0 {
		t.Skip("no supported shell is installed")
	}
	if !slices.Contains(shells, execution.ShellBash) {
		t.Skip("bash is not installed")
	}

	var stdout, stderr strings.Builder
	result, err := connection.RunTask(ctx, execution.Task{
		ID: "client-task",
		Commands: []execution.Command{{
			ID:     "client-command",
			Shell:  execution.ShellBash,
			Script: "printf hello; printf problem >&2; exit 7",
			CWD:    t.TempDir(),
		}},
	}, func(output execution.Output) error {
		if output.Stream == execution.StreamStdout {
			stdout.Write(output.Data)
		} else {
			stderr.Write(output.Data)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "hello" || stderr.String() != "problem" {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if len(result.Commands) != 1 || result.Commands[0].ExitCode != 7 || result.Commands[0].Err != "" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestClientCancelReportsCancelledCommand(t *testing.T) {
	address, privateKey := startAgent(t)
	connection := dialClient(t, address, privateKey)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()
	result, err := connection.RunTask(ctx, execution.Task{
		ID: "cancel-task",
		Commands: []execution.Command{{
			ID:     "cancel-command",
			Shell:  execution.ShellBash,
			Script: "sleep 30",
			CWD:    t.TempDir(),
		}},
	}, nil)
	if err != nil {
		t.Fatalf("cancel should surface as a task result, got %v", err)
	}
	if len(result.Commands) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if !result.Commands[0].Cancelled {
		t.Fatalf("command was not cancelled: %+v", result.Commands[0])
	}
}

func startAgent(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := identity.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	port := freeUDPPort(t)
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

func freeUDPPort(t *testing.T) int {
	t.Helper()
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	return packetConn.LocalAddr().(*net.UDPAddr).Port
}

func dialClient(t *testing.T, address string, privateKey ed25519.PrivateKey) *Client {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		connection, err := Dial(context.Background(), address, privateKey)
		if err == nil {
			t.Cleanup(func() { _ = connection.Close() })
			return connection
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial agent: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
