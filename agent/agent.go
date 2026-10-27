package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/grandcat/zeroconf"
	"github.com/quic-go/quic-go"
	"remote-shell/execution"
	"remote-shell/identity"
	"remote-shell/protocol"
)

const (
	DefaultListenAddress = ":42424"
	DefaultMaxTasks      = 64
	DefaultMaxStreams    = 128
	MaxConfiguredTasks   = 1024
	MaxConfiguredStreams = 4096
	streamHeaderTimeout  = 5 * time.Second
	initialIdleTimeout   = 10 * time.Second
	idleStreamTimeout    = 200 * time.Millisecond
	idleWatchPeriod      = 25 * time.Millisecond
	taskSlotWait         = 100 * time.Millisecond
	streamSlotWaitPeriod = 50 * time.Millisecond
)

var EmbeddedTrustedClientPublicKeyHex string

type Config struct {
	ListenAddress        string
	StateDir             string
	TrustedClientKey     ed25519.PublicKey
	AllowUnauthenticated bool
	DisableDiscovery     bool
	MaxConcurrentTasks   int
	MaxConcurrentStreams int
}

type Agent struct {
	config   Config
	identity identity.ServerIdentity
	tls      *tls.Config
	tasks    chan struct{}
	streams  chan struct{}
}

func New(config Config) (*Agent, error) {
	if config.ListenAddress == "" {
		config.ListenAddress = DefaultListenAddress
	}
	if config.MaxConcurrentTasks < 0 {
		return nil, fmt.Errorf("max concurrent tasks cannot be negative")
	}
	if config.MaxConcurrentStreams < 0 {
		return nil, fmt.Errorf("max concurrent streams cannot be negative")
	}
	if config.MaxConcurrentTasks == 0 {
		config.MaxConcurrentTasks = DefaultMaxTasks
	}
	if config.MaxConcurrentStreams == 0 {
		config.MaxConcurrentStreams = DefaultMaxStreams
	}
	if config.MaxConcurrentTasks > MaxConfiguredTasks {
		return nil, fmt.Errorf("max concurrent tasks cannot exceed %d", MaxConfiguredTasks)
	}
	if config.MaxConcurrentStreams > MaxConfiguredStreams {
		return nil, fmt.Errorf("max concurrent streams cannot exceed %d", MaxConfiguredStreams)
	}
	config.TrustedClientKey = append(ed25519.PublicKey(nil), config.TrustedClientKey...)
	if len(config.TrustedClientKey) != 0 && config.AllowUnauthenticated {
		return nil, fmt.Errorf("cannot enable unauthenticated mode while a client key is configured")
	}
	if len(config.TrustedClientKey) == 0 && !config.AllowUnauthenticated {
		return nil, fmt.Errorf("client authentication is not configured; set a trusted client key or explicitly allow unauthenticated clients")
	}
	serverIdentity, err := identity.LoadOrCreateServer(config.StateDir)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := identity.ServerTLSConfig(serverIdentity, config.TrustedClientKey)
	if err != nil {
		return nil, err
	}
	return &Agent{
		config:   config,
		identity: serverIdentity,
		tls:      tlsConfig,
		tasks:    make(chan struct{}, config.MaxConcurrentTasks),
		streams:  make(chan struct{}, config.MaxConcurrentStreams),
	}, nil
}

func (a *Agent) ID() string {
	return a.identity.ID
}

func (a *Agent) Serve(ctx context.Context) error {
	listener, err := quic.ListenAddr(a.config.ListenAddress, a.tls, &quic.Config{
		MaxIdleTimeout:        45 * time.Second,
		KeepAlivePeriod:       15 * time.Second,
		HandshakeIdleTimeout:  initialIdleTimeout,
		MaxIncomingStreams:    int64(a.config.MaxConcurrentStreams),
		MaxIncomingUniStreams: -1,
	})
	if err != nil {
		return fmt.Errorf("listen for QUIC: %w", err)
	}
	defer listener.Close()
	log.Printf("listening on %s", listener.Addr())

	advertisement, err := a.advertise(listener.Addr())
	if err != nil {
		// Discovery is a convenience; a container or a host without multicast
		// support must still be able to serve explicit connections.
		log.Printf("mDNS advertisement disabled: %v", err)
	}
	if advertisement != nil {
		defer advertisement.Shutdown()
	}

	var connections sync.Map
	var handlers sync.WaitGroup
	shutdown := make(chan struct{})
	defer func() {
		close(shutdown)
		connections.Range(func(_, value any) bool {
			connection := value.(*quic.Conn)
			_ = connection.CloseWithError(0, "agent shutting down")
			return true
		})
		handlers.Wait()
	}()
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-shutdown:
		}
	}()

	for {
		connection, acceptErr := listener.Accept(ctx)
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept QUIC connection: %w", acceptErr)
		}
		connections.Store(connection, connection)
		handlers.Add(1)
		go func(connection *quic.Conn) {
			defer handlers.Done()
			defer connections.Delete(connection)
			a.handleConnection(ctx, connection)
		}(connection)
	}
}

func (a *Agent) advertise(address net.Addr) (*zeroconf.Server, error) {
	if a.config.DisableDiscovery {
		return nil, nil
	}
	udpAddress, ok := address.(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("unexpected QUIC listen address %T", address)
	}
	instance := "RemoteShell-" + strings.TrimPrefix(a.identity.ID, "node-")
	text := []string{
		"id=" + a.identity.ID,
		"proto=" + protocol.Version,
		"auth=" + strconv.FormatBool(len(a.config.TrustedClientKey) != 0),
	}
	server, err := zeroconf.Register(instance, protocol.ServiceType, "local.", udpAddress.Port, text, nil)
	if err != nil {
		return nil, fmt.Errorf("register mDNS service: %w", err)
	}
	return server, nil
}

func (a *Agent) handleConnection(serverCtx context.Context, connection *quic.Conn) {
	defer connection.CloseWithError(0, "connection finished")
	connectionCtx, cancel := context.WithCancel(serverCtx)
	defer cancel()

	var activeStreams atomic.Int64
	var everActive atomic.Bool
	idleSince := time.Now()
	var idleMu sync.Mutex
	touchIdle := func() {
		idleMu.Lock()
		idleSince = time.Now()
		idleMu.Unlock()
	}
	onStreamStart := func() {
		activeStreams.Add(1)
		touchIdle()
	}
	onStreamEnd := func() {
		everActive.Store(true)
		if activeStreams.Add(-1) == 0 {
			touchIdle()
		}
	}
	isIdle := func() (bool, time.Duration, time.Duration) {
		if activeStreams.Load() != 0 {
			return false, 0, 0
		}
		idleMu.Lock()
		defer idleMu.Unlock()
		timeout := initialIdleTimeout
		if everActive.Load() {
			timeout = idleStreamTimeout
		}
		return true, time.Since(idleSince), timeout
	}
	stopIdleWatch := make(chan struct{})
	var idleWatch sync.WaitGroup
	idleWatch.Add(1)
	go func() {
		defer idleWatch.Done()
		ticker := time.NewTicker(idleWatchPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-stopIdleWatch:
				return
			case <-connectionCtx.Done():
				return
			case <-ticker.C:
				if idle, elapsed, timeout := isIdle(); idle && elapsed > timeout {
					_ = connection.CloseWithError(0, "no active task stream")
					return
				}
			}
		}
	}()
	defer func() {
		close(stopIdleWatch)
		idleWatch.Wait()
	}()

	go func() {
		select {
		case <-connection.Context().Done():
			cancel()
		case <-connectionCtx.Done():
		}
	}()

	var streams sync.WaitGroup
	defer func() {
		// Only reached once AcceptStream fails, i.e. the peer finished its last
		// task stream or the connection broke. Cancel first so in-flight
		// commands stop before we wait on them. If a graceful "keep the
		// connection open for more tasks" path is ever added, it must not go
		// through this defer.
		cancel()
		streams.Wait()
	}()
	for {
		stream, err := connection.AcceptStream(connectionCtx)
		if err != nil {
			return
		}
		streams.Add(1)
		go func() {
			defer streams.Done()
			a.beginStream(connectionCtx, connection, stream, onStreamStart, onStreamEnd)
		}()
	}
}

// beginStream reads the first frame off the connection loop and only then
// claims global stream capacity, so idle or reset streams cannot block other
// connections or starve the agent.
func (a *Agent) beginStream(connectionCtx context.Context, connection *quic.Conn, stream *quic.Stream, onStart, onEnd func()) {
	defer stream.Close()
	defer stream.CancelRead(0)

	_ = stream.SetReadDeadline(time.Now().Add(streamHeaderTimeout))
	// Mark the stream busy before reading, so the idle watcher cannot close the
	// connection while a request frame is in flight.
	onStart()
	defer onEnd()

	frame, err := protocol.ReadFrame(stream)
	if err != nil {
		a.writeError(stream, fmt.Errorf("read request: %w", err))
		return
	}
	_ = stream.SetReadDeadline(time.Time{})

	if !a.acquireStreamSlot(connectionCtx) {
		if connectionCtx.Err() != nil {
			return
		}
		a.writeError(stream, fmt.Errorf("agent is at its concurrent stream limit"))
		return
	}
	// The slot is released by the same function that acquired it.
	defer func() { <-a.streams }()

	a.handleStream(connectionCtx, connection, stream, frame)
}

// acquireStreamSlot takes a global stream slot, waiting briefly for one to be
// released so a burst is queued instead of rejected.
func (a *Agent) acquireStreamSlot(ctx context.Context) bool {
	select {
	case a.streams <- struct{}{}:
		return true
	default:
	}
	wait := time.NewTimer(streamSlotWaitPeriod)
	defer wait.Stop()
	select {
	case a.streams <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	case <-wait.C:
		return false
	}
}

func (a *Agent) handleStream(connectionCtx context.Context, connection *quic.Conn, stream *quic.Stream, frame protocol.Frame) {
	clientID, err := a.authenticatedClientID(connection)
	if err != nil {
		a.writeError(stream, err)
		return
	}
	switch frame.Type {
	case protocol.FrameListShells:
		shellList, marshalErr := protocol.MarshalFrame(protocol.FrameShellList, protocol.ShellList{Shells: execution.AvailableShells()})
		if marshalErr == nil {
			_ = protocol.WriteFrame(stream, shellList)
		}
		return
	case protocol.FrameTaskRequest:
	default:
		a.writeError(stream, fmt.Errorf("expected task or shell-list request, got frame type %d", frame.Type))
		return
	}

	var request protocol.TaskRequest
	if err := protocol.UnmarshalPayload(frame, &request); err != nil {
		a.writeError(stream, err)
		return
	}
	if clientID != "" && request.ClientID != clientID {
		a.writeError(stream, fmt.Errorf("client ID does not match the authenticated key"))
		return
	}
	if clientID == "" && request.ClientID != "" {
		a.writeError(stream, fmt.Errorf("client ID supplied without client authentication"))
		return
	}
	task, err := request.Task.ExecutionTask()
	if err != nil {
		a.writeError(stream, err)
		return
	}

	taskWait := time.NewTimer(taskSlotWait)
	defer taskWait.Stop()
	select {
	case a.tasks <- struct{}{}:
		defer func() { <-a.tasks }()
	case <-connectionCtx.Done():
		return
	case <-taskWait.C:
		a.writeError(stream, fmt.Errorf("agent is at its concurrent task limit"))
		return
	}

	taskCtx, cancel := context.WithCancel(connectionCtx)
	defer cancel()
	controlDone := make(chan struct{})
	go func() {
		defer close(controlDone)
		a.readTaskControl(cancel, stream)
	}()
	var writeMu sync.Mutex
	writeFrame := func(frame protocol.Frame) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if err := taskCtx.Err(); err != nil {
			return err
		}
		return protocol.WriteFrame(stream, frame)
	}
	result, runErr := execution.Run(taskCtx, task, func(_ context.Context, output execution.Output) error {
		payload, encodeErr := protocol.EncodeOutput(output)
		if encodeErr != nil {
			return encodeErr
		}
		return writeFrame(protocol.Frame{Type: protocol.FrameOutput, Payload: payload})
	})
	cancel()
	stream.CancelRead(0)
	// Do not wait for the reader when the connection is gone, otherwise a dead
	// peer can hold the stream slot for as long as its TCP/QUIC state survives.
	select {
	case <-controlDone:
	case <-connectionCtx.Done():
	}
	if runErr != nil {
		a.writeError(stream, runErr)
		return
	}
	resultFrame, err := protocol.MarshalFrame(protocol.FrameTaskResult, result)
	if err != nil {
		a.writeError(stream, err)
		return
	}
	writeMu.Lock()
	_ = protocol.WriteFrame(stream, resultFrame)
	writeMu.Unlock()
}

func (a *Agent) authenticatedClientID(connection *quic.Conn) (string, error) {
	if len(a.config.TrustedClientKey) == 0 {
		return "", nil
	}
	state := connection.ConnectionState().TLS
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("client certificate is required")
	}
	publicKey, ok := state.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("client certificate must use Ed25519")
	}
	if subtle.ConstantTimeCompare(publicKey, a.config.TrustedClientKey) != 1 {
		return "", fmt.Errorf("client public key is not trusted")
	}
	return identity.ClientID(publicKey), nil
}

func (a *Agent) readTaskControl(cancel context.CancelFunc, stream *quic.Stream) {
	// A task stream carries exactly one control frame: the client either
	// cancels or closes its write side, both of which end the task.
	if _, err := protocol.ReadFrame(stream); err != nil {
		cancel()
		return
	}
	cancel()
}

func (a *Agent) writeError(stream *quic.Stream, cause error) {
	frame, err := protocol.MarshalFrame(protocol.FrameError, protocol.ErrorMessage{Message: cause.Error()})
	if err == nil {
		_ = protocol.WriteFrame(stream, frame)
	}
}

func ParseClientPublicKey(encoded string) (ed25519.PublicKey, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, nil
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode trusted client public key: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("trusted client public key must be %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(decoded), nil
}
