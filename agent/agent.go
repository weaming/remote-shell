package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
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
	DefaultMaxRuns       = 64
	DefaultMaxStreams    = 128
	MaxConfiguredRuns    = 1024
	MaxConfiguredStreams = 4096
	streamHeaderTimeout  = 5 * time.Second
	initialIdleTimeout   = 10 * time.Second
	idleStreamTimeout    = 200 * time.Millisecond
	idleWatchPeriod      = 25 * time.Millisecond
	runSlotWait          = 100 * time.Millisecond
	streamSlotWaitPeriod = 50 * time.Millisecond
)

var EmbeddedTrustedClientPublicKeyHex string

type Config struct {
	// Name is the human-readable label for this agent, shown by discovery and
	// accepted wherever a node is selected. Empty falls back to the host name.
	Name                 string
	ListenAddress        string
	StateDir             string
	TrustedClientKey     ed25519.PublicKey
	AllowUnauthenticated bool
	DisableDiscovery     bool
	MaxConcurrentRuns    int
	MaxConcurrentStreams int
}

type Agent struct {
	config   Config
	name     string
	identity identity.ServerIdentity
	tls      *tls.Config
	runs     chan struct{}
	streams  chan struct{}
}

func New(config Config) (*Agent, error) {
	if config.ListenAddress == "" {
		config.ListenAddress = DefaultListenAddress
	}
	if config.MaxConcurrentRuns < 0 {
		return nil, fmt.Errorf("max concurrent runs cannot be negative")
	}
	if config.MaxConcurrentStreams < 0 {
		return nil, fmt.Errorf("max concurrent streams cannot be negative")
	}
	if config.MaxConcurrentRuns == 0 {
		config.MaxConcurrentRuns = DefaultMaxRuns
	}
	if config.MaxConcurrentStreams == 0 {
		config.MaxConcurrentStreams = DefaultMaxStreams
	}
	if config.MaxConcurrentRuns > MaxConfiguredRuns {
		return nil, fmt.Errorf("max concurrent runs cannot exceed %d", MaxConfiguredRuns)
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
		name:     resolveName(config.Name),
		identity: serverIdentity,
		tls:      tlsConfig,
		runs:     make(chan struct{}, config.MaxConcurrentRuns),
		streams:  make(chan struct{}, config.MaxConcurrentStreams),
	}, nil
}

func (a *Agent) ID() string {
	return a.identity.ID
}

// Name is the human-readable label advertised for this agent.
func (a *Agent) Name() string {
	return a.name
}

// resolveName picks the label this agent advertises: the configured name, or the
// host name so every agent has something readable to show.
func resolveName(configured string) string {
	if name := strings.TrimSpace(configured); name != "" {
		return name
	}
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	hostname = strings.TrimSuffix(hostname, ".local")
	if index := strings.IndexByte(hostname, '.'); index > 0 {
		hostname = hostname[:index]
	}
	return hostname
}

// sanitizeName keeps an mDNS instance label readable and legal: lower-case
// letters, digits, dash and underscore, collapsed and trimmed.
func sanitizeName(name string) string {
	var builder strings.Builder
	previousDash := false
	for _, char := range strings.ToLower(name) {
		switch {
		case char >= 'a' && char <= 'z', char >= '0' && char <= '9', char == '_':
			builder.WriteRune(char)
			previousDash = false
		default:
			if !previousDash && builder.Len() > 0 {
				builder.WriteByte('-')
				previousDash = true
			}
		}
	}
	return strings.Trim(builder.String(), "-")
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
	// Keep the instance unique even when two agents share a name: the identity
	// suffix is what distinguishes them, the name is what humans read.
	instance := "RemoteShell-" + strings.TrimPrefix(a.identity.ID, "node-")
	if label := sanitizeName(a.name); label != "" {
		instance = "RemoteShell-" + label + "-" + strings.TrimPrefix(a.identity.ID, "node-")
	}
	text := []string{
		"id=" + a.identity.ID,
		"name=" + a.name,
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
					_ = connection.CloseWithError(0, "no active run stream")
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
		// run stream or the connection broke. Cancel first so in-flight
		// commands stop before we wait on them. If a graceful "keep the
		// connection open for more runs" path is ever added, it must not go
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

	request := newRequestLog()
	request.remote = connection.RemoteAddr().String()
	frame, err := protocol.ReadFrame(stream)
	if err != nil {
		cause := fmt.Errorf("read request: %w", err)
		a.writeError(stream, cause)
		request.finish("failed", cause.Error())
		return
	}
	_ = stream.SetReadDeadline(time.Time{})

	if !a.acquireStreamSlot(connectionCtx) {
		if connectionCtx.Err() != nil {
			request.finish("cancelled", "connection closed while waiting for a stream slot")
			return
		}
		a.writeError(stream, fmt.Errorf("agent is at its concurrent stream limit"))
		request.finish("failed", "agent is at its concurrent stream limit")
		return
	}
	// The slot is released by the same function that acquired it.
	defer func() { <-a.streams }()

	a.handleStream(connectionCtx, connection, stream, frame, request)
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

func (a *Agent) handleStream(connectionCtx context.Context, connection *quic.Conn, stream *quic.Stream, frame protocol.Frame, request *requestLog) {
	// The TLS handshake already rejected an untrusted key; re-check here so a
	// future transport change cannot silently drop the requirement.
	if err := a.authenticateClient(connection); err != nil {
		a.writeError(stream, err)
		request.finish("failed", err.Error())
		return
	}
	switch frame.Type {
	case protocol.FrameListShells:
		a.serveShellList(stream, request)
		return
	case protocol.FrameShellRequest:
	default:
		cause := fmt.Errorf("expected shell or shell-list request, got frame type %d", frame.Type)
		a.writeError(stream, cause)
		request.finish("failed", cause.Error())
		return
	}

	// The caller's identity comes from the certificate verified above; nothing
	// about it travels in the request frame.
	var spec protocol.CommandSpec
	if err := protocol.UnmarshalPayload(frame, &spec); err != nil {
		a.writeError(stream, err)
		request.finish("failed", err.Error())
		return
	}
	command, err := spec.ExecutionCommand()
	if err != nil {
		a.writeError(stream, err)
		request.finish("failed", err.Error())
		return
	}
	runID, err := newRunID()
	if err != nil {
		a.writeError(stream, err)
		request.finish("failed", err.Error())
		return
	}
	request.start("shell", runID, describeCommand(command)...)

	runWait := time.NewTimer(runSlotWait)
	defer runWait.Stop()
	select {
	case a.runs <- struct{}{}:
		defer func() { <-a.runs }()
	case <-connectionCtx.Done():
		request.finish("cancelled", "connection closed while waiting for a run slot")
		return
	case <-runWait.C:
		cause := fmt.Errorf("agent is at its concurrent run limit")
		a.writeError(stream, cause)
		request.finish("failed", cause.Error())
		return
	}

	// Announce the run ID before any output, so the client can query or cancel
	// this run while it is still going.
	startedFrame, err := protocol.MarshalFrame(protocol.FrameShellStarted, protocol.ShellStarted{RunID: runID})
	if err == nil {
		err = protocol.WriteFrame(stream, startedFrame)
	}
	if err != nil {
		a.writeError(stream, err)
		request.finish("failed", err.Error())
		return
	}

	runCtx, cancel := context.WithCancel(connectionCtx)
	defer cancel()
	controlDone := make(chan struct{})
	go func() {
		defer close(controlDone)
		a.readRunControl(cancel, stream)
	}()
	var writeMu sync.Mutex
	writeFrame := func(frame protocol.Frame) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if err := runCtx.Err(); err != nil {
			return err
		}
		return protocol.WriteFrame(stream, frame)
	}
	result, runErr := execution.Run(runCtx, runID, command, func(_ context.Context, output execution.Output) error {
		payload, encodeErr := protocol.EncodeOutput(output)
		if encodeErr != nil {
			return encodeErr
		}
		request.countOutput(output.Stream, len(output.Data))
		return writeFrame(protocol.Frame{Type: protocol.FrameOutput, Payload: payload})
	})
	cancel()
	stream.CancelRead(0)
	// Do not wait for the reader when the connection is gone, otherwise a dead
	// peer can hold the run slot for as long as its TCP/QUIC state survives.
	select {
	case <-controlDone:
	case <-connectionCtx.Done():
	}
	if runErr != nil {
		a.writeError(stream, runErr)
		request.finish("failed", runErr.Error())
		return
	}
	resultFrame, err := protocol.MarshalFrame(protocol.FrameShellResult, result)
	if err != nil {
		a.writeError(stream, err)
		request.finish("failed", err.Error())
		return
	}
	writeMu.Lock()
	_ = protocol.WriteFrame(stream, resultFrame)
	writeMu.Unlock()
	state, exitCode, detail := summarizeResult(result)
	request.setExit(exitCode)
	request.finish(state, detail)
}

// newRunID returns the opaque identifier the agent assigns to one run: 96 bits
// of randomness, so an ID is never reused after an agent restarts and cannot
// collide with a run another agent handed out.
func newRunID() (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate run ID: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// serveShellList answers a shell-list request and logs it like any other
// request.
func (a *Agent) serveShellList(stream *quic.Stream, request *requestLog) {
	request.kind = "shells"
	shells := execution.AvailableShells()
	names := make([]string, len(shells))
	for index, shell := range shells {
		names[index] = string(shell)
	}
	frame, err := protocol.MarshalFrame(protocol.FrameShellList, protocol.ShellList{Shells: shells})
	if err == nil {
		err = protocol.WriteFrame(stream, frame)
	}
	if err != nil {
		a.writeError(stream, err)
		request.finish("failed", err.Error())
		return
	}
	request.finish("succeeded", strings.Join(names, ","))
}

// authenticateClient re-checks the peer key. With a single trusted key the
// derived client ID would be a constant, so nothing about the caller is kept or
// logged.
func (a *Agent) authenticateClient(connection *quic.Conn) error {
	if len(a.config.TrustedClientKey) == 0 {
		return nil
	}
	state := connection.ConnectionState().TLS
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("client certificate is required")
	}
	publicKey, ok := state.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("client certificate must use Ed25519")
	}
	if subtle.ConstantTimeCompare(publicKey, a.config.TrustedClientKey) != 1 {
		return fmt.Errorf("client public key is not trusted")
	}
	return nil
}

func (a *Agent) readRunControl(cancel context.CancelFunc, stream *quic.Stream) {
	// A run stream carries exactly one control frame: the client either cancels
	// or closes its write side, both of which end the run.
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
