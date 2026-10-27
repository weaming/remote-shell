package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"remote-shell/agent"
	"remote-shell/identity"
	"remote-shell/mcpserver"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "remote-shell:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printRootUsage()
		return nil
	}
	switch args[0] {
	case "-h", "--help", "-help", "help":
		printRootUsage()
		return nil
	case "serve":
		return runAgent(args[1:])
	case "keygen":
		return runKeygen(args[1:])
	case "pubkey":
		return runPubkey(args[1:])
	case "mcp":
		return runMCP(args[1:])
	default:
		return fmt.Errorf("unknown command %q; expected serve, mcp, keygen or pubkey", args[0])
	}
}

func runAgent(args []string) error {
	config, handled, err := resolveServeConfig(args)
	if err != nil {
		return err
	}
	if handled {
		return nil
	}
	instance, err := agent.New(config)
	if err != nil {
		return err
	}
	if len(config.TrustedClientKey) == 0 {
		log.Print("WARNING: client authentication is disabled")
	}
	log.Printf("agent ID: %s", instance.ID())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return instance.Serve(ctx)
}

// resolveServeConfig parses serve flags into an agent configuration. handled
// reports that the caller should stop (help was printed) without serving.
func resolveServeConfig(args []string) (config agent.Config, handled bool, err error) {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(os.Stdout)
	listenAddress := flags.String("listen", agent.DefaultListenAddress, "QUIC UDP listen address")
	stateDir := flags.String("state-dir", "", "identity state directory (default: OS user config directory)")
	clientKeyHex := flags.String("client-public-key", agent.EmbeddedTrustedClientPublicKeyHex, "trusted client Ed25519 public key in hex")
	allowUnauthenticated := flags.Bool("allow-unauthenticated", false, "allow clients without a trusted client key")
	disableDiscovery := flags.Bool("no-discovery", false, "disable LAN mDNS advertisement")
	maxTasks := flags.Int("max-runs", agent.DefaultMaxRuns, "maximum concurrently executing runs")
	maxStreams := flags.Int("max-streams", agent.DefaultMaxStreams, "maximum concurrently accepted run streams")
	flags.Usage = func() {
		fmt.Fprintln(os.Stdout, "Usage: remote-shell serve [options]")
		flags.PrintDefaults()
	}
	if wantsHelp(args) {
		flags.Usage()
		return agent.Config{}, true, nil
	}
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return agent.Config{}, true, nil
		}
		return agent.Config{}, false, err
	}
	if flags.NArg() != 0 {
		return agent.Config{}, false, fmt.Errorf("unexpected arguments: %v", flags.Args())
	}

	// Only an explicitly supplied non-empty key conflicts with disabling
	// authentication; the embedded key is just a default.
	clientKeySet := false
	flags.Visit(func(current *flag.Flag) {
		if current.Name == "client-public-key" && strings.TrimSpace(current.Value.String()) != "" {
			clientKeySet = true
		}
	})
	if *allowUnauthenticated {
		if clientKeySet {
			return agent.Config{}, false, fmt.Errorf("--client-public-key and --allow-unauthenticated cannot be used together")
		}
		*clientKeyHex = ""
	}
	trustedKey, err := agent.ParseClientPublicKey(*clientKeyHex)
	if err != nil {
		return agent.Config{}, false, err
	}
	return agent.Config{
		ListenAddress:        *listenAddress,
		StateDir:             *stateDir,
		TrustedClientKey:     trustedKey,
		AllowUnauthenticated: *allowUnauthenticated,
		DisableDiscovery:     *disableDiscovery,
		MaxConcurrentRuns:    *maxTasks,
		MaxConcurrentStreams: *maxStreams,
	}, false, nil
}

// runMCP serves the MCP bridge, which turns each tool call into a run on a
// remote agent. Logs and errors go to stderr so stdout stays a clean protocol
// channel for the stdio transport.
func runMCP(args []string) error {
	flags := flag.NewFlagSet("mcp", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	transport := flags.String("transport", "stdio", "MCP transport: stdio or http")
	listen := flags.String("listen", "127.0.0.1:8765", "HTTP listen address (--transport http)")
	authToken := flags.String("auth-token", "", "bearer token required on every HTTP request (--transport http)")
	clientKeyPath := flags.String("client-key", filepath.Join("keys", "client.key"), "client private key; empty connects only to an unauthenticated agent")
	node := flags.String("node", "", "default agent address as host:port")
	maxOutputBytes := flags.Int64("max-output-bytes", mcpserver.DefaultMaxOutputBytes, "retained output bytes per run")
	discoveryWait := flags.Duration("discovery-wait", mcpserver.DefaultDiscoveryWait, "mDNS lookup budget per tool call")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Usage: remote-shell mcp [options]")
		flags.PrintDefaults()
	}
	if wantsHelp(args) {
		flags.Usage()
		return nil
	}
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	explicit := make(map[string]bool, 2)
	flags.Visit(func(current *flag.Flag) { explicit[current.Name] = true })
	mode, err := resolveMCPTransport(*transport, explicit)
	if err != nil {
		return err
	}
	if mode == "http" && !explicit["transport"] {
		log.Print("--listen/--auth-token imply --transport http")
	}

	config := mcpserver.Config{
		DefaultNode:    *node,
		MaxOutputBytes: *maxOutputBytes,
		DiscoveryWait:  *discoveryWait,
	}
	if *clientKeyPath != "" {
		clientKey, err := identity.LoadClientPrivateKey(*clientKeyPath)
		if err != nil {
			return err
		}
		config.ClientKey = clientKey
	} else {
		log.Print("WARNING: no client key configured; the agent must run with --allow-unauthenticated")
	}
	bridge, err := mcpserver.New(config)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if mode == "http" {
		return bridge.ServeHTTP(ctx, *listen, *authToken)
	}
	hint := ""
	if config.DefaultNode == "" {
		hint = "; no default node, pass node per call or set --node"
	}
	log.Printf("mcp stdio ready (default node %q%s)", config.DefaultNode, hint)
	return bridge.ServeStdio(ctx)
}

// resolveMCPTransport picks the transport for the mcp command. The stdio
// transport owns stdin/stdout and never listens, so an HTTP-only flag selects
// HTTP on its own unless --transport was given explicitly.
func resolveMCPTransport(transport string, explicit map[string]bool) (string, error) {
	if transport != "stdio" && transport != "http" {
		return "", fmt.Errorf("unsupported transport %q; expected stdio or http", transport)
	}
	httpOnly := explicit["listen"] || explicit["auth-token"]
	if !explicit["transport"] {
		if httpOnly {
			return "http", nil
		}
		return transport, nil
	}
	if transport == "stdio" && httpOnly {
		return "", fmt.Errorf("--listen/--auth-token cannot be combined with --transport stdio")
	}
	return transport, nil
}

func runKeygen(args []string) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	flags.SetOutput(os.Stdout)
	keyPath := flags.String("private-key", "", "output path for the client private key")
	flags.Usage = func() {
		fmt.Fprintln(os.Stdout, "Usage: remote-shell keygen [options]")
		flags.PrintDefaults()
	}
	if wantsHelp(args) {
		flags.Usage()
		return nil
	}
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	if *keyPath == "" {
		*keyPath = filepath.Join("keys", "client.key")
	}
	if err := os.MkdirAll(filepath.Dir(*keyPath), 0o700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	publicKey, privateKey, err := identity.GenerateClientKey()
	if err != nil {
		return err
	}
	file, err := os.OpenFile(*keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create private key file: %w", err)
	}
	if _, err := file.Write(privateKey); err != nil {
		_ = file.Close()
		_ = os.Remove(*keyPath)
		return fmt.Errorf("write private key: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(*keyPath)
		return fmt.Errorf("sync private key: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close private key: %w", err)
	}
	fmt.Printf("private_key_file=%s\n", *keyPath)
	fmt.Printf("client_id=%s\n", identity.ClientID(publicKey))
	fmt.Printf("client_public_key_hex=%s\n", hex.EncodeToString(publicKey))
	return nil
}

func printRootUsage() {
	fmt.Fprintln(os.Stdout, "Usage: remote-shell <serve|mcp|keygen|pubkey> [options]")
	fmt.Fprintln(os.Stdout, "Commands:")
	fmt.Fprintln(os.Stdout, "  serve   Run the remote execution agent")
	fmt.Fprintln(os.Stdout, "  mcp     Serve the MCP tools over stdio or streamable HTTP")
	fmt.Fprintln(os.Stdout, "  keygen  Generate a client authentication key")
	fmt.Fprintln(os.Stdout, "  pubkey  Print the public key of a client private key")
	fmt.Fprintln(os.Stdout, "Use 'remote-shell <command> -h' for command options.")
}

func runPubkey(args []string) error {
	flags := flag.NewFlagSet("pubkey", flag.ContinueOnError)
	flags.SetOutput(os.Stdout)
	keyPath := flags.String("private-key", filepath.Join("keys", "client.key"), "client private key path")
	flags.Usage = func() {
		fmt.Fprintln(os.Stdout, "Usage: remote-shell pubkey [options]")
		flags.PrintDefaults()
	}
	if wantsHelp(args) {
		flags.Usage()
		return nil
	}
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	privateKey, err := identity.LoadClientPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	// Ed25519 private keys embed the public half, so derive it from the seed to
	// detect a corrupted or partially tampered key file.
	publicKey := ed25519.NewKeyFromSeed(privateKey.Seed()).Public().(ed25519.PublicKey)
	fmt.Println(hex.EncodeToString(publicKey))
	return nil
}

func wantsHelp(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" || arg == "-help" {
			return true
		}
	}
	return false
}
