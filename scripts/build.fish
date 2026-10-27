#!/usr/bin/env fish

set -g script_dir (dirname (status --current-filename))
cd (realpath "$script_dir/..")

set -q GO; and test -n "$GO"; or set -l GO go
set -q CGO_ENABLED; and test -n "$CGO_ENABLED"; or set -l CGO_ENABLED 0
set -q GOFLAGS; and test -n "$GOFLAGS"; or set -l GOFLAGS -trimpath
set -q LDFLAGS; and test -n "$LDFLAGS"; or set -l LDFLAGS "-s -w -buildid="
set -q KEY_DIR; and test -n "$KEY_DIR"; or set -l KEY_DIR keys
set -q OUT_DIR; and test -n "$OUT_DIR"; or set -l OUT_DIR dist
set -gx GO $GO
set -gx CGO_ENABLED $CGO_ENABLED
set -gx GOFLAGS $GOFLAGS
set -gx LDFLAGS $LDFLAGS
set -gx KEY_DIR $KEY_DIR
set -gx OUT_DIR $OUT_DIR

set -g client_key "$KEY_DIR/client.key"
set -g client_key_info "$KEY_DIR/client-key-info"
set -l targets darwin/arm64 linux/amd64 linux/arm64

function usage
    echo "Usage: scripts/build.fish <keygen|build|pubkey>"
    echo "Commands:"
    echo "  keygen  Generate a client authentication key under \$KEY_DIR"
    echo "  build   Build every target under \$OUT_DIR"
    echo "  pubkey  Print the public key of \$KEY_DIR/client.key"
    echo "Environment: GO, CGO_ENABLED, GOFLAGS, LDFLAGS, KEY_DIR, OUT_DIR"
end

function fail
    echo "build: $argv" >&2
    exit 1
end

function host_go
    env -u GOOS -u GOARCH "$GO" $argv
end

function public_key_of
    host_go run ./cmd/remote-shell pubkey --private-key "$client_key"
end

function load_public_key
    test -n "$client_key_info"; or fail "client key info path is not set"
    test -n "$client_key"; or fail "client key path is not set"
    test -s "$client_key_info"; or fail "missing $client_key_info; run 'scripts/build.fish keygen' first"
    set -l recorded (string match -r '^client_public_key_hex=(.*)$' <$client_key_info)[2]
    test -n "$recorded"; or fail "client public key missing from $client_key_info"
    test -s "$client_key"; or fail "missing client private key $client_key; run 'scripts/build.fish keygen' first"
    set -l derived (public_key_of)
    test "$derived" = "$recorded"; or fail "embedded client public key does not match $client_key; regenerate with 'scripts/build.fish keygen'"
    echo $recorded
end

function keygen
    mkdir -p "$KEY_DIR"
    if test -e "$client_key"; or test -e "$client_key_info"
        fail "client key already exists under $KEY_DIR; refusing to overwrite"
    end
    set -l tmp "$client_key_info.tmp"
    host_go run ./cmd/remote-shell keygen --private-key "$client_key" >$tmp
    or begin
        rm -f "$tmp"
        fail "keygen failed"
    end
    set -l public_key (string match -r '^client_public_key_hex=(.*)$' <$tmp)[2]
    test -n "$public_key"; or begin
        rm -f "$tmp"
        fail "keygen did not produce a client public key"
    end
    mv "$tmp" "$client_key_info"
    test (public_key_of) = "$public_key"; or begin
        fail "generated key does not match $client_key_info; inspect the two files before retrying"
    end
    cat "$client_key_info"
end

function build_target
    set -l target $argv[1]
    set -l public_key $argv[2]
    set -l goos (string split / $target)[1]
    set -l goarch (string split / $target)[2]
    set -l output "$OUT_DIR/remote-shell-$goos-$goarch"
    # Build beside the target and rename, so a rebuild never overwrites the
    # pages of a copy that is still running: macOS kills such a process with
    # "Code Signature Invalid" once it faults a page back in.
    set -l staging "$output.new"
    mkdir -p (dirname "$output")
    env CGO_ENABLED="$CGO_ENABLED" GOOS="$goos" GOARCH="$goarch" \
        "$GO" build $GOFLAGS -ldflags "$LDFLAGS -X remote-shell/agent.EmbeddedTrustedClientPublicKeyHex=$public_key" \
        -o "$staging" ./cmd/remote-shell
    or begin
        rm -f "$staging"
        fail "build $target failed"
    end
    mv -f "$staging" "$output"
    echo "built $output"
end

switch "$argv[1]"
    case keygen
        keygen
    case pubkey
        test -s "$client_key"; or fail "missing client private key $client_key"
        public_key_of
    case build ''
        set -l public_key (load_public_key)
        for target in $targets
            build_target $target $public_key
        end
    case -h --help help
        usage
    case '*'
        usage >&2
        exit 1
end
