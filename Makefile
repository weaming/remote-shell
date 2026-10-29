GO ?= go
KEY_DIR ?= keys
OUT_DIR ?= dist

.PHONY: keygen build

# cp over an existing binary keeps its com.apple.provenance attribute, which no
# longer matches the new bytes; macOS then kills the result at exec (exit 137).
install: build
	rm -f ~/go/bin/remote-shell
	cp dist/remote-shell-darwin-arm64 ~/go/bin/remote-shell

build:
	@GO="$(GO)" KEY_DIR="$(KEY_DIR)" OUT_DIR="$(OUT_DIR)" fish scripts/build.fish build

keygen:
	@GO="$(GO)" KEY_DIR="$(KEY_DIR)" OUT_DIR="$(OUT_DIR)" fish scripts/build.fish keygen
