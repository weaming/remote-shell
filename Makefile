GO ?= go
KEY_DIR ?= keys
OUT_DIR ?= dist

.PHONY: keygen build

install: build
	cp dist/remote-shell-darwin-arm64 ~/go/bin/remote-shell

build:
	@GO="$(GO)" KEY_DIR="$(KEY_DIR)" OUT_DIR="$(OUT_DIR)" fish scripts/build.fish build

keygen:
	@GO="$(GO)" KEY_DIR="$(KEY_DIR)" OUT_DIR="$(OUT_DIR)" fish scripts/build.fish keygen
