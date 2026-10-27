GO ?= go
KEY_DIR ?= keys
OUT_DIR ?= dist

.PHONY: keygen build

keygen:
	@GO="$(GO)" KEY_DIR="$(KEY_DIR)" OUT_DIR="$(OUT_DIR)" fish scripts/build.fish keygen

build:
	@GO="$(GO)" KEY_DIR="$(KEY_DIR)" OUT_DIR="$(OUT_DIR)" fish scripts/build.fish build
