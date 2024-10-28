#!/bin/bash
set -e

# Quick checks
command -v go >/dev/null
command -v tar >/dev/null
command -v base64 >/dev/null

# Build go binary
# Archs: amd64,arm64
export CGO_ENABLED=0
export GOARCH="amd64"
export GOOS=linux
go build -o sleeponlan-$GOOS-$GOARCH-static -a -ldflags '-s -w -buildid= -extldflags "-static"' sleeponlan.go

export GOARCH="arm64"
go build -o sleeponlan-$GOOS-$GOARCH-static -a -ldflags '-s -w -buildid= -extldflags "-static"' sleeponlan.go

exit 0
