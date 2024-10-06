#!/bin/bash

function logError {
	echo "Error: $1"
	exit 1
}

# Quick checks
command -v go >/dev/null || logError "go command not found."
command -v tar >/dev/null || logError "tar command not found."
command -v base64 >/dev/null || logError "base64 command not found."

# Build go binary - dont change output name, its hard coded in install script
# Archs: amd64,arm64
export CGO_ENABLED=0
export GOARCH="arm64"
export GOOS=linux
go build -o sleeponlan-linux-$GOARCH-static -a -ldflags '-s -w -buildid= -extldflags "-static"' sleeponlan.go || logError "failed to compile binary"

export GOARCH="amd64"
go build -o sleeponlan-linux-$GOARCH-static -a -ldflags '-s -w -buildid= -extldflags "-static"' sleeponlan.go || logError "failed to compile binary"

exit 0
