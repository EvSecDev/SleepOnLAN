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
export CGO_ENABLED=0
export GOARCH="amd64"
export GOOS=linux
go build -o sleeponlan -a -ldflags '-s -w -buildid= -extldflags "-static"' sleeponlan.go || logError "failed to compile binary"

exit 0
