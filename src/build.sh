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
go build -o sleeponlan-$GOOS-$GOARCH-static -a -ldflags '-s -w -buildid= -extldflags "-static"' *.go

# Get version
version=$(./sleeponlan-$GOOS-$GOARCH-static -v)

# Add version to exe
mv sleeponlan-$GOOS-$GOARCH-static sleeponlan_"$version"-$GOOS-$GOARCH-static

# Make checksum for exe
md5sum sleeponlan_"$version"-$GOOS-$GOARCH-static > sleeponlan_"$version"-$GOOS-$GOARCH-static.sha256

# Compile arm exe
export GOARCH="arm64"
go build -o sleeponlan_"$version"-$GOOS-$GOARCH-static -a -ldflags '-s -w -buildid= -extldflags "-static"' *.go

# Make checksum for exe
md5sum sleeponlan_"$version"-$GOOS-$GOARCH-static > sleeponlan_"$version"-$GOOS-$GOARCH-static.sha256

exit 0
