#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
go mod download
go build -o bin/dockyard ./cmd/dockyard
