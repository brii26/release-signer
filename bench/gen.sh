#!/bin/sh
# POSIX wrapper; run from any working directory. Go is the only dependency.
set -eu
cd "$(dirname "$0")/.."
exec go run ./bench -generate-only
