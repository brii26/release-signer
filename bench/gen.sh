#!/bin/sh
# wrapper POSIX sh
set -eu
cd "$(dirname "$0")/.."
exec go run ./bench -generate-only
