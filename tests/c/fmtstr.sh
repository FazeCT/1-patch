#!/bin/sh
set -eu

test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$test_dir/exploit_cases.py" fmtstr "$@"
