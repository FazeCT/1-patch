#!/bin/sh
set -eu

patcher=$1
target=$2
patch=$3

test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM

"$patcher" -p "$patch" -i "$target" -o "$test_dir/objdump_patched"
readelf -h "$test_dir/objdump_patched" >/dev/null
"$test_dir/objdump_patched" --version >/dev/null
"$test_dir/objdump_patched" -i >/dev/null
