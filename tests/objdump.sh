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

# The original main has a direct call to display_info at 0x6CADB. After
# relocation, that call should name the inserted replacement rather than the
# old display_info entry (which retains a jump for indirect callers).
python3 - "$target" "$test_dir/objdump_patched" <<'PY'
import re
import subprocess
import sys

original, patched = sys.argv[1:]

def section(path, name):
    headers = subprocess.check_output(["readelf", "-SW", path], text=True)
    match = re.search(
        rf"\[\s*\d+\]\s+{name}\s+\S+\s+([0-9a-fA-F]+)\s+"
        r"[0-9a-fA-F]+\s+([0-9a-fA-F]+)", headers)
    assert match, f"missing section {name}"
    return tuple(int(value, 16) for value in match.groups())

source_text, _ = section(original, r"\.text")
output_text, _ = section(patched, r"\.text")
replacement_text, replacement_size = section(patched, r"\.text\.[^\s]+")
callsite = 0x6CADB - source_text + output_text
disassembly = subprocess.check_output(
    ["objdump", "-d", f"--start-address={callsite}",
     f"--stop-address={callsite + 5}", patched], text=True)
call = re.search(r"\bcallq?\s+([0-9a-fA-F]+)\b", disassembly)
assert call, "relocated display_info call was not found"
destination = int(call.group(1), 16)
assert replacement_text <= destination < replacement_text + replacement_size, (
    f"direct display_info call still targets 0x{destination:x}")
PY
