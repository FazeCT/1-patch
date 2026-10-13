#!/usr/bin/env python3
"""Check that an entry trampoline clears the complete verified old body."""
import re
import subprocess
import sys


def command(*args):
    return subprocess.check_output(args, text=True)


def symbol(path, name):
    for line in command("nm", "-S", "-n", path).splitlines():
        fields = line.split()
        if len(fields) == 4 and fields[3] == name:
            return int(fields[0], 16), int(fields[1], 16)
    raise AssertionError(f"missing sized symbol {name} in {path}")


def read_function(path, address, size):
    sections = command("readelf", "-SW", path)
    match = re.search(
        r"\[\s*\d+\]\s+\.text\s+\S+\s+([0-9a-fA-F]+)\s+"
        r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)", sections)
    assert match, "missing .text section"
    section_address, section_offset, section_size = (
        int(value, 16) for value in match.groups()
    )
    assert section_address <= address
    assert address - section_address + size <= section_size
    with open(path, "rb") as stream:
        stream.seek(section_offset + address - section_address)
        return stream.read(size)


original, patched, name, mode = sys.argv[1:]
_, size = symbol(original, name)
patched_address, _ = symbol(patched, name)
code = read_function(patched, patched_address, size)
if mode == "trampoline":
    assert code[0] == 0xE9, f"expected entry jump, got {code[0]:#x}"
    assert code[5:] == b"\x90" * (size - 5), (
        "verified old function tail was not completely NOP-filled"
    )
elif mode == "in-place":
    assert code.startswith(b"\xf3\x0f\x1e\xfa"), (
        "in-place replacement lost its CET landing pad"
    )
    assert code.rstrip(b"\x90").endswith(b"\xc3"), (
        "in-place replacement does not end in a return"
    )
    assert len(code.rstrip(b"\x90")) < size, (
        "unused original bytes were not NOP-filled"
    )
else:
    raise AssertionError(f"unknown mode: {mode}")
