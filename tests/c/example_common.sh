#!/bin/sh

example_setup() {
    example=$1
    patcher=$2
    source_root=$3
    target="$source_root/examples/$example/$example"
    patch="$source_root/examples/$example/${example}_patch.c"

    test -x "$patcher" || { echo "Missing patcher: $patcher" >&2; exit 1; }
    test -s "$target" || { echo "Missing example target: $target" >&2; exit 1; }
    test -s "$patch" || { echo "Missing example patch: $patch" >&2; exit 1; }
    readelf -h "$target" >/dev/null || {
        echo "Invalid example ELF: $target" >&2
        exit 1
    }
}

example_skip() {
    echo "TODO: add runtime behavior assertions for $example" >&2
    exit 77
}
