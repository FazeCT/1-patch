# Sourced by the C++ runtime integration tests. Keep failed fixtures in the
# shared build directory so their ELF metadata and debugger output are visible
# from both Ubuntu and the Windows workspace.
ulimit -c 0 || :

cpp_fixture_cleanup() {
    cpp_status=$1
    if test "$cpp_status" -eq 0; then
        rm -rf "$test_dir"
        return
    fi
    cpp_base=$(dirname "$patcher")/cpp-diagnostics
    mkdir -p "$cpp_base"
    cpp_saved=$(mktemp -d "$cpp_base/$cpp_test_name-XXXXXX")
    cp -a "$test_dir/." "$cpp_saved/"
    for cpp_binary in "$cpp_saved"/*-target "$cpp_saved"/*-patched; do
        test -f "$cpp_binary" || continue
        readelf -aW "$cpp_binary" > "$cpp_binary.readelf.txt" 2>&1 || :
        readelf -wF "$cpp_binary" > "$cpp_binary.frames.txt" 2>&1 || :
        objdump -drwC "$cpp_binary" > "$cpp_binary.asm.txt" 2>&1 || :
        case "$cpp_binary" in
            *-patched)
                if command -v gdb >/dev/null 2>&1; then
                    timeout -k 2s 10s gdb -nx -batch -ex run -ex 'bt full' \
                        -ex 'info registers' -ex 'info proc mappings' --args "$cpp_binary" \
                        > "$cpp_binary.gdb.txt" 2>&1 || :
                fi
                ;;
        esac
    done
    echo "C++ diagnostic files: $cpp_saved" >&2
    rm -rf "$test_dir"
}
