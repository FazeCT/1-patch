#!/bin/sh
set -eu

patcher=$1
case "$patcher" in
    /*) ;;
    *) patcher=$(cd "$(dirname "$patcher")" && pwd)/$(basename "$patcher") ;;
esac

test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
cd "$test_dir"

cat > target.c <<'EOF'
#include <stdio.h>
__attribute__((noinline)) int target(void) {
    puts("before");
    __asm__ volatile(".rept 64; nop; .endr");
    return 3;
}
int main(void) { return target(); }
EOF

slot_count() {
    readelf -Wr "$1" | awk -v name="$2" \
        '$3 ~ /^R_X86_64_(JUMP_SLOT|GLOB_DAT)$/ && \
         $5 ~ ("^" name "(@|$)") { count++ } END { print count + 0 }'
}

for kind in exec pie; do
    case "$kind" in
        exec) gcc -no-pie -O0 -g target.c -o "$kind-target" ;;
        pie) gcc -fPIE -pie -O0 -g target.c -o "$kind-target" ;;
    esac
    target_address=$(nm -n "$kind-target" |
        awk '$3 == "target" { print $1; exit }')
    test -n "$target_address"
    test "$(slot_count "$kind-target" puts)" -eq 1
    test "$(slot_count "$kind-target" getpid)" -eq 0

    cat > "$kind-patch.c" <<EOF
#include <stdio.h>
#include <unistd.h>
int fix_0x${target_address}_target(void) {
    puts("after");
    return getpid() > 0 ? 7 : 8;
}
EOF
    "$patcher" -v -p "$kind-patch.c" -i "$kind-target" \
        -o "$kind-patched" > "$kind.log"
    grep -q 'Reused GOT entry for puts' "$kind.log"
    test "$(slot_count "$kind-patched" puts)" -eq 1
    test "$(slot_count "$kind-patched" getpid)" -eq 1
    set +e
    "./$kind-patched" > "$kind.out"
    result=$?
    set -e
    test "$result" -eq 7
    grep -qx 'after' "$kind.out"
done
