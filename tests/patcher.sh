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

set +e
"$patcher" unexpected >/dev/null 2>&1
result=$?
set -e
test "$result" -eq 2

cat > target.c <<'EOF'
int value;
__attribute__((noinline)) int helper(void) { return value; }
__attribute__((noinline)) int target(void) { return helper(); }
int main(void) { return target(); }
EOF
gcc -no-pie -O0 -g target.c -o target
target_address=$(nm -n target | awk '$3 == "target" { print $1; exit }')
helper_address=$(nm -n target | awk '$3 == "helper" { print $1; exit }')
value_address=$(nm -n target | awk '$3 == "value" { print $1; exit }')
test -n "$target_address"
test -n "$helper_address"
test -n "$value_address"

cat > patch.c <<EOF
int ref_0x${value_address}_value;
int ref_0x${helper_address}_helper(void) { return -1; }
int fix_0x${target_address}_target(void) {
    return ref_0x${helper_address}_helper() + ref_0x${value_address}_value + 7;
}
EOF
"$patcher" -p patch.c -i target -o patched
set +e
./patched
result=$?
set -e
test "$result" -eq 7

# Exercise ET_DYN as well as the fixed-address ET_EXEC case above.
gcc -fPIE -pie -O0 -g target.c -o pie-target
pie_target_address=$(nm -n pie-target | awk '$3 == "target" { print $1; exit }')
pie_helper_address=$(nm -n pie-target | awk '$3 == "helper" { print $1; exit }')
pie_value_address=$(nm -n pie-target | awk '$3 == "value" { print $1; exit }')
test -n "$pie_target_address"
test -n "$pie_helper_address"
test -n "$pie_value_address"
cat > pie-patch.c <<EOF
int ref_0x${pie_value_address}_value;
int ref_0x${pie_helper_address}_helper(void) { return -1; }
int fix_0x${pie_target_address}_target(void) {
    return ref_0x${pie_helper_address}_helper() + ref_0x${pie_value_address}_value + 7;
}
EOF
"$patcher" -p pie-patch.c -i pie-target -o pie-patched
set +e
./pie-patched
result=$?
set -e
test "$result" -eq 7

printf 'old private output\n' > private-output
chmod 600 private-output
"$patcher" -p patch.c -i target -o private-output
test "$(stat -c %a private-output)" = 600

cp target stripped-target
strip -s stripped-target
if "$patcher" -p patch.c -i stripped-target -o refused-output 2> refusal.log; then
    echo "unknown target function extent unexpectedly succeeded" >&2
    exit 1
fi
grep -q 'Target function size is unknown' refusal.log
test ! -e refused-output
"$patcher" -p patch.c -i stripped-target -o stripped-patched --allow-unverified-targets
set +e
./stripped-patched
result=$?
set -e
test "$result" -eq 7

printf 'preserve this output\n' > existing-output
cp existing-output expected-output
cat > invalid.c <<'EOF'
int fix_0xfffffffffffffff0_invalid(void) { return 9; }
EOF
if "$patcher" -p invalid.c -i target -o existing-output; then
    echo "out-of-range fix unexpectedly succeeded" >&2
    exit 1
fi
cmp existing-output expected-output

cat > unresolved.c <<EOF
int ordinary_global = 1;
int fix_0x${target_address}_target(void) { return ordinary_global; }
EOF
if "$patcher" -p unresolved.c -i target -o unresolved-output 2> unresolved.log; then
    echo "unresolved patch reference unexpectedly succeeded" >&2
    exit 1
fi
grep -q 'Unresolved patch global reference' unresolved.log
test ! -e unresolved-output

# Calls through a saved function pointer must reach fix_, including with IBT
# landing pads in both the original and newly compiled functions.
cat > indirect-target.c <<'EOF'
__attribute__((noinline)) int target(void) { return 3; }
int main(void) {
    int (*volatile saved_target)(void) = target;
    return target() + saved_target();
}
EOF
for kind in exec pie plain; do
    case "$kind" in
        exec) gcc -no-pie -fcf-protection=full -O0 -g indirect-target.c -o "indirect-$kind" ;;
        pie) gcc -fPIE -pie -fcf-protection=full -O0 -g indirect-target.c -o "indirect-$kind" ;;
        plain) gcc -no-pie -fcf-protection=none -O0 -g indirect-target.c -o "indirect-$kind" ;;
    esac
    address=$(nm -n "indirect-$kind" | awk '$3 == "target" { print $1; exit }')
    test -n "$address"
    cat > "indirect-$kind-patch.c" <<EOF
#if !defined(__CET__) || (__CET__ & 3) != 3
#error patch compiler must enable CET branch and return protection
#endif
int fix_0x${address}_target(void) { return 7; }
EOF
    "$patcher" -p "indirect-$kind-patch.c" -i "indirect-$kind" -o "indirect-$kind-patched"
    set +e
    "./indirect-$kind-patched"
    result=$?
    set -e
    test "$result" -eq 14
    case "$kind" in
        plain) objdump -d --disassemble=target "indirect-$kind-patched" |
            grep -A1 '<target>:' | grep -q 'jmp' ;;
        *) objdump -d --disassemble=target "indirect-$kind-patched" |
            grep -A1 '<target>:' | grep -q 'endbr64' ;;
    esac
    inserted_section=$(readelf -SW "indirect-$kind-patched" |
        awk '$2 ~ /^\.text\./ { print $2; exit }')
    test -n "$inserted_section"
    objdump -d -j "$inserted_section" "indirect-$kind-patched" |
        awk '/^[[:space:]]*[[:xdigit:]]+:/ { found = ($0 ~ /endbr64/); exit }
             END { exit !found }'
done

# Neither a one-byte function nor ENDBR64 plus RET can hold the jump.
cat > tiny.S <<'EOF'
.text
.globl tiny
.type tiny, @function
tiny:
    ret
.size tiny, .-tiny
.globl tiny_cet
.type tiny_cet, @function
tiny_cet:
    .byte 0xf3, 0x0f, 0x1e, 0xfa
    ret
.size tiny_cet, .-tiny_cet
.section .note.GNU-stack,"",@progbits
EOF
cat > tiny-main.c <<'EOF'
extern void tiny(void);
int main(void) { return 0; }
EOF
gcc -no-pie -O0 -g tiny.S tiny-main.c -o tiny-target
for symbol in tiny tiny_cet; do
    tiny_address=$(nm -n tiny-target | awk -v name="$symbol" '$3 == name { print $1; exit }')
    test -n "$tiny_address"
    cat > "$symbol-patch.c" <<EOF
void fix_0x${tiny_address}_${symbol}(void) { }
EOF
    "$patcher" -p "$symbol-patch.c" -i tiny-target -o "$symbol-patched" 2> "$symbol.log"
    grep -q 'insufficient space for an entry jump' "$symbol.log"
    objdump -d --disassemble="$symbol" "$symbol-patched" | grep -q 'ret'
    "./$symbol-patched"
done

# Redirecting a function that ref_ also calls needs an original-code trampoline.
cat > recursive-patch.c <<EOF
int ref_0x${target_address}_target(void) { return -1; }
int fix_0x${target_address}_target(void) { return ref_0x${target_address}_target() + 1; }
EOF
if "$patcher" -p recursive-patch.c -i target -o recursive-patched 2> recursive.log; then
    echo 'self-reference unexpectedly succeeded' >&2
    exit 1
fi
grep -q 'original-code trampoline' recursive.log
test ! -e recursive-patched
