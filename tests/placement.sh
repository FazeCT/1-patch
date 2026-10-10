#!/bin/sh
set -eu

patcher=$1
script_dir=$(cd "$(dirname "$0")" && pwd)
case "$patcher" in
    /*) ;;
    *) patcher=$(cd "$(dirname "$patcher")" && pwd)/$(basename "$patcher") ;;
esac

test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
cd "$test_dir"

cat > roomy.c <<'EOF'
__attribute__((noinline)) int target(void) {
    __asm__ volatile(".rept 48; nop; .endr");
    return 3;
}
int main(void) {
    int (*volatile saved)(void) = target;
    return target() + saved();
}
EOF
gcc -no-pie -fcf-protection=none -O0 -g roomy.c -o roomy
address=$(nm -n roomy | awk '$3 == "target" { print $1; exit }')
cat > roomy-patch.c <<EOF
int fix_0x${address}_target(void) { return 7; }
EOF
"$patcher" -p roomy-patch.c -i roomy -o roomy-patched
set +e
./roomy-patched
result=$?
set -e
test "$result" -eq 14
! readelf -SW roomy-patched | grep -q '\.text\.'
python3 "$script_dir/placement_bytes.py" roomy roomy-patched target in-place

cat > small.c <<'EOF'
__attribute__((noinline)) int target(void) { return 3; }
int main(void) { return target(); }
EOF
gcc -no-pie -fcf-protection=none -O0 -g small.c -o small
address=$(nm -n small | awk '$3 == "target" { print $1; exit }')
cat > large-patch.c <<EOF
int fix_0x${address}_target(void) {
    __asm__ volatile(".rept 64; nop; .endr");
    return 7;
}
EOF
"$patcher" -p large-patch.c -i small -o large-patched
set +e
./large-patched
result=$?
set -e
test "$result" -eq 7
python3 "$script_dir/placement_bytes.py" small large-patched target trampoline

# A known interior entry must keep its original implementation. The function
# is large enough for the replacement, but not safe to overwrite in place.
cat > interior.S <<'EOF'
.text
.globl target
.type target, @function
target:
    .rept 16
    nop
    .endr
.globl target_inner
.type target_inner, @function
target_inner:
    mov $3, %eax
    ret
.size target_inner, .-target_inner
.size target, .-target
.section .note.GNU-stack,"",@progbits
EOF
cat > interior-main.c <<'EOF'
extern int target(void);
extern int target_inner(void);
int main(void) { return target() + target_inner(); }
EOF
gcc -no-pie -O0 -g interior.S interior-main.c -o interior
address=$(nm -n interior | awk '$3 == "target" { print $1; exit }')
cat > interior-patch.c <<EOF
int fix_0x${address}_target(void) { return 7; }
EOF
"$patcher" -p interior-patch.c -i interior -o interior-patched
set +e
./interior-patched
result=$?
set -e
test "$result" -eq 10
readelf -SW interior-patched | grep -q '\.text\.'

# _start passes main in RDI to __libc_start_main instead of calling it.
# This three-byte main cannot hold a jump, so startup must pass the relocated
# replacement address for both absolute and RIP-relative address loads.
cat > startup-main.S <<'EOF'
.text
.globl main
.type main, @function
main:
    xor %eax, %eax
    ret
.size main, .-main
.section .note.GNU-stack,"",@progbits
EOF
for kind in exec pie; do
    case "$kind" in
        exec) gcc -no-pie -fcf-protection=none -g startup-main.S -o "startup-$kind" ;;
        pie) gcc -fPIE -pie -fcf-protection=none -g startup-main.S -o "startup-$kind" ;;
    esac
    address=$(nm -n "startup-$kind" |
        awk '$3 == "main" { print $1; exit }')
    test -n "$address"
    cat > "startup-$kind-patch.c" <<EOF
int fix_0x${address}_main(void) { return 7; }
EOF
    "$patcher" -p "startup-$kind-patch.c" -i "startup-$kind" \
        -o "startup-$kind-patched" 2> "startup-$kind.log"
    grep -q 'insufficient space for an entry jump' "startup-$kind.log"
    set +e
    "./startup-$kind-patched"
    result=$?
    set -e
    test "$result" -eq 7
done

