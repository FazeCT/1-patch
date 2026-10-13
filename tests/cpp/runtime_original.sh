#!/bin/sh
set -eu
patcher=$1
case "$patcher" in /*) ;; *) patcher=$(cd "$(dirname "$patcher")" && pwd)/$(basename "$patcher") ;; esac
test_dir=$(mktemp -d)
cpp_test_name=original
. "$(dirname "$0")/diagnostics.sh"
trap 'cpp_fixture_cleanup $?' EXIT
cd "$test_dir"

cat > target.cpp <<'EOF'
#include <stdexcept>
extern "C" __attribute__((noinline)) int target(int n) {
    if (n == 9) throw std::runtime_error("original");
    if (!n) return 1;
    return target(n - 1) + 1;
}
EOF
cat > caller.cpp <<'EOF'
#include <stdexcept>
#include <string>
extern "C" int target(int);
int main() {
    if (target(3) != 24) return 1;
    int (*volatile indirect)(int) = target;
    if (indirect(2) != 23) return 2;
    try { target(9); return 3; }
    catch (const std::runtime_error& error) {
        return std::string(error.what()) == "original" ? 0 : 4;
    }
}
EOF
for kind in exec pie; do
    case "$kind" in exec) flags='-no-pie -fcf-protection=none' ;; pie) flags='-fPIE -pie -fcf-protection=full' ;; esac
    g++ $flags -O0 -g target.cpp caller.cpp -o "$kind-target"
    address=$(nm -n "$kind-target" | awk '$3 == "target" { print $1; exit }')
    test -n "$address"
    cat > "$kind-patch.cpp" <<EOF
extern "C" int ref_0x${address}_original(int);
extern "C" int fix_0x${address}_target(int n) {
    return ref_0x${address}_original(n) + 20;
}
EOF
    "$patcher" --cpp-runtime -p "$kind-patch.cpp" -i "$kind-target" -o "$kind-patched"
    readelf -SW "$kind-patched" | grep -q '\.text.original\.'
    "./$kind-patched"
done

# A short original entry cannot be retained using this prologue trampoline.
cat > short.S <<'EOF'
.text
.globl target
.type target,@function
target:
  ret
.size target,.-target
.section .note.GNU-stack,"",@progbits
EOF
cat > short.cpp <<'EOF'
extern "C" void target();
int main() { target(); }
EOF
g++ -no-pie short.cpp short.S -o short-target
address=$(nm -n short-target | awk '$3 == "target" { print $1; exit }')
cat > short-patch.cpp <<EOF
extern "C" void ref_0x${address}_original();
extern "C" void fix_0x${address}_target() { ref_0x${address}_original(); }
EOF
if "$patcher" --cpp-runtime -p short-patch.cpp -i short-target -o short-output 2> short.log; then
    echo 'unsafe short original-function trampoline accepted' >&2
    exit 1
fi
test ! -e short-output
grep -q 'too short for a safe entry jump' short.log

cat > recursive.S <<'EOF'
.text
.globl target
.type target,@function
target:
  push %rbp
  mov %rsp,%rbp
  nop
  pop %rbp
  jmp target
.size target,.-target
.section .note.GNU-stack,"",@progbits
EOF
g++ -no-pie short.cpp recursive.S -o recursive-target
address=$(nm -n recursive-target | awk '$3 == "target" { print $1; exit }')
cat > recursive-patch.cpp <<EOF
extern "C" void ref_0x${address}_original();
extern "C" void fix_0x${address}_target() { ref_0x${address}_original(); }
EOF
if "$patcher" --cpp-runtime -p recursive-patch.cpp -i recursive-target -o recursive-output 2> recursive.log; then
    echo 'unsafe recursive short branch accepted' >&2
    exit 1
fi
test ! -e recursive-output
grep -q 'out-of-range recursive branch' recursive.log
