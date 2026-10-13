#!/bin/sh
set -eu
patcher=$1
case "$patcher" in /*) ;; *) patcher=$(cd "$(dirname "$patcher")" && pwd)/$(basename "$patcher") ;; esac
test_dir=$(mktemp -d)
cpp_test_name=tls-fix
. "$(dirname "$0")/diagnostics.sh"
trap 'cpp_fixture_cleanup $?' EXIT
cd "$test_dir"

cat > target.cpp <<'EOF'
#include <atomic>
#include <thread>
#include <vector>
extern "C" {
int anchor = 11;
thread_local int initialized = 3;
thread_local int zero;
thread_local int untouched = 23;
thread_local int* pointer = &anchor;
}
extern "C" __attribute__((noinline)) int target() { return -1; }
std::atomic<int> failures{0};
void check() {
    if (initialized != 17 || zero != 19 || untouched != 23 || *pointer != 11) ++failures;
    if (target() != 39 || initialized != 18 || zero != 21) ++failures;
    if (target() != 42 || initialized != 19 || zero != 23 || *pointer != 11) ++failures;
}
int main() {
    check();
    std::vector<std::thread> workers;
    for (int i = 0; i < 4; ++i) workers.emplace_back(check);
    for (auto& worker : workers) worker.join();
    if (initialized != 19 || zero != 23) ++failures;
    return failures.load() ? 1 : 0;
}
EOF
for kind in exec pie; do
    case "$kind" in exec) flags='-no-pie' ;; pie) flags='-fPIE -pie' ;; esac
    g++ $flags -O0 -g -pthread target.cpp -o "$kind-target"
    address=$(nm -n "$kind-target" | awk '$3 == "target" { print $1; exit }')
    initialized=$(nm -n "$kind-target" | awk '$3 == "initialized" { print $1; exit }')
    zero=$(nm -n "$kind-target" | awk '$3 == "zero" { print $1; exit }')
    test -n "$address" && test -n "$initialized" && test -n "$zero"
    cat > "$kind-patch.cpp" <<EOF
extern "C" {
thread_local int fix_0x${initialized}_initialized = 17;
thread_local int fix_0x${zero}_zero = 19;
int fix_0x${address}_target() {
    ++fix_0x${initialized}_initialized;
    fix_0x${zero}_zero += 2;
    return fix_0x${initialized}_initialized + fix_0x${zero}_zero;
}
}
EOF
    "$patcher" --cpp-runtime -p "$kind-patch.cpp" -i "$kind-target" -o "$kind-patched"
    readelf -SW "$kind-patched" | grep -q '\.patch.tls_image'
    "./$kind-patched"
done

cat > dynamic.cpp <<EOF
int initial() { return 99; }
extern "C" thread_local int fix_0x${initialized}_initialized = initial();
EOF
if "$patcher" --cpp-runtime -p dynamic.cpp -i pie-target -o dynamic-output 2> dynamic.log; then
    echo 'dynamic TLS initializer accepted as a plain template fix' >&2
    exit 1
fi
test ! -e dynamic-output
grep -q 'fix_tls_ lifecycle hook' dynamic.log
