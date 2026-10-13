#!/bin/sh
set -eu
patcher=$1
case "$patcher" in
    /*) ;;
    *) patcher=$(cd "$(dirname "$patcher")" && pwd)/$(basename "$patcher") ;;
esac
test_dir=$(mktemp -d)
cpp_test_name=tls
. "$(dirname "$0")/diagnostics.sh"
trap 'cpp_fixture_cleanup $?' EXIT
cd "$test_dir"

cat > target.cpp <<'EOF'
#include <atomic>
#include <string>
#include <thread>
#include <vector>
__attribute__((noinline)) int initial_value() { return 5; }
extern "C" {
thread_local int initialized = 3;
thread_local int zero_tls;
thread_local int dynamic_value = initial_value();
thread_local std::string word = "tls";
}
__attribute__((noinline)) int target(int) { return -1; }
std::atomic<int> failures{0};
void check(int tag) {
    // The patch accesses these TLS variables before this thread accesses them
    // through their original names, exercising the original TLS initializer.
    int result = target(tag);
    if (result != 12 + 12 * tag || initialized != 3 + tag ||
        zero_tls != 10 * tag || dynamic_value != 5 + tag ||
        word != "tls" + std::to_string(tag)) ++failures;
}
int main() {
    check(1);
    std::vector<std::thread> workers;
    for (int tag = 2; tag <= 4; ++tag) workers.emplace_back(check, tag);
    for (auto& worker : workers) worker.join();
    if (initialized != 4 || zero_tls != 10 || dynamic_value != 6 || word != "tls1")
        ++failures;
    return failures.load() ? 1 : 0;
}
EOF

for kind in exec pie; do
    case "$kind" in
        exec) flags='-no-pie -fcf-protection=none' ;;
        pie) flags='-fPIE -pie -fcf-protection=full' ;;
    esac
    g++ $flags -O0 -g -pthread target.cpp -o "$kind-target"
    target_address=$(nm -n "$kind-target" | awk '$3 == "_Z6targeti" { print $1; exit }')
    initialized_offset=$(nm -n "$kind-target" | awk '$3 == "initialized" { print $1; exit }')
    zero_offset=$(nm -n "$kind-target" | awk '$3 == "zero_tls" { print $1; exit }')
    dynamic_offset=$(nm -n "$kind-target" | awk '$3 == "dynamic_value" { print $1; exit }')
    word_offset=$(nm -n "$kind-target" | awk '$3 == "word" { print $1; exit }')
    test -n "$target_address" && test -n "$initialized_offset" &&
        test -n "$zero_offset" && test -n "$dynamic_offset" && test -n "$word_offset"
    cat > "$kind-patch.cpp" <<EOF
#include <string>
extern "C" {
extern thread_local int ref_0x${initialized_offset}_initialized;
extern thread_local int ref_0x${zero_offset}_zero;
extern thread_local int ref_0x${dynamic_offset}_dynamic;
extern thread_local std::string ref_0x${word_offset}_word;
int fix_0x${target_address}_target(int tag) {
    ref_0x${initialized_offset}_initialized += tag;
    ref_0x${zero_offset}_zero = tag * 10;
    ref_0x${dynamic_offset}_dynamic += tag;
    ref_0x${word_offset}_word += static_cast<char>('0' + tag);
    return ref_0x${initialized_offset}_initialized + ref_0x${zero_offset}_zero +
           ref_0x${dynamic_offset}_dynamic + static_cast<int>(ref_0x${word_offset}_word.size());
}
}
EOF
    "$patcher" --cpp-runtime -p "$kind-patch.cpp" -i "$kind-target" -o "$kind-patched"
    readelf -sW "$kind-patched" | grep "ref_0x${initialized_offset}_initialized" | grep -q TLS
    "./$kind-patched"
done
