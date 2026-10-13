#!/bin/sh
set -eu
patcher=$1
case "$patcher" in /*) ;; *) patcher=$(cd "$(dirname "$patcher")" && pwd)/$(basename "$patcher") ;; esac
test_dir=$(mktemp -d)
cpp_test_name=tls-objects
. "$(dirname "$0")/diagnostics.sh"
trap 'cpp_fixture_cleanup $?' EXIT
cd "$test_dir"

cat > target.cpp <<'EOF'
#include <atomic>
#include <string>
#include <thread>
#include <vector>
extern "C" {
thread_local int initializations;
thread_local int untouched = 6;
}
std::string initial() { ++initializations; return "original thread object with heap allocation"; }
extern "C" { thread_local std::string word = initial(); }
extern "C" __attribute__((noinline)) int target() { return -1; }
std::atomic<int> failures{0};
void check(int mode) {
    // Test both native first access and access through a patch ref_ first.
    if (mode) {
        if (word != "replacement thread object with heap allocation") ++failures;
    }
    if (target() != 1 || word != "replacement thread object with heap allocation") ++failures;
    word += '!';
    if (target() != 2 || word != "replacement thread object with heap allocation!") ++failures;
    if (initializations != 1 || untouched != 6) ++failures;
}
int main() {
    check(1);
    std::vector<std::thread> workers;
    for (int i = 0; i < 4; ++i) workers.emplace_back(check, i % 2);
    for (auto& worker : workers) worker.join();
    return failures.load() ? 1 : 0;
}
EOF
for kind in exec pie; do
    case "$kind" in exec) flags='-no-pie -fcf-protection=none' ;; pie) flags='-fPIE -pie -fcf-protection=full' ;; esac
    g++ $flags -O0 -g -pthread target.cpp -o "$kind-target"
    address=$(nm -n "$kind-target" | awk '$3 == "target" { print $1; exit }')
    word=$(nm -n "$kind-target" | awk '$3 == "word" { print $1; exit }')
    test -n "$address" && test -n "$word"
    cat > "$kind-patch.cpp" <<EOF
#include <cstddef>
#include <cstdlib>
#include <new>
#include <string>
extern "C" {
extern thread_local std::string ref_0x${word}_word;
extern const std::size_t fix_tls_size_0x${word}_word = sizeof(std::string);
extern const std::size_t fix_tls_priority_0x${word}_word = 1;
void fix_tls_0x${word}_word(void* storage) noexcept {
    auto* object = static_cast<std::string*>(storage);
    if (*object != "original thread object with heap allocation") std::abort();
    object->~basic_string();
    new (storage) std::string("replacement thread object with heap allocation");
}
int fix_0x${address}_target() {
    if (ref_0x${word}_word == "replacement thread object with heap allocation") return 1;
    if (ref_0x${word}_word == "replacement thread object with heap allocation!") return 2;
    return 90;
}
}
EOF
    "$patcher" --cpp-runtime -p "$kind-patch.cpp" -i "$kind-target" -o "$kind-patched"
    "./$kind-patched"
done
