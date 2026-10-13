#!/bin/sh
set -eu
patcher=$1
case "$patcher" in /*) ;; *) patcher=$(cd "$(dirname "$patcher")" && pwd)/$(basename "$patcher") ;; esac
test_dir=$(mktemp -d)
cpp_test_name=objects
. "$(dirname "$0")/diagnostics.sh"
trap 'cpp_fixture_cleanup $?' EXIT
cd "$test_dir"

cat > target.cpp <<'EOF'
#include <string>
extern "C" {
std::string first = "original first object with heap allocation";
std::string second = "original second object with heap allocation";
int limit = 1;
int target() { return 1; }
}
int main() {
    return first == "replacement first object with heap allocation" &&
           second == "replacement second object with heap allocation" &&
           limit == 100 && target() == 7 ? 0 : 1;
}
EOF
for kind in exec pie; do
    case "$kind" in exec) flags='-no-pie' ;; pie) flags='-fPIE -pie' ;; esac
    g++ $flags -O0 -g target.cpp -o "$kind-target"
    first=$(nm -n "$kind-target" | awk '$3 == "first" { print $1; exit }')
    second=$(nm -n "$kind-target" | awk '$3 == "second" { print $1; exit }')
    limit=$(nm -n "$kind-target" | awk '$3 == "limit" { print $1; exit }')
    address=$(nm -n "$kind-target" | awk '$3 == "target" { print $1; exit }')
    test -n "$first" && test -n "$second" && test -n "$limit" && test -n "$address"
    cat > "$kind-patch.cpp" <<EOF
#include <cstddef>
#include <cstdlib>
#include <new>
#include <string>
extern "C" {
extern std::string ref_0x${first}_first;
extern const std::size_t fix_size_0x${first}_first = sizeof(std::string);
extern const std::size_t fix_size_0x${second}_second = sizeof(std::string);
extern const std::size_t fix_priority_0x${first}_first = 1;
extern const std::size_t fix_priority_0x${second}_second = 2;
int fix_0x${limit}_limit = 100;
int fix_0x${address}_target() { return 7; }
void fix_0x${first}_first(void* storage) noexcept {
    auto* object = static_cast<std::string*>(storage);
    if (*object != "original first object with heap allocation") std::abort();
    object->~basic_string();
    new (storage) std::string("replacement first object with heap allocation");
}
void fix_0x${second}_second(void* storage) noexcept {
    auto* object = static_cast<std::string*>(storage);
    if (*object != "original second object with heap allocation" ||
        ref_0x${first}_first != "replacement first object with heap allocation") std::abort();
    // Assignment is another valid lifecycle strategy with the same object type.
    *object = "replacement second object with heap allocation";
}
}
EOF
    "$patcher" --cpp-runtime -p "$kind-patch.cpp" -i "$kind-target" -o "$kind-patched"
    "./$kind-patched"
done
cat > wrong-size.cpp <<EOF
#include <cstddef>
extern "C" {
extern const std::size_t fix_size_0x${first}_first = 1;
void fix_0x${first}_first(void*) noexcept {}
}
EOF
cat > missing-size.cpp <<EOF
extern "C" void fix_0x${first}_first(void*) noexcept {}
EOF
cat > wrong-kind.cpp <<EOF
#include <cstddef>
extern "C" {
extern const std::size_t fix_size_0x${address}_target = sizeof(int);
void fix_0x${address}_target(void*) noexcept {}
}
EOF
cat > mangled.cpp <<EOF
#include <cstddef>
extern "C" const std::size_t fix_size_0x${first}_first = sizeof(int);
void fix_0x${first}_first(void*) noexcept {}
EOF
for bad in wrong-size missing-size wrong-kind mangled; do
    if "$patcher" --cpp-runtime -p "$bad.cpp" -i pie-target -o "$bad-output" 2> "$bad.log"; then
        echo "invalid $bad lifecycle hook accepted" >&2
        exit 1
    fi
    test ! -e "$bad-output"
done
grep -q 'size must match the complete target object' wrong-size.log
grep -q 'Missing replacement size metadata' missing-size.log
grep -q 'writable ordinary storage' wrong-kind.log
grep -q 'require extern "C" linkage' mangled.log
