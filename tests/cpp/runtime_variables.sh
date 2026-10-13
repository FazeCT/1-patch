#!/bin/sh
set -eu
patcher=$1
case "$patcher" in
    /*) ;;
    *) patcher=$(cd "$(dirname "$patcher")" && pwd)/$(basename "$patcher") ;;
esac
test_dir=$(mktemp -d)
cpp_test_name=variables
. "$(dirname "$0")/diagnostics.sh"
trap 'cpp_fixture_cleanup $?' EXIT
cd "$test_dir"

cat > data.hpp <<'EOF'
struct Inner { short left; short right; };
struct Record { int first; Inner inner; unsigned char bytes[3]; };
EOF
cat > target.cpp <<'EOF'
#include "data.hpp"
#include <string>
extern "C" {
int number = 1;
int zero;
unsigned char bytes[4] = {1, 2, 3, 4};
Record record = {2, {1, 2}, {1, 2, 3}};
extern const int readonly = 5;
std::string guarded = "safe";
}
__attribute__((noinline)) int target() { return 1; }
int main() {
    int first = target();
    int second = target();
    return first == 50 && second == 55 && number == 9 && zero == 10 &&
        bytes[0] == 11 && bytes[1] == 10 && bytes[2] == 11 && bytes[3] == 12 &&
        record.first == 15 && record.inner.left == 14 && record.inner.right == 15 &&
        record.bytes[0] == 16 && record.bytes[1] == 17 && record.bytes[2] == 18 &&
        guarded == "safe" ? 0 : 1;
}
EOF

for kind in exec pie; do
    case "$kind" in
        exec) flags='-no-pie' ;;
        pie) flags='-fPIE -pie' ;;
    esac
    g++ $flags -O0 -g target.cpp -o "$kind-target"
    target_address=$(nm -n "$kind-target" | awk '$3 == "_Z6targetv" { print $1; exit }')
    number_address=$(nm -n "$kind-target" | awk '$3 == "number" { print $1; exit }')
    zero_address=$(nm -n "$kind-target" | awk '$3 == "zero" { print $1; exit }')
    bytes_address=$(nm -n "$kind-target" | awk '$3 == "bytes" { print $1; exit }')
    record_address=$(nm -n "$kind-target" | awk '$3 == "record" { print $1; exit }')
    readonly_address=$(nm -n "$kind-target" | awk '$3 == "readonly" { print $1; exit }')
    guarded_address=$(nm -n "$kind-target" | awk '$3 == "guarded" { print $1; exit }')
    test -n "$target_address" && test -n "$number_address" && test -n "$zero_address" &&
        test -n "$bytes_address" && test -n "$record_address" && test -n "$readonly_address" &&
        test -n "$guarded_address"
    cat > "$kind-patch.cpp" <<EOF
#include "data.hpp"
#include <string>
extern "C" {
int fix_0x${number_address}_number = 7;
int fix_0x${zero_address}_zero = 8;
unsigned char fix_0x${bytes_address}_bytes[4] = {9, 10, 11, 12};
Record fix_0x${record_address}_record = {13, {14, 15}, {16, 17, 18}};
extern int ref_0x${number_address}_number;
int add_counter = 3;
std::string add_message = "ready";
thread_local int add_thread_counter = 1;
int fix_0x${target_address}_target() {
    if (&fix_0x${number_address}_number != &ref_0x${number_address}_number) return 90;
    ++fix_0x${number_address}_number;
    ++fix_0x${zero_address}_zero;
    ++fix_0x${bytes_address}_bytes[0];
    ++fix_0x${record_address}_record.first;
    ++add_counter;
    if (add_thread_counter != 1) return 91;
    return fix_0x${number_address}_number + fix_0x${zero_address}_zero +
        fix_0x${bytes_address}_bytes[0] + fix_0x${record_address}_record.first +
        add_counter + static_cast<int>(add_message.size());
}
}
EOF
    "$patcher" --cpp-runtime -p "$kind-patch.cpp" -i "$kind-target" -o "$kind-patched"
    "./$kind-patched"
done

cat > bad-size.cpp <<EOF
extern "C" char fix_0x${number_address}_number[5] = {};
EOF
cat > bad-layout.cpp <<EOF
extern "C" float fix_0x${number_address}_number = 1.0f;
EOF
cat > readonly.cpp <<EOF
extern "C" int fix_0x${readonly_address}_readonly = 9;
EOF
cat > nontrivial.cpp <<EOF
#include <string>
extern "C" std::string fix_0x${guarded_address}_guarded = "replacement";
EOF
cat > disguised.cpp <<EOF
extern "C" unsigned char fix_0x${guarded_address}_guarded[sizeof(void*) * 4] = {};
EOF
for bad in bad-size bad-layout readonly nontrivial disguised; do
    if "$patcher" --cpp-runtime -p "$bad.cpp" -i pie-target -o "$bad-output" 2> "$bad.log"; then
        echo "$bad runtime variable fix unexpectedly accepted" >&2
        exit 1
    fi
    test ! -e "$bad-output"
done
grep -q 'complete target size' bad-size.log
grep -q 'data layout does not match target' bad-layout.log
grep -q 'writable ordinary target storage' readonly.log
grep -q 'data-only type' nontrivial.log
grep -q 'data-only type' disguised.log

# A variable-only patch must initialize target storage without function slots.
cat > solo.cpp <<'EOF'
extern "C" { int solo = 1; }
int main() { return solo; }
EOF
g++ -fPIE -pie -g solo.cpp -o solo-target
solo_address=$(nm -n solo-target | awk '$3 == "solo" { print $1; exit }')
test -n "$solo_address"
cat > solo-patch.cpp <<EOF
__attribute__((noinline)) int initial_value() { return 17; }
extern "C" int fix_0x${solo_address}_solo = initial_value();
EOF
"$patcher" --cpp-runtime -p solo-patch.cpp -i solo-target -o solo-patched
set +e
./solo-patched
status=$?
set -e
test "$status" -eq 17

cp solo-target no-debug-target
strip --strip-debug no-debug-target
if "$patcher" --cpp-runtime -p solo-patch.cpp -i no-debug-target -o no-debug-output 2> no-debug.log; then
    echo 'unverified target variable layout unexpectedly accepted' >&2
    exit 1
fi
test ! -e no-debug-output
grep -Eq 'DWARF type information|Missing runtime variable type' no-debug.log
