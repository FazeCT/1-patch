#!/bin/sh
set -eu

patcher=$1
case "$patcher" in
    /*) ;;
    *) patcher=$(cd "$(dirname "$patcher")" && pwd)/$(basename "$patcher") ;;
esac
test_dir=$(mktemp -d)
cpp_test_name=runtime
. "$(dirname "$0")/diagnostics.sh"
trap 'cpp_fixture_cleanup $?' EXIT
cd "$test_dir"

cat > target.cpp <<'EOF'
__attribute__((noinline)) int target(int value) { return value; }
EOF
cat > caller.cpp <<'EOF'
#include <stdexcept>
extern int target(int value);
int main(int argc, char**) {
    if (argc > 1) return target(1);
    try { return target(3); }
    catch (const std::runtime_error&) { return target(1); }
}
EOF

for kind in exec pie; do
    case "$kind" in
        exec) flags='-no-pie' ;;
        pie) flags='-fPIE -pie' ;;
    esac
    # Compile the caller separately: a visible trivial definition can let GCC
    # prove the call cannot throw and remove the catch before patching.
    g++ $flags -O0 -g target.cpp caller.cpp -o "$kind-target"
    readelf -SW "$kind-target" | grep -q '\.gcc_except_table'
    address=$(nm -n "$kind-target" |
        awk '$3 == "_Z6targeti" { print $1; exit }')
    test -n "$address"

    cat > "$kind-patch.cpp" <<EOF
#include <stdexcept>
#include <string>
struct Base { virtual ~Base() = default; };
struct Derived : Base {};
thread_local int local_bonus = 4;
int constructed = 0;
struct Startup { Startup() { constructed = 5; } } startup;
extern "C" int fix_0x${address}_target(int value) {
    Derived derived;
    Base* base = &derived;
    if (!dynamic_cast<Derived*>(base)) return 90;
    if (value == 3) throw std::runtime_error("patched");
    std::string text = "abc";
    return value + local_bonus + constructed + static_cast<int>(text.size());
}
EOF
    "$patcher" --cpp-runtime -p "$kind-patch.cpp" -i "$kind-target" \
        -o "$kind-patched"
    test -f "$kind-patched"
    readelf -d "$kind-patched" | grep -q '(INIT)'
    set +e
    "./$kind-patched" normal
    normal_result=$?
    "./$kind-patched"
    result=$?
    set -e
    if test "$normal_result" -ne 13 || test "$result" -ne 13; then
        echo "$kind C++ runtime result: normal=$normal_result exception=$result (expected 13/13)" >&2
        exit 1
    fi
done
