#!/bin/sh
set -eu

patcher=$1
case "$patcher" in
    /*) ;;
    *) patcher=$(cd "$(dirname "$patcher")" && pwd)/$(basename "$patcher") ;;
esac
test_dir=$(mktemp -d)
cpp_test_name=abi
. "$(dirname "$0")/diagnostics.sh"
trap 'cpp_fixture_cleanup $?' EXIT
cd "$test_dir"

cat > target.cpp <<'EOF'
#include <string>
__attribute__((noinline)) std::string transform(std::string input) {
    return input;
}
int main() { return transform("value") == "patched-value" ? 0 : 1; }
EOF

for kind in exec pie; do
    case "$kind" in
        exec) flags='-no-pie' ;;
        pie) flags='-fPIE -pie' ;;
    esac
    g++ $flags -O0 -g target.cpp -o "$kind-target"
    address=$(nm -n "$kind-target" |
        awk '$3 ~ /^_Z9transformNSt7__cxx1112basic_string/ { print $1; exit }')
    test -n "$address"
    cat > "$kind-patch.cpp" <<EOF
#include <string>
#include <unistd.h>
struct Shutdown { ~Shutdown() { (void)write(1, "done", 4); } } shutdown_hook;
extern "C" std::string fix_0x${address}_transform(std::string input) {
    return "patched-" + input;
}
EOF
    "$patcher" --cpp-runtime -p "$kind-patch.cpp" -i "$kind-target" \
        -o "$kind-patched"
    set +e
    result=$("./$kind-patched")
    status=$?
    set -e
    if test "$status" -ne 0 || test "$result" != done; then
        echo "$kind C++ ABI/destructor result: exit=$status output=$result (expected 0/done)" >&2
        exit 1
    fi
done
