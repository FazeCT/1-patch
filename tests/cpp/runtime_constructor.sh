#!/bin/sh
set -eu
patcher=$1
case "$patcher" in /*) ;; *) patcher=$(cd "$(dirname "$patcher")" && pwd)/$(basename "$patcher") ;; esac
test_dir=$(mktemp -d)
cpp_test_name=constructor
. "$(dirname "$0")/diagnostics.sh"
trap 'cpp_fixture_cleanup $?' EXIT
cd "$test_dir"

cat > target.cpp <<'EOF'
extern "C" __attribute__((noinline)) int target() { return 1; }
int main() { return target() == 23 ? 0 : 1; }
EOF
for kind in exec pie; do
    case "$kind" in exec) flags='-no-pie -fcf-protection=none' ;; pie) flags='-fPIE -pie -fcf-protection=full' ;; esac
    g++ $flags -O0 -g -rdynamic target.cpp -o "$kind-target"
    address=$(nm -n "$kind-target" | awk '$3 == "target" { print $1; exit }')
    test -n "$address"
    cat > "$kind-patch.cpp" <<EOF
#include <cstdlib>
extern "C" int target();
int constructed = 0;
extern "C" int fix_0x${address}_target() { return constructed ? 23 : 17; }
struct Startup {
    Startup() {
        // Goes through the executable's old entry while dlopen is running.
        if (target() != 17) std::abort();
        constructed = 1;
    }
} startup;
EOF
    "$patcher" --cpp-runtime -p "$kind-patch.cpp" -i "$kind-target" -o "$kind-patched"
    "./$kind-patched"
done
