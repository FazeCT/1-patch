#!/bin/sh
set -eu

patcher=$1
case "$patcher" in
    /*) ;;
    *) patcher=$(cd "$(dirname "$patcher")" && pwd)/$(basename "$patcher") ;;
esac

test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
cd "$test_dir"

cat > target.cpp <<'EOF'
#include <string>
namespace sample {
__attribute__((noinline)) int target(int value) { return value; }
__attribute__((noinline)) int target(double) { return 2; }
struct Box {
    static __attribute__((noinline)) int bonus(int value) { return value; }
};
}
int main() {
    std::string word = "x";
    return sample::target(3) + sample::target(1.5) +
           sample::Box::bonus(1) + static_cast<int>(word.size()) - 1;
}
EOF

for kind in exec pie; do
    case "$kind" in
        exec) g++ -no-pie -O0 -g target.cpp -o "$kind-target" ;;
        pie) g++ -fPIE -pie -O0 -g target.cpp -o "$kind-target" ;;
    esac
    address=$(nm -n "$kind-target" |
        awk '$3 ~ /^_ZN6sample6targetEi$/ { print $1; exit }')
    test -n "$address"
    static_address=$(nm -n "$kind-target" |
        awk '$3 == "_ZN6sample3Box5bonusEi" { print $1; exit }')
    test -n "$static_address"

    cat > "$kind-patch.cpp" <<EOF
namespace patch { constexpr int bonus = 1; }
extern "C" int fix_0x${address}_target(int value) {
    return value * 2 + patch::bonus;
}
extern "C" int fix_0x${static_address}_bonus(int value) {
    return value + 4;
}
EOF
    "$patcher" -p "$kind-patch.cpp" -i "$kind-target" -o "$kind-patched"
    set +e
    "./$kind-patched"
    result=$?
    set -e
    test "$result" -eq 14

    cat > "$kind-mangled.cpp" <<EOF
int fix_0x${address}_target(int value) { return value + 1; }
EOF
    if "$patcher" -p "$kind-mangled.cpp" -i "$kind-target" \
        -o "$kind-mangled-output" 2> "$kind-mangled.log"; then
        echo 'mangled C++ patch marker unexpectedly succeeded' >&2
        exit 1
    fi
    grep -q 'C++ patch markers require extern "C"' "$kind-mangled.log"
    test ! -e "$kind-mangled-output"
done

cat > global-constructor.cpp <<EOF
volatile int constructor_ran;
struct Global { Global() { constructor_ran = 1; } };
Global object;
extern "C" int fix_0x${address}_target(int value) { return value + 1; }
EOF
if "$patcher" -p global-constructor.cpp -i pie-target \
    -o constructor-output 2> constructor.log; then
    echo 'unsupported C++ global constructor unexpectedly succeeded' >&2
    exit 1
fi
grep -q 'unsupported startup or shutdown hook' constructor.log
test ! -e constructor-output

cat > runtime-import.cpp <<EOF
#include <string>
extern "C" int fix_0x${address}_target(int value) {
    std::string text("x");
    return value + static_cast<int>(text.size());
}
EOF
if "$patcher" -p runtime-import.cpp -i pie-target \
    -o runtime-import-output 2> runtime-import.log; then
    echo 'unsupported C++ runtime import unexpectedly succeeded' >&2
    exit 1
fi
grep -Eq 'unsupported runtime import|unsupported section|Unresolved patch function reference' runtime-import.log
test ! -e runtime-import-output
