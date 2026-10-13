#!/bin/sh
set -eu

patcher=$1
case "$patcher" in
    /*) ;;
    *) patcher=$(cd "$(dirname "$patcher")" && pwd)/$(basename "$patcher") ;;
esac
test_dir=$(mktemp -d)
cpp_test_name=refs
. "$(dirname "$0")/diagnostics.sh"
trap 'cpp_fixture_cleanup $?' EXIT
cd "$test_dir"

cat > target.cpp <<'EOF'
int bonus = 4;
int zero_bonus;
__attribute__((noinline)) int helper(int value) { return value * 2; }
__attribute__((noinline)) int target() { return 0; }
int main() { zero_bonus = 2; return target(); }
EOF

for kind in exec pie; do
    case "$kind" in
        exec) flags='-no-pie' ;;
        pie) flags='-fPIE -pie' ;;
    esac
    g++ $flags -O0 -g target.cpp -o "$kind-target"
    target_address=$(nm -n "$kind-target" |
        awk '$3 == "_Z6targetv" { print $1; exit }')
    helper_address=$(nm -n "$kind-target" |
        awk '$3 == "_Z6helperi" { print $1; exit }')
    bonus_address=$(nm -n "$kind-target" |
        awk '$3 == "bonus" { print $1; exit }')
    zero_address=$(nm -n "$kind-target" |
        awk '$3 == "zero_bonus" { print $1; exit }')
    test -n "$target_address" && test -n "$helper_address" &&
        test -n "$bonus_address" && test -n "$zero_address"
    cat > "$kind-patch.cpp" <<EOF
extern "C" int ref_0x${helper_address}_helper(int);
extern "C" int ref_0x${bonus_address}_bonus;
extern "C" int ref_0x${zero_address}_zero_bonus;
extern "C" int fix_0x${target_address}_target() {
    return ref_0x${helper_address}_helper(3) + ref_0x${bonus_address}_bonus +
           ref_0x${zero_address}_zero_bonus + 1;
}
EOF
    "$patcher" --cpp-runtime -p "$kind-patch.cpp" -i "$kind-target" \
        -o "$kind-patched"
    nm -D "$kind-patched" | grep -q "ref_0x${helper_address}_helper"
    nm -D "$kind-patched" | grep -q "ref_0x${bonus_address}_bonus"
    nm -D "$kind-patched" | grep -q "ref_0x${zero_address}_zero_bonus"
    set +e
    "./$kind-patched"
    result=$?
    set -e
    if test "$result" -ne 13; then
        echo "$kind C++ runtime ref result: $result (expected 13)" >&2
        exit 1
    fi
done

cat > mangled-ref.cpp <<EOF
int ref_0x${helper_address}_helper(int);
extern "C" int fix_0x${target_address}_target() {
    return ref_0x${helper_address}_helper(3);
}
EOF
if "$patcher" --cpp-runtime -p mangled-ref.cpp -i pie-target \
    -o mangled-output 2> mangled.log; then
    echo 'mangled runtime ref_ unexpectedly accepted' >&2
    exit 1
fi
grep -q 'C++ patch markers require extern "C" linkage' mangled.log
test ! -e mangled-output

cat > tls-ref.cpp <<EOF
extern "C" { extern thread_local int ref_0x${bonus_address}_bonus; }
extern "C" int fix_0x${target_address}_target() {
    return ref_0x${bonus_address}_bonus;
}
EOF
if "$patcher" --cpp-runtime -p tls-ref.cpp -i pie-target \
    -o tls-output 2> tls.log; then
    echo 'target TLS ref_ unexpectedly accepted' >&2
    exit 1
fi
grep -q 'Target TLS offset has no bounded TLS symbol' tls.log
test ! -e tls-output
