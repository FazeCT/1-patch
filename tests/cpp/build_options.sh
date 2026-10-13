#!/bin/sh
set -eu
patcher=$1
case "$patcher" in /*) ;; *) patcher=$(cd "$(dirname "$patcher")" && pwd)/$(basename "$patcher") ;; esac
test_dir=$(mktemp -d)
cpp_test_name=build-options
. "$(dirname "$0")/diagnostics.sh"
trap 'cpp_fixture_cleanup $?' EXIT
cd "$test_dir"
mkdir 'include space' 'library space'
cat > 'include space/options.hpp' <<'EOF'
#ifndef PATCH_BONUS
#error Missing patch preprocessor definition
#endif
template<class T> int bonus(T) { return PATCH_BONUS; }
#if __cplusplus >= 202002L
template<class T> concept Numeric = requires(T value) { value + 1; };
static_assert(Numeric<int>);
#endif
EOF
cat > extra.cpp <<'EOF'
int extra() { return 7; }
EOF
cat > support.cpp <<'EOF'
int support() { return 11; }
EOF
cat > target.cpp <<'EOF'
#include <string>
__attribute__((noinline)) int target(std::string text) { return static_cast<int>(text.size()) + 1; }
EOF
cat > caller.cpp <<'EOF'
#include <string>
extern int target(std::string);
int main() { return target("abc") == 27 ? 0 : 1; }
EOF

for cxx in g++ clang++; do
    if ! command -v "$cxx" >/dev/null 2>&1; then
        echo "Compiler matrix: $cxx unavailable; skipped"
        continue
    fi
    last_cxx=$cxx
    for abi in 0 1; do
        for standard in c++11 c++17 c++20; do
            kind="${cxx}-${abi}-${standard}"
            echo "Compiler matrix: $kind"
            "$cxx" -fPIC -D_GLIBCXX_USE_CXX11_ABI="$abi" -c support.cpp -o support.o
            ar rcs 'library space/libsupport.a' support.o
            "$cxx" -fPIE -pie -O0 -g -std="$standard" -D_GLIBCXX_USE_CXX11_ABI="$abi" \
                target.cpp caller.cpp -o "$kind-target"
            address=$(nm -n "$kind-target" | awk '$3 ~ /^_Z6target/ { print $1; exit }')
            test -n "$address"
            cat > "$kind-patch.cpp" <<EOF
#include <string>
#include "options.hpp"
int extra();
int support();
extern "C" int ref_0x${address}_original(std::string);
extern "C" int fix_0x${address}_target(std::string text) {
    return ref_0x${address}_original(text) + extra() + support() + bonus(1);
}
EOF
            "$patcher" --cpp-runtime --cxx "$cxx" --std "$standard" \
                -I 'include space' -DPATCH_BONUS=5 --define "_GLIBCXX_USE_CXX11_ABI=$abi" \
                --source extra.cpp -L 'library space' -lsupport \
                -p "$kind-patch.cpp" -i "$kind-target" -o "$kind-patched"
            "./$kind-patched"
        done
    done
done

# Direct archive paths and attached -I/-L forms also work, including spaces.
"$patcher" --cpp-runtime --cxx "$last_cxx" --std=c++20 "-Iinclude space" \
    --define PATCH_BONUS=5 --define _GLIBCXX_USE_CXX11_ABI=1 --source extra.cpp \
    --link-file 'library space/libsupport.a' \
    -p "$kind-patch.cpp" -i "$kind-target" -o linked-patched
./linked-patched
for invalid in standard define library; do
    case "$invalid" in
        standard) set -- --std c++invalid ;;
        define) set -- --define 'INVALID NAME=1' ;;
        library) set -- --library 'bad/name' ;;
    esac
    set +e
    "$patcher" --cpp-runtime "$@" -p "$kind-patch.cpp" -i "$kind-target" \
        -o "$invalid-output" > "$invalid.log" 2>&1
    status=$?
    set -e
    test "$status" -eq 2
    test ! -e "$invalid-output"
done
