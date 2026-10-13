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
#include <cstdint>

struct Left {
    virtual int left() { return 1; }
    std::uint64_t left_data = 0;
};

struct Right {
    virtual int score(int extra);
    std::uint64_t right_data = 0;
};

int Right::score(int extra) { return extra; }

struct Derived : Left, Right {
    std::uint64_t value = 6;
    int score(int extra) override;
};

__attribute__((noinline)) int Derived::score(int extra) {
    return static_cast<int>(value) + extra;
}

__attribute__((noinline)) int through_secondary_base(Right* right) {
    return right->score(3);
}

int main(int argc, char**) {
    Derived value;
    if (argc > 1) return value.Derived::score(2);
    return through_secondary_base(&value);
}
EOF

for kind in exec pie; do
    for cet in none branch; do
        name="$kind-$cet"
        case "$kind" in
            exec) g++ -no-pie -O0 -g -fcf-protection="$cet" target.cpp -o "$name-target" ;;
            pie) g++ -fPIE -pie -O0 -g -fcf-protection="$cet" target.cpp -o "$name-target" ;;
        esac
        address=$(nm -n "$name-target" |
            awk '$3 == "_ZN7Derived5scoreEi" { print $1; exit }')
        test -n "$address"
        nm -n "$name-target" | grep -Eq '_ZThn[0-9]+_N7Derived5scoreEi$'

        set +e
        "./$name-target"
        original_virtual=$?
        "./$name-target" direct
        original_direct=$?
        set -e
        test "$original_virtual" -eq 9
        test "$original_direct" -eq 8

        cat > "$name-patch.cpp" <<EOF
#include <cstdint>
struct DerivedView {
    void* left_vptr;
    std::uint64_t left_data;
    void* right_vptr;
    std::uint64_t right_data;
    std::uint64_t value;
};

extern "C" int fix_0x${address}_score(DerivedView* self, int extra) {
    int result = static_cast<int>(self->value) + extra + 4;
    volatile int barrier = extra;
    if (barrier < 0) result -= 100;
    return result;
}
EOF
        "$patcher" -p "$name-patch.cpp" -i "$name-target" -o "$name-patched"
        set +e
        "./$name-patched"
        virtual_result=$?
        "./$name-patched" direct
        direct_result=$?
        set -e
        if test "$virtual_result" -ne 13 || test "$direct_result" -ne 12; then
            echo "$name: secondary-base virtual=$virtual_result direct=$direct_result" >&2
            exit 1
        fi
    done
done
