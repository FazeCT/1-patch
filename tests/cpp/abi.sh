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

cat > virtual.hpp <<'EOF'
struct Base {
    int base_value;
    virtual int score(int extra);
};
struct Derived : virtual Base {
    int value;
    int score(int extra) override;
};
EOF
cat > virtual.cpp <<'EOF'
#include "virtual.hpp"
int Base::score(int extra) { return base_value + extra; }
__attribute__((noinline)) int Derived::score(int extra) {
    return value + extra;
}
__attribute__((noinline)) int through_virtual_base(Base* base) {
    return base->score(3);
}
int main(int argc, char**) {
    Derived value{};
    value.value = 6;
    if (argc > 1) return value.Derived::score(2);
    return through_virtual_base(&value);
}
EOF

cat > covariant.hpp <<'EOF'
struct Left {
    virtual int marker();
    long left_value;
};
struct Right {
    virtual Right* self();
    long right_value;
};
struct Derived : Left, Right {
    int value;
    Derived* self() override;
};
EOF
cat > covariant.cpp <<'EOF'
#include "covariant.hpp"
int Left::marker() { return 0; }
Right* Right::self() { return this; }
__attribute__((noinline)) Derived* Derived::self() { return this; }
__attribute__((noinline)) Right* through_right(Right* right) {
    return right->self();
}
int main(int argc, char**) {
    Derived value{};
    value.value = 1;
    if (argc > 1) {
        Derived* returned = value.Derived::self();
        return returned == &value ? value.value : 100;
    }
    Right* right = &value;
    Right* returned = through_right(right);
    return returned == right ? value.value : 100;
}
EOF

for kind in exec pie; do
    case "$kind" in
        exec) flags='-no-pie' ;;
        pie) flags='-fPIE -pie' ;;
    esac

    g++ $flags -O0 -g virtual.cpp -o "$kind-virtual-target"
    address=$(nm -n "$kind-virtual-target" |
        awk '$3 == "_ZN7Derived5scoreEi" { print $1; exit }')
    test -n "$address"
    nm -C "$kind-virtual-target" | grep -q 'virtual thunk to Derived::score(int)'
    cat > "$kind-virtual-patch.cpp" <<EOF
#include "virtual.hpp"
extern "C" int fix_0x${address}_score(Derived* self, int extra) {
    return self->value + extra + 4;
}
EOF
    "$patcher" -p "$kind-virtual-patch.cpp" -i "$kind-virtual-target" \
        -o "$kind-virtual-patched"
    set +e
    "./$kind-virtual-patched"
    virtual_result=$?
    "./$kind-virtual-patched" direct
    direct_result=$?
    set -e
    if test "$virtual_result" -ne 13 || test "$direct_result" -ne 12; then
        echo "$kind virtual-base result: virtual=$virtual_result direct=$direct_result" >&2
        exit 1
    fi

    g++ $flags -O0 -g covariant.cpp -o "$kind-covariant-target"
    address=$(nm -n "$kind-covariant-target" |
        awk '$3 == "_ZN7Derived4selfEv" { print $1; exit }')
    test -n "$address"
    nm -C "$kind-covariant-target" | grep -q 'covariant return thunk to Derived::self()'
    cat > "$kind-covariant-patch.cpp" <<EOF
#include "covariant.hpp"
extern "C" Derived* fix_0x${address}_self(Derived* self) {
    self->value = 7;
    return self;
}
EOF
    "$patcher" -p "$kind-covariant-patch.cpp" -i "$kind-covariant-target" \
        -o "$kind-covariant-patched"
    set +e
    "./$kind-covariant-patched"
    virtual_result=$?
    "./$kind-covariant-patched" direct
    direct_result=$?
    set -e
    if test "$virtual_result" -ne 7 || test "$direct_result" -ne 7; then
        echo "$kind covariant result: virtual=$virtual_result direct=$direct_result" >&2
        exit 1
    fi
done
