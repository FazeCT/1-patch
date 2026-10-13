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
struct Base {
    virtual int score(int extra) { return extra; }
};

struct Widget : Base {
    int value;
    int score(int extra) override;
};

__attribute__((noinline)) int Widget::score(int extra) {
    return value + extra;
}

__attribute__((noinline)) int through_vtable(Base* base, int extra) {
    return base->score(extra);
}

int main(int argc, char**) {
    Widget widget{};
    widget.value = 6;
    if (argc > 1) return widget.Widget::score(2);
    return through_vtable(&widget, 3);
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
            awk '$3 == "_ZN6Widget5scoreEi" { print $1; exit }')
        test -n "$address"

        set +e
        "./$name-target"
        original_virtual=$?
        "./$name-target" direct
        original_direct=$?
        set -e
        test "$original_virtual" -eq 9
        test "$original_direct" -eq 8

        cat > "$name-patch.cpp" <<EOF
struct WidgetView { void* vptr; int value; };

extern "C" int fix_0x${address}_score(WidgetView* self, int extra) {
    int result = self->value + extra + 4;
    volatile int barrier = extra;
    if (barrier < 0) result -= 100;
    return result;
}
EOF
        "$patcher" -v -p "$name-patch.cpp" -i "$name-target" \
            -o "$name-patched" > "$name.log"
        # The replacement is deliberately larger than the original method.
        # Its virtual callers must therefore use the old entry trampoline.
        grep -q 'Added .text' "$name.log"
        if grep -q 'Replaced function in place' "$name.log"; then
            echo "virtual-method fixture unexpectedly used in-place patching" >&2
            exit 1
        fi

        set +e
        "./$name-patched"
        virtual_result=$?
        "./$name-patched" direct
        direct_result=$?
        set -e
        if test "$virtual_result" -ne 13 || test "$direct_result" -ne 12; then
            echo "$name: expected virtual=13 and direct=12; got virtual=$virtual_result direct=$direct_result" >&2
            exit 1
        fi

        objdump --disassemble=_ZN6Widget5scoreEi "$name-patched" > "$name-entry.txt"
        grep -q 'jmp' "$name-entry.txt"
        if test "$cet" = branch; then
            grep -q 'endbr64' "$name-entry.txt"
        fi
    done
done

# An optimized virtual method can be shorter than a five-byte entry jump.
# Its vtable would continue calling the old body, so no patched output is safe.
cat > short.cpp <<'EOF'
struct ShortBase {
    virtual int score(int extra);
};

__attribute__((noinline)) int ShortBase::score(int) { return 0; }

__attribute__((noinline)) int through_short_vtable(ShortBase* base) {
    return base->score(2);
}

int main() {
    ShortBase value;
    return through_short_vtable(&value);
}
EOF

for kind in exec pie; do
    case "$kind" in
        exec) g++ -no-pie -O2 -g -fcf-protection=none short.cpp -o "$kind-short" ;;
        pie) g++ -fPIE -pie -O2 -g -fcf-protection=none short.cpp -o "$kind-short" ;;
    esac
    address=$(nm -n "$kind-short" |
        awk '$3 == "_ZN9ShortBase5scoreEi" { print $1; exit }')
    size=$(nm -S "$kind-short" |
        awk '$4 == "_ZN9ShortBase5scoreEi" { print $2; exit }')
    test -n "$address"
    test -n "$size"
    test "$((0x$size))" -lt 5

    cat > "$kind-short-patch.cpp" <<EOF
extern "C" int fix_0x${address}_score(void*, int) { return 7; }
EOF
    if "$patcher" -p "$kind-short-patch.cpp" -i "$kind-short" \
        -o "$kind-short-patched" 2> "$kind-short.log"; then
        echo "$kind short virtual method unexpectedly produced a partial patch" >&2
        exit 1
    fi
    grep -q 'indirect callers retain the original entry' "$kind-short.log"
    test ! -e "$kind-short-patched"
done
