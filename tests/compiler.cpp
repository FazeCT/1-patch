#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <set>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "../src/compiler.hpp"

namespace fs = std::filesystem;

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

void write_file(const fs::path& path, const std::string& contents) {
    std::ofstream out(path);
    out << contents;
    require(static_cast<bool>(out), "failed to write test fixture");
}

void require_no_build_directories(const fs::path& temp_root) {
    for (const auto& entry : fs::directory_iterator(temp_root)) {
        require(entry.path().filename().string().find("1-patch-") != 0,
                "temporary build directory was not removed");
    }
}

int main() {
    std::string template_path = (fs::temp_directory_path() / "1-patch-tests-XXXXXX").string();
    std::vector<char> template_chars(template_path.begin(), template_path.end());
    template_chars.push_back('\0');
    char* created = mkdtemp(template_chars.data());
    require(created != nullptr, "failed to make test directory");
    const fs::path test_root(created);
    const fs::path old_cwd = fs::current_path();
    const char* old_tmpdir = getenv("TMPDIR");
    const bool had_tmpdir = old_tmpdir != nullptr;
    const std::string saved_tmpdir = old_tmpdir ? old_tmpdir : "";
    const char* old_path = getenv("PATH");
    const std::string saved_path = old_path ? old_path : "";

    try {
        const fs::path temp_root = test_root / "temp area";
        fs::create_directory(temp_root);
        fs::current_path(test_root);
        setenv("TMPDIR", temp_root.c_str(), 1);

        const fs::path shell_name = test_root / "patch $(touch marker).c";
        write_file(shell_name, "int main(void) { return 0; }\n");
        {
            CompiledPatch patch = compile(shell_name.string());
            require(fs::exists(patch.binary_path()), "GCC did not produce a binary");
            struct stat info {};
            require(stat(fs::path(patch.binary_path()).parent_path().c_str(), &info) == 0,
                    "missing private build directory");
            require((info.st_mode & 0777) == 0700, "build directory is not private");
        }
        require(!fs::exists(test_root / "marker"), "patch filename executed shell syntax");
        require_no_build_directories(temp_root);

        write_file(test_root / "-patch.c", "int main(void) { return 0; }\n");
        {
            CompiledPatch patch = compile("-patch.c");
            require(fs::exists(patch.binary_path()), "leading-dash filename was treated as an option");
        }
        require_no_build_directories(temp_root);

        const fs::path without_main = test_root / "without main.c";
        write_file(without_main, "int fix_0x1234(void) { return 1; }\n");
        {
            CompiledPatch patch = compile(without_main.string());
            require(fs::exists(patch.binary_path()), "missing-main retry failed");
        }
        require_no_build_directories(temp_root);

        std::string many_variables;
        for (int i = 0; i < 40; ++i) {
            many_variables += "int test_var_" + std::to_string(i) + " = " +
                              std::to_string(i) + ";\n";
        }
        many_variables += "int main(void) { return test_var_39; }\n";
        const fs::path many_variables_source = test_root / "many-variables.c";
        write_file(many_variables_source, many_variables);
        {
            CompiledPatch patch = compile(many_variables_source.string());
            DWARFResolver resolver(patch.binary_path());
            resolver.resolve("test_var_39");
            resolver.resolve("test_var_0");
        }
        require_no_build_directories(temp_root);

        const fs::path fake_bin = test_root / "fake-bin";
        fs::create_directory(fake_bin);
        const fs::path fake_gcc = fake_bin / "gcc";
        write_file(fake_gcc, "#!/bin/sh\nexit 42\n");
        require(chmod(fake_gcc.c_str(), 0755) == 0, "failed to make fake GCC executable");
        setenv("PATH", (fake_bin.string() + ":" + saved_path).c_str(), 1);
        bool rejected = false;
        try {
            CompiledPatch patch = compile(shell_name.string());
        } catch (const std::runtime_error&) {
            rejected = true;
        }
        require(rejected, "silent nonzero GCC exit was accepted");
        require_no_build_directories(temp_root);

        write_file(fake_gcc,
                   "#!/bin/sh\n"
                   "dd if=/dev/zero bs=1048576 count=2 2>/dev/null\n"
                   "exit 42\n");
        const CompilerResult large_output = run_gcc(shell_name.string(),
                                                    (test_root / "unused-output").string());
        require(large_output.status == 42, "large GCC output hid its exit status");
        require(large_output.output.size() < 1100000 &&
                large_output.output.find("[compiler output truncated]") != std::string::npos,
                "GCC output was not bounded and drained");
        setenv("PATH", saved_path.c_str(), 1);

        ReferenceMap references;
        extract_references({0xff, 0xe0, 0xff, 0x20, 0xc3}, 0x1000, references);
        require(references.get_references().empty(), "indirect branches got fabricated destinations");

        std::set<std::string> section_names;
        for (int i = 0; i < 100; ++i) {
            section_names.insert(generate_random_string());
        }
        require(section_names.size() == 100, "new section names collided");

        fs::current_path(old_cwd);
        if (had_tmpdir) setenv("TMPDIR", saved_tmpdir.c_str(), 1);
        else unsetenv("TMPDIR");
        fs::remove_all(test_root);
        std::cout << "compiler and reference tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        fs::current_path(old_cwd);
        setenv("PATH", saved_path.c_str(), 1);
        if (had_tmpdir) setenv("TMPDIR", saved_tmpdir.c_str(), 1);
        else unsetenv("TMPDIR");
        fs::remove_all(test_root);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
