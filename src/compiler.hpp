#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <stdlib.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "utils.hpp"

#ifndef COMPILER_HPP
#define COMPILER_HPP

struct CompilerResult {
    int status;
    std::string output;
};

enum class PatchLanguage {
    C,
    Cpp
};

struct PatchCompilerOptions {
    std::string cxx = "g++";
    std::string standard;
    std::vector<std::string> include_directories;
    std::vector<std::string> definitions;
    std::vector<std::string> library_directories;
    std::vector<std::string> libraries;
    std::vector<std::string> link_files;
    std::vector<std::string> sources;
};

PatchLanguage patch_language(const std::string& input_path) {
    const std::string extension = std::filesystem::path(input_path).extension().string();

    if (extension == ".c")
        return PatchLanguage::C;

    if (extension == ".cpp" || extension == ".cc" || extension == ".cxx")
        return PatchLanguage::Cpp;

    throw std::runtime_error("Patch file must have a .c, .cpp, .cc, or .cxx extension");
}

CompilerResult run_compiler(const std::string& input_path, const std::string& output_path, PatchLanguage language, const std::string& source_directory = "", bool shared_object = false, bool ibt_plt = false, const PatchCompilerOptions& options = {}, const std::vector<std::string>& generated_sources = {}, const std::string& library_initializer = "") {
    const std::string absolute_input = std::filesystem::absolute(input_path).string();
    const std::string compiler = language == PatchLanguage::Cpp ? options.cxx : "gcc";
    std::vector<std::string> args = {compiler, "-w", "-fcf-protection=full"};

    if (!shared_object)
        args.push_back("-fno-stack-protector");

    if (language == PatchLanguage::Cpp && !shared_object) {
        args.push_back("-fno-exceptions");
        args.push_back("-fno-rtti");
    }

    if (shared_object) {
        args.push_back("-shared");
        args.push_back("-fPIC");
    }

    if (ibt_plt)
        args.push_back("-Wl,-z,ibtplt");

    if (!source_directory.empty()) {
        args.push_back("-I");
        args.push_back(source_directory);
    }

    if (language == PatchLanguage::Cpp && !options.standard.empty())
        args.push_back("-std=" + options.standard);

    for (const auto& path : options.include_directories) {
        args.push_back("-I" + std::filesystem::absolute(path).string());
    }

    for (const auto& definition : options.definitions) {
        args.push_back("-D" + definition);
    }

    args.push_back(absolute_input);

    for (const auto& source : options.sources) {
        args.push_back(std::filesystem::absolute(source).string());
    }

    for (const auto& source : generated_sources) {
        args.push_back(std::filesystem::absolute(source).string());
    }

    for (const auto& file : options.link_files) {
        args.push_back(std::filesystem::absolute(file).string());
    }

    for (const auto& path : options.library_directories) {
        args.push_back("-L" + std::filesystem::absolute(path).string());
    }

    for (const auto& library : options.libraries) {
        args.push_back("-l" + library);
    }

    if (!library_initializer.empty())
        args.push_back("-Wl,-init," + library_initializer);

    args.insert(args.end(), {"-o", output_path, "-g"});

    // Older glibc releases provide dlopen/dlsym in libdl rather than libc
    if (ibt_plt)
        args.push_back("-ldl");

    std::vector<char*> argv;

    for (auto& argument : args) {
        argv.push_back(argument.data());
    }

    argv.push_back(nullptr);

    int output_pipe[2];

    if (pipe(output_pipe) != 0) {
        throw std::runtime_error("Failed to create compiler pipe");
    }

    pid_t child = fork();

    if (child < 0) {
        close(output_pipe[0]);
        close(output_pipe[1]);
        throw std::runtime_error("Failed to start GCC");
    }

    if (child == 0) {
        close(output_pipe[0]);
        if (dup2(output_pipe[1], STDOUT_FILENO) < 0 || dup2(output_pipe[1], STDERR_FILENO) < 0) {
            _exit(127);
        }

        close(output_pipe[1]);
        execvp(compiler.c_str(), argv.data());

        static constexpr char message[] = "Failed to execute compiler\n";
        const ssize_t diagnostic_written = write(STDERR_FILENO, message, sizeof(message) - 1);

        (void)diagnostic_written;
        _exit(127);
    }

    close(output_pipe[1]);

    std::string output;
    constexpr size_t max_output_bytes = 1 << 20;
    bool truncated = false;
    char buffer[4096];
    bool read_failed = false;

    while (true) {
        const ssize_t count = read(output_pipe[0], buffer, sizeof(buffer));

        if (count > 0) {
            const size_t available = max_output_bytes - output.size();
            const size_t received = static_cast<size_t>(count);

            output.append(buffer, std::min(available, received));
            truncated |= received > available;
        } else if (count == 0) {
            break;
        } else if (errno != EINTR) {
            read_failed = true;
            break;
        }
    }

    close(output_pipe[0]);

    int status = 0;

    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            throw std::runtime_error("Failed to wait for GCC");
        }
    }

    if (read_failed) {
        throw std::runtime_error("Failed to read GCC output");
    }

    if (truncated)
        output += "\n[compiler output truncated]\n";

    return {WIFEXITED(status) ? WEXITSTATUS(status) : 128, output};
}

void compile_cpp_shared_object(const std::string& source, const std::string& output, const PatchCompilerOptions& options = {}, const std::vector<std::string>& generated_sources = {}, const std::string& initializer = "") {
    const auto directory = std::filesystem::absolute(source).parent_path().string();
    CompilerResult result = run_compiler(source, output, PatchLanguage::Cpp, directory, true, true, options, generated_sources, initializer);

    if (result.status != 0) {
        if (!result.output.empty())
            std::cerr << result.output;

        throw std::runtime_error("C++ shared-object compilation failed");
    }
}

CompilerResult run_gcc(const std::string& input_path, const std::string& output_path) {
    return run_compiler(input_path, output_path, PatchLanguage::C);
}

void exec_compile(const std::string& input_path, const std::string& output_path, const std::string& source_directory = "", bool ibt_plt = false, const PatchCompilerOptions& options = {}) {
    if (!std::filesystem::exists(input_path)) {
        verbose_print::print_red("Patch file does not exist: " + input_path);
        throw std::runtime_error("Compilation failed");
    }

    if (!std::filesystem::is_regular_file(input_path)) {
        verbose_print::print_red("Patch file is not a regular file: " + input_path);
        throw std::runtime_error("Compilation failed");
    }

    const PatchLanguage language = patch_language(input_path);

    const CompilerResult result = run_compiler(input_path, output_path, language, source_directory, false, ibt_plt, options);

    if (result.status == 0) {
        return;
    }

    if (result.output.find("undefined reference to `main'") != std::string::npos || result.output.find("undefined reference to 'main'") != std::string::npos) {
        throw std::runtime_error("Missing main() function");
    }

    if (!result.output.empty()) {
        std::cerr << result.output;
    }

    throw std::runtime_error("Compilation failed");
}

// Owns the private build directory until every patching phase is finished
class CompiledPatch {
public:
    CompiledPatch(std::filesystem::path directory, PatchLanguage language) : directory_(std::move(directory)), language_(language) {}

    CompiledPatch(const CompiledPatch&) = delete;
    CompiledPatch& operator=(const CompiledPatch&) = delete;

    CompiledPatch(CompiledPatch&& other) noexcept : directory_(std::move(other.directory_)), language_(other.language_) {
        other.directory_.clear();
    }

    ~CompiledPatch() {
        if (!directory_.empty()) {
            std::error_code error;

            std::filesystem::remove_all(directory_, error);
        }
    }

    std::string binary_path() const {
        return (directory_ / "patch").string();
    }

    std::filesystem::path source_path() const {
        return directory_ / (language_ == PatchLanguage::Cpp ? "patch-with-main.cpp" : "patch-with-main.c");
    }

    PatchLanguage language() const {
        return language_;
    }

private:
    std::filesystem::path directory_;
    PatchLanguage language_;
};

CompiledPatch compile(const std::string& input_path, bool ibt_plt = false, const PatchCompilerOptions& options = {}) {
    const PatchLanguage language = patch_language(input_path);
    const std::string source_directory = std::filesystem::absolute(input_path).parent_path().string();
    std::filesystem::path temp_dir;

    try {
        temp_dir = std::filesystem::temp_directory_path();
    } catch (const std::filesystem::filesystem_error&) {
        verbose_print::print_red("Failed to find temp directory");
        throw std::runtime_error("Compilation failed");
    }

    std::string template_path = (temp_dir / "1-patch-XXXXXX").string();
    std::vector<char> directory_name(template_path.begin(), template_path.end());

    directory_name.push_back('\0');

    char* created = mkdtemp(directory_name.data());

    if (!created) {
        throw std::runtime_error("Failed to create private temporary directory");
    }

    CompiledPatch patch(created, language);

    try {
        exec_compile(input_path, patch.binary_path(), source_directory, ibt_plt, options);
    } catch (const std::runtime_error& error) {
        if (std::string(error.what()) != "Missing main() function") {
            verbose_print::print_red("Failed to compile " + input_path);
            throw;
        }

        std::ifstream original_file(input_path, std::ios::binary);

        if (!original_file) {
            throw std::runtime_error("Failed to open patch source: " + input_path);
        }

        std::ofstream source(patch.source_path(), std::ios::binary | std::ios::trunc);

        if (!source) {
            throw std::runtime_error("Failed to create temporary patch source");
        }

        source << original_file.rdbuf() << "\nint main() { return 0; }\n";
        source.close();
        if (!source) {
            throw std::runtime_error("Failed to write temporary patch source");
        }

        verbose_print::print_yellow("Missing main() function in " + input_path + ", added main()");
        exec_compile(patch.source_path().string(), patch.binary_path(), source_directory, ibt_plt, options);
    }

    return patch;
}

#endif // COMPILER_HPP