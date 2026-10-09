#ifndef COMPILER_HPP
#define COMPILER_HPP

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

struct CompilerResult {
    int status;
    std::string output;
};

// Pass each argument directly to GCC. No patch-controlled path is interpreted by a shell.
CompilerResult run_gcc(const std::string& input_path, const std::string& output_path) {
    const std::string absolute_input = std::filesystem::absolute(input_path).string();
    const char* args[] = {
        "gcc", "-w", "-fno-stack-protector", "-fcf-protection=full",
        absolute_input.c_str(),
        "-o", output_path.c_str(), "-g", nullptr
    };

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
        if (dup2(output_pipe[1], STDOUT_FILENO) < 0 ||
            dup2(output_pipe[1], STDERR_FILENO) < 0) {
            _exit(127);
        }
        close(output_pipe[1]);
        execvp("gcc", const_cast<char* const*>(args));
        static constexpr char message[] = "Failed to execute GCC\n";
        write(STDERR_FILENO, message, sizeof(message) - 1);
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
    if (truncated) output += "\n[compiler output truncated]\n";
    return {WIFEXITED(status) ? WEXITSTATUS(status) : 128, output};
}

void exec_compile(const std::string& input_path, const std::string& output_path) {
    if (!std::filesystem::exists(input_path)) {
        verbose_print::print_red("Patch file does not exist: " + input_path);
        throw std::runtime_error("Compilation failed");
    }
    if (!std::filesystem::is_regular_file(input_path)) {
        verbose_print::print_red("Patch file is not a regular file: " + input_path);
        throw std::runtime_error("Compilation failed");
    }
    if (std::filesystem::path(input_path).extension() != ".c") {
        verbose_print::print_red("Patch file extension is not .c: " + input_path);
        throw std::runtime_error("Compilation failed");
    }

    const CompilerResult result = run_gcc(input_path, output_path);
    if (result.status == 0) {
        return;
    }
    if (result.output.find("undefined reference to `main'") != std::string::npos ||
        result.output.find("undefined reference to 'main'") != std::string::npos) {
        throw std::runtime_error("Missing main() function");
    }
    if (!result.output.empty()) {
        std::cerr << result.output;
    }
    throw std::runtime_error("Compilation failed");
}

// Owns the private build directory until every patching phase is finished.
class CompiledPatch {
public:
    explicit CompiledPatch(std::filesystem::path directory) : directory_(std::move(directory)) {}
    CompiledPatch(const CompiledPatch&) = delete;
    CompiledPatch& operator=(const CompiledPatch&) = delete;
    CompiledPatch(CompiledPatch&& other) noexcept : directory_(std::move(other.directory_)) {
        other.directory_.clear();
    }
    ~CompiledPatch() {
        if (!directory_.empty()) {
            std::error_code error;
            std::filesystem::remove_all(directory_, error);
        }
    }
    std::string binary_path() const { return (directory_ / "patch").string(); }
    std::filesystem::path source_path() const { return directory_ / "patch-with-main.c"; }

private:
    std::filesystem::path directory_;
};

CompiledPatch compile(const std::string& input_path) {
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
    CompiledPatch patch(created);

    try {
        exec_compile(input_path, patch.binary_path());
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
        exec_compile(patch.source_path().string(), patch.binary_path());
    }
    return patch;
}

#endif // COMPILER_HPP
