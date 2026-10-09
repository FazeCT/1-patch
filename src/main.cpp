#include <iostream>
#include <string>
#include <memory>
#include <optional>
#include <vector>
#include <exception>
#include <filesystem>
#include <cstdlib>

#include "utils.hpp"
#include "compiler.hpp"
#include "patch_parser.hpp"
#include "merger.hpp"
#include "relocator.hpp"

class OutputTransaction {
public:
    explicit OutputTransaction(const std::string& output_path)
        : destination_(std::filesystem::absolute(output_path)) {
        std::string template_path =
            (destination_.parent_path() / ".1-patch-output-XXXXXX").string();
        std::vector<char> name(template_path.begin(), template_path.end());
        name.push_back('\0');
        char* created = mkdtemp(name.data());
        if (!created) {
            throw std::runtime_error("Failed to create private output directory");
        }
        directory_ = created;
    }

    OutputTransaction(const OutputTransaction&) = delete;
    OutputTransaction& operator=(const OutputTransaction&) = delete;

    ~OutputTransaction() {
        if (!directory_.empty()) {
            std::error_code error;
            std::filesystem::remove_all(directory_, error);
        }
    }

    std::string working_path() const { return (directory_ / "output").string(); }

    void commit(const std::string& target_path) {
        const std::filesystem::path staged = working_path();
        const std::filesystem::path permission_source =
            std::filesystem::exists(destination_) ? destination_ : std::filesystem::path(target_path);
        auto mode = std::filesystem::status(permission_source).permissions();
        mode &= ~(std::filesystem::perms::set_uid |
                  std::filesystem::perms::set_gid |
                  std::filesystem::perms::sticky_bit);
        std::filesystem::permissions(staged, mode);
        std::filesystem::rename(staged, destination_);
    }

private:
    std::filesystem::path destination_;
    std::filesystem::path directory_;
};

int main(int argc, char* argv[]) {
    std::string patch_code_path;
    std::string target_binary_path;
    std::string output_binary_path;
    bool help = false;
    bool invalid_arguments = false;
    bool allow_unverified_targets = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            help = true;
        } else if (arg == "-v" || arg == "--verbose") {
            verbose_print::verbose = true;
        } else if (arg == "--allow-unverified-targets") {
            allow_unverified_targets = true;
        } else if ((arg == "-p" || arg == "--patch") && i + 1 < argc) {
            patch_code_path = argv[++i];
        } else if ((arg == "-i" || arg == "--input") && i + 1 < argc) {
            target_binary_path = argv[++i];
        } else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            output_binary_path = argv[++i];
        } else {
            invalid_arguments = true;
            break;
        }
    }

    if (help) {
        print_help();
        return 0;
    }
    if (invalid_arguments || patch_code_path.empty() || target_binary_path.empty()) {
        print_help();
        return 2;
    }

    if (output_binary_path.empty()) {
        output_binary_path = target_binary_path + "_patched";
    }

    verbose_print::print_module("Compile");

    std::string patch_binary_path;
    std::optional<CompiledPatch> compiled_patch;
    std::optional<OutputTransaction> staged_output;

    try {
        staged_output.emplace(output_binary_path);
        compiled_patch.emplace(compile(patch_code_path));
        patch_binary_path = compiled_patch->binary_path();
        verbose_print::print_green("Compiled " + patch_code_path + " into " + patch_binary_path);

    } catch (const std::exception& e) {
        std::cerr << "1-patch: " << e.what() << '\n';
        return 1;
    }

    verbose_print::print_module("Parse");

    // Contains global variables and functions in patch binary
    GlobalVarMap global_var_map;
    FunctionMap function_map;

    try {
        verbose_print::print_blue("Parsing patch binary at" + patch_binary_path);
        parse_patch_binary(patch_binary_path, global_var_map, function_map);
    } catch (const std::exception& e) {
        std::cerr << "1-patch: " << e.what() << '\n';
        return 1;
    }

    verbose_print::print_module("Merge");

    std::string new_section_indicator;

    try {
        new_section_indicator = merge_binary(patch_binary_path, target_binary_path,
                                             staged_output->working_path(), global_var_map, function_map);
    } catch (const std::exception& e) {
        std::cerr << "1-patch: " << e.what() << '\n';
        return 1;
    }

    verbose_print::print_module("Relocate");

    try {
        relocate(patch_binary_path, target_binary_path, staged_output->working_path(),
                 global_var_map, function_map, new_section_indicator,
                 allow_unverified_targets);
        staged_output->commit(target_binary_path);
    } catch (const std::exception& e) {
        std::cerr << "1-patch: " << e.what() << '\n';
        return 1;
    }

    verbose_print::print_green("Done.");

    return 0;
}
