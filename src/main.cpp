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
#include "placement.hpp"
#include "merger.hpp"
#include "relocator.hpp"
#include "cpp_runtime.hpp"

class OutputTransaction {
public:
    explicit OutputTransaction(const std::string& output_path) : destination_(std::filesystem::absolute(output_path)) {
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

    std::string working_path() const {
        return (directory_ / "output").string();
    }

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
    bool cpp_runtime = false;
    PatchCompilerOptions compiler_options;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            help = true;
        } else if (arg == "-v" || arg == "--verbose") {
            verbose_print::verbose = true;
        } else if (arg == "--allow-unverified-targets") {
            allow_unverified_targets = true;
        } else if (arg == "--cpp-runtime") {
            cpp_runtime = true;
        } else if ((arg == "--cxx" || arg == "--std" || arg == "--include-dir" || arg == "--define" || arg == "--library-dir" || arg == "--library" || arg == "--link-file" || arg == "--source" || arg == "-I" || arg == "-D" || arg == "-L" || arg == "-l") && i + 1 < argc) {
            const std::string value = argv[++i];

            if (arg == "--cxx")
                compiler_options.cxx = value;
            else if (arg == "--std")
                compiler_options.standard = value;
            else if (arg == "--include-dir" || arg == "-I")
                compiler_options.include_directories.push_back(value);
            else if (arg == "--define" || arg == "-D")
                compiler_options.definitions.push_back(value);
            else if (arg == "--library-dir" || arg == "-L")
                compiler_options.library_directories.push_back(value);
            else if (arg == "--library" || arg == "-l")
                compiler_options.libraries.push_back(value);
            else if (arg == "--source")
                compiler_options.sources.push_back(value);
            else
                compiler_options.link_files.push_back(value);
        } else if (arg.rfind("--std=", 0) == 0) {
            compiler_options.standard = arg.substr(6);
        } else if (arg.size() > 2 && (arg.rfind("-I", 0) == 0 || arg.rfind("-D", 0) == 0 || arg.rfind("-L", 0) == 0 || arg.rfind("-l", 0) == 0)) {
            if (arg[1] == 'I')
                compiler_options.include_directories.push_back(arg.substr(2));
            else if (arg[1] == 'D')
                compiler_options.definitions.push_back(arg.substr(2));
            else if (arg[1] == 'L')
                compiler_options.library_directories.push_back(arg.substr(2));
            else
                compiler_options.libraries.push_back(arg.substr(2));
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

    if (compiler_options.cxx.empty() || compiler_options.cxx[0] == '-' || (!compiler_options.standard.empty() && !std::regex_match(compiler_options.standard, std::regex("^(gnu\\+\\+|c\\+\\+)(11|14|17|20|23|26)$")))) {
        std::cerr << "1-patch: invalid C++ compiler or standard\n";

        return 2;
    }

    for (const auto& definition : compiler_options.definitions) {
        if (!std::regex_match(definition.substr(0, definition.find('=')), std::regex("^[A-Za-z_][A-Za-z_0-9]*$"))) {
            std::cerr << "1-patch: invalid preprocessor definition\n";

            return 2;
        }
    }

    for (const auto& library : compiler_options.libraries) {
        if (!std::regex_match(library, std::regex("^[A-Za-z_0-9.+:-]+$"))) {
            std::cerr << "1-patch: invalid library name; use --link-file for a file path\n";

            return 2;
        }
    }

    if (cpp_runtime) {
        const std::string extension =
            std::filesystem::path(patch_code_path).extension().string();

        if (extension != ".cpp" && extension != ".cc" && extension != ".cxx") {
            std::cerr << "1-patch: --cpp-runtime requires a C++ patch file\n";

            return 2;
        }
    }

    verbose_print::print_module("Compile");

    std::string patch_binary_path;
    std::optional<CompiledPatch> compiled_patch;
    std::unique_ptr<RuntimeCppPatch> runtime_patch;
    std::optional<OutputTransaction> staged_output;

    try {
        staged_output.emplace(output_binary_path);
        if (cpp_runtime) {
            runtime_patch = std::make_unique<RuntimeCppPatch>(patch_code_path,
                                                              target_binary_path, compiler_options);
        }

        compiled_patch.emplace(compile(cpp_runtime ? runtime_patch->bootstrap_source() : patch_code_path,
                                       cpp_runtime, cpp_runtime ? PatchCompilerOptions{} : compiler_options));
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
        parse_patch_binary(patch_binary_path, global_var_map, function_map,
                           compiled_patch->language() == PatchLanguage::Cpp);
    } catch (const std::exception& e) {
        std::cerr << "1-patch: " << e.what() << '\n';

        return 1;
    }

    verbose_print::print_module("Merge");

    std::string new_section_indicator;
    std::unique_ptr<LIEF::ELF::Binary> prepared_runtime_output;

    try {
        new_section_indicator = merge_binary(patch_binary_path, target_binary_path,
                                             staged_output->working_path(), global_var_map,
                                             function_map, true,
                                             cpp_runtime ? &prepared_runtime_output : nullptr,
                                             cpp_runtime ? runtime_patch->references() : std::vector<RuntimeReference>{});
        if (cpp_runtime)
            runtime_patch->prepare_tls_image(*prepared_runtime_output);
    } catch (const std::exception& e) {
        std::cerr << "1-patch: " << e.what() << '\n';

        return 1;
    }

    verbose_print::print_module("Relocate");

    try {
        try {
            relocate(patch_binary_path, target_binary_path, staged_output->working_path(),
                     global_var_map, function_map, new_section_indicator,
                     allow_unverified_targets,
                     cpp_runtime ? runtime_patch->init_patch_address(patch_binary_path) : UINT64_MAX,
                     cpp_runtime ? runtime_patch->references() : std::vector<RuntimeReference>{},
                     cpp_runtime ? &prepared_runtime_output : nullptr,
                     cpp_runtime ? runtime_patch->after_init_patch_address(patch_binary_path) : UINT64_MAX);
        } catch (const InPlaceRelocationFailure&) {
            // A RIP-relative operand can become unreachable when the patch is placed in the old text segment
            new_section_indicator = merge_binary(
                patch_binary_path, target_binary_path, staged_output->working_path(),
                global_var_map, function_map, false,
                cpp_runtime ? &prepared_runtime_output : nullptr,
                cpp_runtime ? runtime_patch->references() : std::vector<RuntimeReference>{});
            if (cpp_runtime)
                runtime_patch->prepare_tls_image(*prepared_runtime_output);

            relocate(patch_binary_path, target_binary_path, staged_output->working_path(),
                     global_var_map, function_map, new_section_indicator,
                     allow_unverified_targets,
                     cpp_runtime ? runtime_patch->init_patch_address(patch_binary_path) : UINT64_MAX,
                     cpp_runtime ? runtime_patch->references() : std::vector<RuntimeReference>{},
                     cpp_runtime ? &prepared_runtime_output : nullptr,
                     cpp_runtime ? runtime_patch->after_init_patch_address(patch_binary_path) : UINT64_MAX);
        }

        if (cpp_runtime)
            runtime_patch->append_library(staged_output->working_path());

        staged_output->commit(target_binary_path);
    } catch (const std::exception& e) {
        std::cerr << "1-patch: " << e.what() << '\n';

        return 1;
    }

    verbose_print::print_green("Done.");

    return 0;
}
