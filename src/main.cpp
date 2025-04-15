#include <iostream>
#include <string>
#include <memory>

#include "utils.hpp"
#include "compiler.hpp"
#include "patch_parser.hpp"
#include "target_parser.hpp"
#include "merger.hpp"
#include "relocator.hpp"

// Print help
void print_help() {
    std::cout << "\n\033[1;32m1-PATCH [v0.1.0]\033[0m\n";
    std::cout << "\033[1;32m----------------\033[0m\n";

    std::cout << "\033[1;36mStatic Binary Rewriting With Code Insertion\033[0m\n";
    std::cout << "\033[1;36mPatch an ELF binary with user-input C program\033[0m\n";

    std::cout << "\n\033[1;33mUsage: 1-patch <OPTIONS> [PATCH_CODE] [TARGET_BINARY] [OUTPUT_BINARY]\033[0m\n";

    std::cout << "\n\033[1;36mPatch Syntax:\033[0m\n";
    std::cout << "\033[1;36m  Prefix:\033[0m\n";
    std::cout << "    \033[1;32mvolatile\033[0m\033[1;35m add_\033[0m Add a symbol to the target binary\n";
    std::cout << "    \033[1;32mvolatile\033[0m\033[1;35m fix_\033[0m Fix a symbol within the target binary\n";
    std::cout << "    \033[1;32mvolatile\033[0m\033[1;35m ref_\033[0m Reference a symbol within the target binary\n";

    std::cout << "\n\033[1;36m  Suffix:\033[0m\n";
    std::cout << "    Anything in case of\033[1;35m add_\033[0m\n";
    std::cout << "    Address of the symbol within the target binary in case of\033[1;35m fix_\033[0m and\033[1;35m ref_\033[0m\n";

    std::cout << "\n\033[1;36m  Note:\033[0m\n";
    std::cout << "    Any symbols that do not adhere to the defined syntax will be skipped\n";

    std::cout << "\n\033[1;36mOptions:\033[0m\n";
    std::cout << "    \033[1;35m-h, --help\033[0m Show this help\n";

    std::cout << "\n\033[1;36mArguments:\033[0m\n";
    std::cout << "    \033[1;35mPATCH_CODE\033[0m Path to the C program\n";
    std::cout << "    \033[1;35mTARGET_BINARY\033[0m Path to the target binary\n";
    std::cout << "    \033[1;35mOUTPUT_BINARY\033[0m Path to the output binary\n";
}

int main(int argc, char* argv[]) {
    bool help = false;
    std::string patch_code_path;
    std::string target_binary_path;
    std::string output_binary_path;

    if (argc >= 2 && (argv[1] == std::string("-h") || argv[1] == std::string("--help"))) {
        help = true;
    }

    if (argc >= 2 && argv[1] != nullptr) {
        patch_code_path = argv[1];
    }

    if (argc >= 3 && argv[2] != nullptr) {
        target_binary_path = argv[2];
    }

    if (argc >= 4 && argv[3] != nullptr) {
        output_binary_path = argv[3];
    }
    
    if (argc == 1 || help || patch_code_path.empty() || target_binary_path.empty()) {
        print_help();
        return 0;
    }

    std::string patch_binary_path;

    try {
        patch_binary_path = compile(patch_code_path);
        std::cout << "\033[1;32m[+]\033[0m Compiled " << patch_code_path << " into " << patch_binary_path << "\n";
    } catch (const std::runtime_error& e) {
        std::cerr << "\033[1;31m[!]\033[0m 1-patch: " << e.what() << "\033[0m\n";
        return 1;
    }

    // Contains global variables and functions in patch binary
    GlobalVarTree global_var_tree;
    FunctionTree function_tree;

    try {
        parse_patch_binary(patch_binary_path, global_var_tree, function_tree);
    } catch (const std::runtime_error& e) {
        std::cerr << "\033[1;31m[!]\033[0m 1-patch: " << e.what() << "\033[0m\n";
        return 1;
    }

    // Contains references within the target binary
    ReferenceTree reference_tree;

    try {
        parse_target_binary(target_binary_path, reference_tree);
    } catch (const std::runtime_error& e) {
        std::cerr << "\033[1;31m[!]\033[0m 1-patch: " << e.what() << "\033[0m\n";
        return 1;
    }

    if (output_binary_path.empty()) {
        output_binary_path = target_binary_path + "_patched";
    }

    std::string new_section_indicator;

    try {
        new_section_indicator = merge_binary(patch_binary_path, target_binary_path, output_binary_path, global_var_tree, function_tree);
    } catch (const std::runtime_error& e) {
        std::cerr << "\033[1;31m[!]\033[0m 1-patch: " << e.what() << "\033[0m\n";
        return 1;
    }

    try {
        relocate(patch_binary_path, target_binary_path, output_binary_path, global_var_tree, function_tree, new_section_indicator);
    } catch (const std::runtime_error& e) {
        std::cerr << "\033[1;31m[!]\033[0m 1-patch: " << e.what() << "\033[0m\n";
        return 1;
    }

    std::filesystem::remove(patch_binary_path);

    std::cout << "\033[1;32m[+]\033[0m Done." << std::endl;

    return 0;
}