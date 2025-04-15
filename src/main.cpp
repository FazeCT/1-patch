#include <iostream>
#include <string>
#include <memory>

#include "utils.hpp"
#include "compiler.hpp"
#include "patch_parser.hpp"
#include "merger.hpp"
#include "relocator.hpp"

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

    std::cout << "\033[1;32m[Compile]\033[0m" << std::endl;

    std::string patch_binary_path;

    try {
        patch_binary_path = compile(patch_code_path);
        print_green("Compiled " + patch_code_path + " into " + patch_binary_path);

    } catch (const std::runtime_error& e) {
        print_red("1-patch: " + std::string(e.what()));
        return 1;
    }

    print_green("Done.");

    std::cout << "\n\033[1;32m[Parse]\033[0m" << std::endl;

    // Contains global variables and functions in patch binary
    GlobalVarTree global_var_tree;
    FunctionTree function_tree;

    try {
        parse_patch_binary(patch_binary_path, global_var_tree, function_tree);
    } catch (const std::runtime_error& e) {
        print_red("1-patch: " + std::string(e.what()));
        return 1;
    }

    if (output_binary_path.empty()) {
        output_binary_path = target_binary_path + "_patched";
    }

    print_green("Done.");

    std::cout << "\n\033[1;32m[Merge]\033[0m" << std::endl;

    std::string new_section_indicator;

    try {
        new_section_indicator = merge_binary(patch_binary_path, target_binary_path, output_binary_path, global_var_tree, function_tree);
    } catch (const std::runtime_error& e) {
        print_red("1-patch: " + std::string(e.what()));
        return 1;
    }

    print_green("Done.");

    std::cout << "\n\033[1;32m[Relocate]\033[0m" << std::endl;

    try {
        relocate(patch_binary_path, target_binary_path, output_binary_path, global_var_tree, function_tree, new_section_indicator);
    } catch (const std::runtime_error& e) {
        print_red("1-patch: " + std::string(e.what()));
        return 1;
    }

    std::filesystem::remove(patch_binary_path);

    print_green("Done.");

    return 0;
}