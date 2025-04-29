#include <iostream>
#include <string>
#include <memory>

#include "utils.hpp"
#include "compiler.hpp"
#include "patch_parser.hpp"
#include "target_parser.hpp"
#include "merger.hpp"
#include "relocator.hpp"

int main(int argc, char* argv[]) {
    std::string patch_code_path;
    std::string target_binary_path;
    std::string output_binary_path;
    bool help = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            help = true;
        } else if (arg == "-v" || arg == "--verbose") {
            verbose_print::verbose = true;
        } else if ((arg == "-p" || arg == "--patch") && i + 1 < argc) {
            patch_code_path = argv[++i];
        } else if ((arg == "-i" || arg == "--input") && i + 1 < argc) {
            target_binary_path = argv[++i];
        } else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            output_binary_path = argv[++i];
        } else {
            help = true;
            break;
        }
    }

    if (help || patch_code_path.empty() || target_binary_path.empty()) {
        print_help();
        return 0;
    }

    if (output_binary_path.empty()) {
        output_binary_path = target_binary_path + "_patched";
    }

    verbose_print::print_module("Compile");

    std::string patch_binary_path;

    try {
        
        patch_binary_path = compile(patch_code_path);
        verbose_print::print_green("Compiled " + patch_code_path + " into " + patch_binary_path);

    } catch (const std::runtime_error& e) {
        verbose_print::print_red("1-patch: " + std::string(e.what()));
        return 1;
    }

    verbose_print::print_module("Parse");

    // Contains global variables and functions in patch binary
    GlobalVarMap global_var_map;
    FunctionMap function_map;

    try {
        verbose_print::print_blue("Parsing patch binary at" + patch_binary_path);
        parse_patch_binary(patch_binary_path, global_var_map, function_map);
    } catch (const std::runtime_error& e) {
        verbose_print::print_red("1-patch: " + std::string(e.what()));
        return 1;
    }

    // Contains references in target binary
    ReferenceMap reference_map;

    try {
        verbose_print::print_blue("Parsing target binary at " + target_binary_path);
        parse_target_binary(target_binary_path, reference_map);
        verbose_print::print_green("Done.");
    } catch (const std::runtime_error& e) {
        verbose_print::print_red("1-patch: " + std::string(e.what()));
        return 1;
    }

    verbose_print::print_module("Merge");

    std::string new_section_indicator;

    try {
        new_section_indicator = merge_binary(patch_binary_path, target_binary_path, output_binary_path, global_var_map, function_map);
    } catch (const std::runtime_error& e) {
        verbose_print::print_red("1-patch: " + std::string(e.what()));
        return 1;
    }

    verbose_print::print_module("Relocate");

    try {
        relocate(patch_binary_path, target_binary_path, output_binary_path, global_var_map, function_map, reference_map, new_section_indicator);
    } catch (const std::runtime_error& e) {
        verbose_print::print_red("1-patch: " + std::string(e.what()));
        return 1;
    }

    std::filesystem::remove(patch_binary_path);

    verbose_print::print_green("Done.");

    return 0;
}