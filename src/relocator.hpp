#include "utils.hpp"

#ifndef RELOCATOR_HPP
#define RELOCATOR_HPP

void relocate(const std::string& patch_binary_path, const std::string& target_binary_path, const std::string& output_binary_path,
                GlobalVarTree& global_var_tree, FunctionTree& function_tree) {
    
    auto patch_binary = LIEF::ELF::Parser::parse(patch_binary_path);
    auto target_binary = LIEF::ELF::Parser::parse(target_binary_path);
    auto output_binary = LIEF::ELF::Parser::parse(output_binary_path);

    // Account for the PHT new alighment bytes, which push everything down in virtual space
    uint64_t entrypoint_difference = output_binary->header().entrypoint() - target_binary->header().entrypoint();
    std::cout << "\033[1;32m[+]\033[0m Difference between old and new entrypoints is 0x" << std::hex << entrypoint_difference << std::endl;
}

#endif // RELOCATOR_HPP