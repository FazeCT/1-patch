#include <iostream>
#include <string>
#include <vector>
#include <fstream>

#include <capstone/capstone.h>
#include <LIEF/LIEF.hpp>
#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>

#include "utils.hpp"

#ifndef TARGET_PARSER_HPP
#define TARGET_PARSER_HPP

void parse_target_binary(const std::string& target_binary_path, ReferenceTree& reference_tree) {
    // Read the target binary
    auto target_binary = LIEF::ELF::Parser::parse(target_binary_path);

    if (!target_binary) {
        std::cerr << "\033[1;31m[!]\033[0m Failed to parse target binary: " << target_binary_path << "\033[0m\n";
        throw std::runtime_error("Target parser failed");
    }
}

#endif // TARGET_PARSER_HPP