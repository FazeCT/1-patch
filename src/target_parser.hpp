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

    // Get all executable sections
    for (const auto& section : target_binary->sections()) {
        if (section.has(LIEF::ELF::Section::FLAGS::EXECINSTR)) {
            uint64_t start_address = section.virtual_address();
            uint64_t size = section.size();
            
            auto section_content = section.content();
            std::vector<uint8_t> code(section_content.begin(), section_content.end());

            // Extract references from the code
            extract_references(code, start_address, reference_tree);
        }
    }

    for (auto &reference : reference_tree.get_references()) {
        std::cout << "\033[1;32m[+]\033[0m Found reference: 0x" << std::hex << reference->address << "\n";
    }
}

#endif // TARGET_PARSER_HPP