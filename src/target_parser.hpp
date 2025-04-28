#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <fstream>

#ifndef TARGET_PARSER_HPP
#define TARGET_PARSER_HPP

void parse_target_binary(const std::string& target_binary_path, ReferenceMap& reference_map) {
    std::unique_ptr<LIEF::ELF::Binary> target_binary = LIEF::ELF::Parser::parse(target_binary_path);
    if (!target_binary) {
        print_red("Failed to parse target binary: " + target_binary_path);
        throw std::runtime_error("Target parser failed");
    }

    for (const auto& section: target_binary->sections()) {
        if (section.has(LIEF::ELF::Section::FLAGS::EXECINSTR)) {
            auto section_code = target_binary->get_content_from_virtual_address(section.virtual_address(), section.size());

            extract_references(std::vector<uint8_t>(section_code.begin(), section_code.end()), section.virtual_address(), reference_map);
        }
    }
}

#endif // TARGET_PARSER_HPP