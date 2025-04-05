#include <vector>

#include <LIEF/LIEF.hpp>

#include "binary_tree.hpp"

void merge_binary(const std::string& patch_binary_path, const std::string& target_binary_path, const std::string& output_binary_path,
                    GlobalVarTree& global_var_tree, FunctionTree& function_tree) {

    std::string random_string = generate_random_string();

    auto patch_binary = LIEF::ELF::Parser::parse(patch_binary_path);

    if (!patch_binary) {
        std::cerr << "\033[1;31m[!]\033[0m Failed to parse patch binary: " << patch_binary_path << "\033[0m\n";
        throw std::runtime_error("Merge failed");
    }

    int original_stderr = dup(STDERR_FILENO); 
    freopen("/dev/null", "w", stderr);
    
    auto target_binary = LIEF::ELF::Parser::parse(target_binary_path);

    fflush(stderr);
    dup2(original_stderr, STDERR_FILENO);
    close(original_stderr);

    if (!target_binary) {
        std::cerr << "\033[1;31m[!]\033[0m Failed to parse target binary: " << target_binary_path << "\033[0m\n";
        throw std::runtime_error("Merge failed");
    }

    if (patch_binary->has_section(".rodata")) {
        auto rodata_section = patch_binary->get_section(".rodata");
        auto rodata_section_content = rodata_section->content();

        std::string new_rodata_section_name = ".rodata." + random_string;
        auto new_rodata_section = LIEF::ELF::Section(new_rodata_section_name);

        new_rodata_section.content(std::vector<uint8_t>(rodata_section_content.begin(), rodata_section_content.end()));
        new_rodata_section.alignment(rodata_section->alignment());
        new_rodata_section.flags(rodata_section->flags());

        target_binary->add(new_rodata_section);
        target_binary->write(output_binary_path);

        uint64_t new_rodata_section_address = target_binary->get_section(new_rodata_section_name)->virtual_address();

        std::cout << "\033[1;32m[+]\033[0m Added .rodata to target binary at 0x" << std::hex << new_rodata_section_address << std::endl;
    }

    if (patch_binary->has_section(".data")) {
        auto data_section = patch_binary->get_section(".data");
        auto data_section_content = data_section->content();

        std::string new_data_section_name = ".data." + random_string;
        auto new_data_section = LIEF::ELF::Section(new_data_section_name);

        new_data_section.content(std::vector<uint8_t>(data_section_content.begin(), data_section_content.end()));
        new_data_section.alignment(data_section->alignment());
        new_data_section.flags(data_section->flags());

        target_binary->add(new_data_section);
        target_binary->write(output_binary_path);

        uint64_t new_data_section_address = target_binary->get_section(new_data_section_name)->virtual_address();

        std::cout << "\033[1;32m[+]\033[0m Added .data to target binary at 0x" << std::hex << new_data_section_address << std::endl;
    }

    if (!function_tree.get_functions().empty()) {
        auto text_section = target_binary->get_section(".text");

        std::string new_text_section_name = ".text." + random_string;
        auto new_text_section = LIEF::ELF::Section(new_text_section_name);

        new_text_section.alignment(text_section->alignment());
        new_text_section.flags(text_section->flags());

        std::vector<uint8_t> new_text_section_content;

        for (auto& function : function_tree.get_functions()) {
            auto function_code = patch_binary->get_content_from_virtual_address(function->patch_address, function->size);
            function->new_address = new_text_section_content.size();
            new_text_section_content.insert(new_text_section_content.end(), function_code.begin(), function_code.end());
        }

        new_text_section.content(new_text_section_content);

        target_binary->add(new_text_section);
        target_binary->write(output_binary_path);

        uint64_t new_text_section_address = target_binary->get_section(new_text_section_name)->virtual_address();

        for (auto& function : function_tree.get_functions()) {
            function->new_address += new_text_section_address;
        }

        std::cout << "\033[1;32m[+]\033[0m Added .text to target binary at 0x" << std::hex << new_text_section_address << std::endl;
    }
}