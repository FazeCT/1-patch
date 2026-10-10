#include <vector>
#include <string>
#include <memory>

#include <LIEF/LIEF.hpp>

#include "got_reuse.hpp"

#ifndef MERGER_HPP
#define MERGER_HPP

// Get shared libraries from the binary
std::vector<std::string> get_shared_libraries(const std::string& binary_path) {
    std::vector<std::string> libraries;

    std::unique_ptr<LIEF::ELF::Binary> binary = LIEF::ELF::Parser::parse(binary_path);
    if (!binary) {
        verbose_print::print_red("Failed to parse binary: " + binary_path);
        return libraries;
    }

    LIEF::ELF::Section* dynamic_string_section = binary->get_section(".dynstr");
    if (!dynamic_string_section) {
        verbose_print::print_red("Failed to find .dynstr section in " + binary_path);
        return libraries;
    }

    std::vector<uint8_t> dynamic_strings(dynamic_string_section->content().begin(), dynamic_string_section->content().end());

    for (const auto& entry : binary->dynamic_entries()) {
        if (entry.tag() == LIEF::ELF::DynamicEntry::TAG::NEEDED) {
            auto library_offset = entry.value();
            if (library_offset < dynamic_strings.size()) {
                std::string library_name;
                for (size_t i = library_offset; i < dynamic_strings.size(); ++i) {
                    if (dynamic_strings[i] == '\0') {
                        break;
                    }
                    library_name += static_cast<char>(dynamic_strings[i]);
                }
                if (!library_name.empty()) {
                    libraries.push_back(library_name);
                }
            }   
        }
    }

    return libraries;
}

std::string merge_binary(const std::string& patch_binary_path, const std::string& target_binary_path, const std::string& output_binary_path,
                    GlobalVarMap& global_var_map, FunctionMap& function_map,
                    bool enable_in_place = true) {

    std::string random_string = generate_random_string();

    std::unique_ptr<LIEF::ELF::Binary> patch_binary = LIEF::ELF::Parser::parse(patch_binary_path);

    if (!patch_binary) {
        verbose_print::print_red("Failed to parse patch binary: " + patch_binary_path);
        throw std::runtime_error("Merge failed");
    }

    int original_stderr = dup(STDERR_FILENO); 
    freopen("/dev/null", "w", stderr);
    
    std::unique_ptr<LIEF::ELF::Binary> target_binary = LIEF::ELF::Parser::parse(target_binary_path);

    fflush(stderr);
    dup2(original_stderr, STDERR_FILENO);
    close(original_stderr);

    if (!target_binary) {
        verbose_print::print_red("Failed to parse target binary: " + target_binary_path);
        throw std::runtime_error("Merge failed");
    }

    plan_function_placement(*target_binary, function_map, enable_in_place);

    bool needs_plt = false;
    bool needs_rodata = false;
    bool needs_text = false;
    for (const Function* function : function_map.get_functions()) {
        if (function->operation == OperationType::Ref) continue;
        needs_text |= !function->in_place;
        for (const Reference* reference : function->reference_table->get_references()) {
            const LIEF::ELF::Section* source = patch_binary->section_from_virtual_address(
                reference->reference_address);
            if (!source) continue;
            needs_plt |= source->name() == ".plt.sec";
            needs_rodata |= source->name() == ".rodata";
        }
    }
    // Pointer initializers in patch data can also depend on the copied PLT
    // and read-only data even when no patch function refers to them directly.
    if (!global_var_map.get_global_vars().empty()) {
        needs_plt |= patch_binary->has_section(".plt.sec");
        needs_rodata |= patch_binary->has_section(".rodata");
    }

    // Add libraries to the target binary
    std::vector<std::string> patch_libraries = get_shared_libraries(patch_binary_path);

    for (const auto& library : patch_libraries) {
        if (!target_binary->has_library(library)) {
            try {
                target_binary->add_library(library);
                verbose_print::print_green("Added " + library + " to target binary");
            } catch (const std::exception& e) {
                continue;
            }
        } else {
            verbose_print::print_yellow("Library " + library + " is already included in target binary -> skipped");
        }
    }

    // Add .got section
    if (patch_binary->has_section(".got") &&
        (needs_plt || !global_var_map.get_global_vars().empty())) {
        const auto reused = reusable_got_entries(*patch_binary, *target_binary);
        size_t new_slot_count = 0;

        for (const LIEF::ELF::Relocation& rel : patch_binary->pltgot_relocations()) {
            const LIEF::ELF::Symbol* symbol = rel.symbol();
            if (symbol && reused.count(rel.address()) == 0) ++new_slot_count;
        }

        if (new_slot_count != 0) {
            size_t got_size = new_slot_count * sizeof(uint64_t);
            LIEF::ELF::Section* got_section = patch_binary->get_section(".got");

            std::string new_got_section_name = ".got." + random_string;
            LIEF::ELF::Section new_got_section(new_got_section_name);

            new_got_section.content(std::vector<uint8_t>(got_size, 0x00));
            new_got_section.type(got_section->type());
            new_got_section.alignment(got_section->alignment());
            new_got_section.flags(got_section->flags());

            target_binary->add(new_got_section);

            verbose_print::print_green("Added .got to target binary");
        }
    }

    // Add .plt.sec section
    if (patch_binary->has_section(".plt.sec") && needs_plt) {
        LIEF::ELF::Section* pltsec_section = patch_binary->get_section(".plt.sec");
        auto pltsec_section_content = pltsec_section->content();

        std::string new_pltsec_section_name = ".plt.sec." + random_string;
        LIEF::ELF::Section new_pltsec_section(new_pltsec_section_name);

        new_pltsec_section.content(std::vector<uint8_t>(pltsec_section_content.begin(), pltsec_section_content.end()));
        new_pltsec_section.type(pltsec_section->type());
        new_pltsec_section.alignment(pltsec_section->alignment());
        new_pltsec_section.flags(pltsec_section->flags());

        target_binary->add(new_pltsec_section);

        verbose_print::print_green("Added .plt.sec to target binary");
    }
    
    // Add .rodata section
    if (patch_binary->has_section(".rodata") && needs_rodata) {
        LIEF::ELF::Section* rodata_section = patch_binary->get_section(".rodata");
        auto rodata_section_content = rodata_section->content();

        std::string new_rodata_section_name = ".rodata." + random_string;
        LIEF::ELF::Section new_rodata_section(new_rodata_section_name);

        new_rodata_section.content(std::vector<uint8_t>(rodata_section_content.begin(), rodata_section_content.end()));
        new_rodata_section.type(rodata_section->type());
        new_rodata_section.alignment(rodata_section->alignment());
        new_rodata_section.flags(rodata_section->flags());

        target_binary->add(new_rodata_section);

        verbose_print::print_green("Added .rodata to target binary");
    }

    // Add .data section
    if (patch_binary->has_section(".data") && !global_var_map.get_global_vars().empty()) {
        LIEF::ELF::Section* data_section = patch_binary->get_section(".data");
        auto data_section_content = data_section->content();

        std::string new_data_section_name = ".data." + random_string;
        LIEF::ELF::Section new_data_section(new_data_section_name);

        new_data_section.content(std::vector<uint8_t>(data_section_content.begin(), data_section_content.end()));
        new_data_section.type(data_section->type());
        new_data_section.alignment(data_section->alignment());
        new_data_section.flags(data_section->flags());

        target_binary->add(new_data_section);

        verbose_print::print_green("Added .data to target binary");
    }

    // Add .text section
    if (patch_binary->has_section(".text") && needs_text) {
        LIEF::ELF::Section* text_section = target_binary->get_section(".text");

        std::string new_text_section_name = ".text." + random_string;
        LIEF::ELF::Section new_text_section(new_text_section_name);

        new_text_section.type(text_section->type());
        new_text_section.alignment(text_section->alignment());
        new_text_section.flags(text_section->flags());

        std::vector<uint8_t> new_text_section_content;

        for (auto& function : function_map.get_functions()) {
            if (function->operation == OperationType::Ref || function->in_place)
                continue;
            auto function_code = patch_binary->get_content_from_virtual_address(function->patch_address, function->size);
            function->new_address = new_text_section_content.size();
            new_text_section_content.insert(new_text_section_content.end(), function_code.begin(), function_code.end());
        }

        new_text_section.content(new_text_section_content);

        target_binary->add(new_text_section);

        verbose_print::print_green("Added .text to target binary");
    }
    
    target_binary->write(output_binary_path);
    return random_string;
}

#endif // MERGER_HPP
