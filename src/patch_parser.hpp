#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <cstdint>

#include <capstone/capstone.h>
#include <LIEF/LIEF.hpp>
#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>

#ifndef PATCH_PARSER_HPP
#define PATCH_PARSER_HPP

void validate_cpp_patch_binary(const LIEF::ELF::Binary& binary) {
    // Need dedicated ELF and ABI handling
    for (const char* name : {".data.rel.ro", ".data.rel.ro.local", ".gcc_except_table", ".tdata", ".tbss"}) {
        const LIEF::ELF::Section* section = binary.get_section(name);

        if (section && section->size() != 0) {
            throw std::runtime_error(std::string("C++ patch uses unsupported section ") + name);
        }
    }

    for (const auto& relocation : binary.relocations()) {
        const LIEF::ELF::Symbol* symbol = relocation.symbol();

        if (!symbol)
            continue;

        const std::string& name = symbol->name();

        if (name.rfind("_Z", 0) == 0 || name.rfind("__gxx_personality", 0) == 0 || (name.rfind("__cxa_", 0) == 0 && name != "__cxa_finalize")) {
            throw std::runtime_error("C++ patch uses unsupported runtime import " + name);
        }
    }

    auto check_array = [&](const char* name, const char* allowed_symbol) {
        const LIEF::ELF::Section* section = binary.get_section(name);

        if (!section || !section->size())
            return;

        auto content = section->content();

        if (content.size() != section->size() || content.size() % sizeof(uint64_t) != 0) {
            throw std::runtime_error(std::string("Invalid C++ patch section ") + name);
        }

        for (size_t offset = 0; offset < content.size(); offset += sizeof(uint64_t)) {
            uint64_t entry = 0;

            for (size_t i = 0; i < sizeof(uint64_t); ++i) {
                entry |= uint64_t(content[offset + i]) << (8 * i);
            }

            const uint64_t slot = section->virtual_address() + offset;

            for (const auto& relocation : binary.relocations()) {
                if (relocation.address() != slot)
                    continue;

                if (relocation.type() != LIEF::ELF::Relocation::TYPE::X86_64_RELATIVE) {
                    throw std::runtime_error(std::string("Unsupported C++ patch relocation in ") + name);
                }

                entry = static_cast<uint64_t>(relocation.addend());
            }

            bool permitted = false;

            for (const auto& symbol : binary.symbols()) {
                if (symbol.name() == allowed_symbol && symbol.value() == entry) {
                    permitted = true;
                    break;
                }
            }

            if (!permitted) {
                throw std::runtime_error(std::string("C++ patch requires unsupported startup or shutdown hook in ") + name);
            }
        }
    };

    check_array(".init_array", "frame_dummy");
    check_array(".fini_array", "__do_global_dtors_aux");
}

// Parse the patch binary, extract global variables and functions
void parse_patch_binary(const std::string& patch_binary_path, GlobalVarMap& global_var_map, FunctionMap& function_map, bool cpp_patch = false) {
    // Read the patch binary
    std::unique_ptr<LIEF::ELF::Binary> patch_binary = LIEF::ELF::Parser::parse(patch_binary_path);

    if (!patch_binary) {
        verbose_print::print_red("Failed to parse patch binary: " + patch_binary_path);
        throw std::runtime_error("Patch parser failed");
    }

    if (cpp_patch)
        validate_cpp_patch_binary(*patch_binary);

    std::unique_ptr<DWARFResolver> resolver;

    for (const auto& symbol : patch_binary->symbols()) {
        const std::string symbol_name = symbol.name();

        if (cpp_patch && symbol_name.rfind("_Z", 0) == 0) {
            const std::string demangled = symbol.demangled_name();

            if (demangled.rfind("add_", 0) == 0 || demangled.rfind("fix_", 0) == 0 || demangled.rfind("ref_", 0) == 0) {
                throw std::runtime_error(
                    "C++ patch markers require extern \"C\" linkage: " + demangled);
            }
        }

        // Get the operation type (add, fix, ref)
        OperationType operation = OperationType::None;

        if (symbol_name.find("add_") == 0) {
            operation = OperationType::Add;
        } else if (symbol_name.find("fix_") == 0) {
            operation = OperationType::Fix;
        } else if (symbol_name.find("ref_") == 0) {
            operation = OperationType::Ref;
        }

        if (operation == OperationType::None) {
            continue;
        }

        uint64_t patch_address = symbol.value();
        uint64_t target_address = UINT64_MAX;

        if (operation != OperationType::Add) {
            target_address = parse_address(symbol_name.substr(4));
            if (target_address == UINT64_MAX) {
                verbose_print::print_yellow("Target address for " + symbol_name + " cannot be resolved -> skipped");
                continue;
            }
        }

        verbose_print::print_blue("Found symbol " + symbol_name);

        if (symbol.is_variable()) {
            if (operation != OperationType::Ref) {
                if (!resolver)
                    resolver = std::make_unique<DWARFResolver>(patch_binary_path);

                GlobalVariableType variable_type = resolver->resolve(symbol_name);

                if (variable_type.element_count == 0 || symbol.size() == 0 || variable_type.element_count > symbol.size() || symbol.size() % variable_type.element_count != 0) {
                    throw std::runtime_error("Invalid patch variable array extent");
                }

                uint64_t variable_size = symbol.size() / variable_type.element_count;
                GlobalVariableType element_type = variable_type;

                element_type.is_array = false;
                element_type.element_count = 1;

                global_var_map.insert(std::make_unique<GlobalVar>(
                    operation,
                    variable_size,
                    patch_address,
                    target_address,
                    element_type,
                    UINT64_MAX));

                // Also insert all elements of the array
                for (uint64_t i = 1; i < variable_type.element_count; ++i) {
                    if (i > (UINT64_MAX - patch_address) / variable_size || (operation != OperationType::Add && i > (UINT64_MAX - target_address) / variable_size)) {
                        throw std::runtime_error("Patch variable array address overflows");
                    }

                    global_var_map.insert(std::make_unique<GlobalVar>(
                        operation,
                        variable_size,
                        patch_address + i * variable_size,
                        operation == OperationType::Add ? UINT64_MAX : target_address + i * variable_size,
                        element_type,
                        UINT64_MAX));
                }
            } else {
                GlobalVariableType element_type;

                element_type.primitive = "none";
                element_type.pointer_depth = 0;
                element_type.is_array = false;
                element_type.element_count = 0;

                global_var_map.insert(std::make_unique<GlobalVar>(
                    operation,
                    symbol.size(),
                    patch_address,
                    target_address,
                    element_type,
                    UINT64_MAX));
            }
        }

        else if (symbol.is_function()) {
            if (operation != OperationType::Ref) {
                auto function_code = patch_binary->get_content_from_virtual_address(patch_address, symbol.size());

                // Get all references of the function
                std::unique_ptr<ReferenceMap> reference_table = std::make_unique<ReferenceMap>();

                extract_references(std::vector<uint8_t>(function_code.begin(), function_code.end()), patch_address, *reference_table);

                function_map.insert(std::make_unique<Function>(
                    operation,
                    symbol.size(),
                    patch_address,
                    target_address,
                    std::move(reference_table),
                    UINT64_MAX));
            } else {
                std::unique_ptr<ReferenceMap> empty_reference_table = std::make_unique<ReferenceMap>();

                function_map.insert(std::make_unique<Function>(
                    operation,
                    symbol.size(),
                    patch_address,
                    target_address,
                    std::move(empty_reference_table),
                    UINT64_MAX));
            }
        }

        else {
            verbose_print::print_red("Symbol " + symbol_name + " is not a global variable or a function");
        }
    }
}

#endif // PATCH_PARSER_HPP
