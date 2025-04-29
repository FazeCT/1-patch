#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <fstream>

#include <capstone/capstone.h>
#include <LIEF/LIEF.hpp>
#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>

#ifndef PATCH_PARSER_HPP
#define PATCH_PARSER_HPP

// Parse the patch binary, extract global variables and functions
void parse_patch_binary(const std::string& patch_binary_path, GlobalVarMap& global_var_map, FunctionMap& function_map) {
    // Read the patch binary
    std::unique_ptr<LIEF::ELF::Binary> patch_binary = LIEF::ELF::Parser::parse(patch_binary_path);

    if (!patch_binary) {
        verbose_print::print_red("Failed to parse patch binary: " + patch_binary_path);
        throw std::runtime_error("Patch parser failed");
    }
    
    for (const auto& symbol : patch_binary->symbols()) {
        std::string symbol_name = symbol.demangled_name();

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
            if (operation != OperationType::Ref){
                DWARFResolver resolver(patch_binary_path);

                GlobalVariableType variable_type = resolver.resolve(symbol_name);
                uint64_t variable_size = variable_type.element_count > 0? symbol.size() / variable_type.element_count : symbol.size();
        
                global_var_map.insert(std::make_unique<GlobalVar>(
                    operation,
                    variable_size,
                    patch_address,
                    target_address,
                    variable_type,
                    UINT64_MAX
                ));

                // Also insert all elements of the array
                for (int i = 1; i < variable_type.element_count; ++i) {
                    GlobalVariableType element_type;

                    element_type.primitive = variable_type.primitive;
                    element_type.pointer_depth = variable_type.pointer_depth;
                    element_type.is_array = false;
                    element_type.element_count = 1;

                    global_var_map.insert(std::make_unique<GlobalVar>(
                        operation,
                        variable_size,
                        patch_address + i * variable_size, 
                        target_address + i * variable_size, 
                        element_type,
                        UINT64_MAX
                    ));
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
                    UINT64_MAX
                ));
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
                    UINT64_MAX
                ));
            } else {
                std::unique_ptr<ReferenceMap> empty_reference_table = std::make_unique<ReferenceMap>();

                function_map.insert(std::make_unique<Function>(
                    operation, 
                    symbol.size(), 
                    patch_address, 
                    target_address, 
                    std::move(empty_reference_table),
                    UINT64_MAX
                ));
            }
        }

        else {
            verbose_print::print_red("Symbol " + symbol_name + " is not a global variable or a function");
        }
    }
}

#endif // PATCH_PARSER_HPP