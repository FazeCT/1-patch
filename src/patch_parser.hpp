#include <iostream>
#include <string>
#include <vector>
#include <fstream>

#include <capstone/capstone.h>
#include <LIEF/LIEF.hpp>
#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>

#ifndef PATCH_PARSER_HPP
#define PATCH_PARSER_HPP

// Parse the patch binary, extract global variables and functions
void parse_patch_binary(const std::string& patch_binary_path, GlobalVarTree& global_var_tree, FunctionTree& function_tree) {
    // Read the patch binary
    auto patch_binary = LIEF::ELF::Parser::parse(patch_binary_path);

    if (!patch_binary) {
        std::cout << "\033[1;31m[!]\033[0m Failed to parse patch binary: " << patch_binary_path << std::endl;
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
            target_address = hex_to_decimal(symbol_name.substr(4));
            if (target_address == UINT64_MAX) {
                std::cout << "\033[1;31m[!]\033[0m Target address for " << symbol_name << " cannot be resolved -> skipped" << std::endl;
                continue;
            }
        }

        std::cout << "\033[1;36m[-]\033[0m Found symbol " << symbol_name << std::endl;

        if (symbol.is_variable()) {
            DWARFResolver resolver(patch_binary_path);

            GlobalVariableType variable_type = resolver.resolve(symbol_name);
            uint64_t variable_size = symbol.size() / variable_type.element_count;

            GlobalVarNode* global_var_node = new GlobalVarNode(new GlobalVar{
                operation, 
                variable_size,
                patch_address, 
                target_address, 
                variable_type,
                UINT64_MAX,
            });

            global_var_tree.insert(global_var_node);

            // Also insert all elements of the array
            for (int i = 1; i < variable_type.element_count; ++i) {
                GlobalVariableType element_type;

                element_type.primitive = variable_type.primitive;
                element_type.pointer_depth = variable_type.pointer_depth;
                element_type.is_array = false;
                element_type.element_count = 1;

                GlobalVarNode* global_var_node_element = new GlobalVarNode(new GlobalVar{
                    operation, 
                    variable_size,
                    patch_address + i * variable_size, 
                    target_address + i * variable_size, 
                    element_type,
                    UINT64_MAX,
                });

                global_var_tree.insert(global_var_node_element);
            }
        }

        else if (symbol.is_function()) {
            auto function_code = patch_binary->get_content_from_virtual_address(patch_address, symbol.size());

            // Get all references of the function
            std::unique_ptr<ReferenceTree> reference_table = std::make_unique<ReferenceTree>();
            extract_references(std::vector<uint8_t>(function_code.begin(), function_code.end()), patch_address, *reference_table);

            FunctionNode* function_node = new FunctionNode(new Function{
                operation, 
                symbol.size(), 
                patch_address, 
                target_address, 
                std::move(reference_table),
                UINT64_MAX,
            });

            function_tree.insert(function_node);

            // Insert .plt functions
            for (auto& reference : function_node->get_function()->reference_table->get_references()) {
                if (reference->reference_type == SymbolType::Function) {
                    // std::cout << "[-] Found reference to function: 0x" << std::hex << reference->reference_address << std::endl;
                    LIEF::ELF::Section* plt_sec = patch_binary->section_from_virtual_address(reference->reference_address);
                    // to-do
                }
            }
        }

        else {
            std::cout << "\033[1;31m[!]\033[0m Symbol " << symbol_name << " is not a global variable or a function" << std::endl;
        }
    }
}

#endif // PATCH_PARSER_HPP