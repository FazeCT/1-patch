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
        std::cerr << "\033[1;31m[!]\033[0m Failed to parse patch binary: " << patch_binary_path << "\033[0m\n";
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
            try {
                target_address = hex_to_decimal(symbol_name.substr(4));
            } catch (...) {
                std::cerr << "[-] Target address for " << symbol_name << " cannot be resolved" << std::endl;
            }
        }

        // Check if the symbol is a global variable or function
        if (symbol.is_variable()) {
            auto variable_value = patch_binary->get_content_from_virtual_address(patch_address, symbol.size());

            GlobalVarNode* global_var_node = new GlobalVarNode(new GlobalVar{
                operation, 
                patch_address, 
                target_address, 
                symbol_name.substr(4), 
                // nullptr, 
                std::vector<uint8_t>(variable_value.begin(), variable_value.end()),
            });

            global_var_tree.insert(global_var_node);
        }

        else if (symbol.is_function()) {
            auto function_code = patch_binary->get_content_from_virtual_address(patch_address, symbol.size());

            // Get all references of the function
            ReferenceTree reference_table;
            extract_references(std::vector<uint8_t>(function_code.begin(), function_code.end()), patch_address, reference_table);

            FunctionNode* function_node = new FunctionNode(new Function{
                operation, 
                symbol.size(), 
                patch_address, 
                target_address, 
                symbol_name.substr(4), 
                reference_table,
                UINT64_MAX,
            });

            function_tree.insert(function_node);

            // Insert .plt functions
            for (auto& reference : reference_table.get_references()) {
                if (reference->reference_type == SymbolType::Function) {
                    std::cout << "[-] Found reference to function: 0x" << std::hex << reference->reference_address << std::endl;
                    auto plt_sec = patch_binary->section_from_virtual_address(reference->reference_address);
                    // to-do
                }
            }
        }

        else {
            std::cerr << "\033[1;31m[!]\033[0m Symbol " << symbol_name << " is not a global variable or a function" << std::endl;
        }
    }
}

#endif // PATCH_PARSER_HPP