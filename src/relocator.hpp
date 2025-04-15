#include <capstone/capstone.h>

#include "utils.hpp"

#ifndef RELOCATOR_HPP
#define RELOCATOR_HPP

void recursive_patcher(
    LIEF::ELF::Binary& patch_binary, 
    LIEF::ELF::Binary& output_binary, 
    const uint64_t address, 
    const uint8_t pointer_depth, 
    const std::string new_section_indicator) 
{
    if (pointer_depth <= 0) {
        return;
    }
   
    // Get 8-byte content at the address (64-bit pointers)
    auto element_content = patch_binary.get_content_from_virtual_address(address, 8);
    if (element_content.size() != 8) {
        std::cout << "\033[1;31m[!]\033[0m Failed to read full pointer at address 0x" << std::hex << address << std::dec << std::endl;
        return;
    }

    uint64_t element_value = vector_to_int(std::vector<uint8_t>(element_content.begin(), element_content.end()));

    // Get original section from element value
    LIEF::ELF::Section* assoc_section_value = patch_binary.section_from_virtual_address(element_value);
    if (!assoc_section_value) {
        std::cout << "\033[1;31m[!]\033[0m No section found for virtual address 0x" << std::hex << element_value << std::dec << std::endl;
        return;
    }

    // Find relocated section in output binary
    std::string new_section_value_name = assoc_section_value->name() + "." + new_section_indicator;
    LIEF::ELF::Section* new_section_value = output_binary.get_section(new_section_value_name);
    if (!new_section_value) {
        std::cout << "\033[1;31m[!]\033[0m Could not find section '" << new_section_value_name << "' in output binary" << std::endl;
        return;
    }

    // Calculate new value for the pointer
    uint64_t new_element_value = element_value - assoc_section_value->virtual_address() + new_section_value->virtual_address();
    auto new_element_content = int_to_vector(new_element_value);

    // Get original section from element address
    LIEF::ELF::Section* assoc_section_address = patch_binary.section_from_virtual_address(address);
    if (!assoc_section_address) {
        std::cout << "\033[1;31m[!]\033[0m No section found for virtual address 0x" << std::hex << address << std::dec << std::endl;
        return;
    }

    // Find relocated section in output binary
    std::string new_section_address_name = assoc_section_address->name() + "." + new_section_indicator;
    LIEF::ELF::Section* new_section_address = output_binary.get_section(new_section_address_name);

    if (!new_section_address) {
        std::cout << "\033[1;31m[!]\033[0m Could not find section '" << new_section_address_name << "' in output binary" << std::endl;
        return;
    }

    uint64_t new_element_address = address - assoc_section_address->virtual_address() + new_section_address->virtual_address();

    // Patch the value in output binary
    output_binary.patch_address(new_element_address, new_element_content);

    recursive_patcher(patch_binary, output_binary, element_value, pointer_depth - 1, new_section_indicator);
}

void relocate(const std::string& patch_binary_path, const std::string& target_binary_path, const std::string& output_binary_path,
                GlobalVarTree& global_var_tree, FunctionTree& function_tree, const std::string new_section_indicator) {
    
    auto patch_binary = LIEF::ELF::Parser::parse(patch_binary_path);
    auto target_binary = LIEF::ELF::Parser::parse(target_binary_path);
    auto output_binary = LIEF::ELF::Parser::parse(output_binary_path);

    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize Capstone");
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // Account for the PHT new alignment bytes, which push everything down in virtual space
    uint64_t entrypoint_difference = output_binary->header().entrypoint() - target_binary->header().entrypoint();

    // Relocate global variables
    for (auto& global_var : global_var_tree.get_global_vars()) {
        auto variable_type = global_var->variable_type;
        
        // We only care about pointer variables
        if (variable_type.pointer_depth > 0) {
            // Recursive fix for all elements
            uint64_t element_count = std::max<uint64_t>(1, variable_type.element_count);


            for (uint64_t element_idx = 0; element_idx < element_count; ++element_idx) {
                uint64_t element_address = global_var->patch_address + 8 * element_idx;
                recursive_patcher(*patch_binary, *output_binary, element_address, variable_type.pointer_depth, new_section_indicator);
            }
        }

        // Fix the fix_ global variable by overwriting
        if (global_var->operation == OperationType::Fix) {
            auto new_value = patch_binary->get_content_from_virtual_address(global_var->patch_address, global_var->size);
            output_binary->patch_address(global_var->target_address + entrypoint_difference, std::vector<uint8_t>(new_value.begin(), new_value.end()));
        }
    }   

    std::cout << "\033[1;32m[+]\033[0m Relocated all global variables" << std::endl;
    
    // Relocate functions
    for (auto& function : function_tree.get_functions()) {
        // Relocate ref_ symbols referenced by patched functions
        if (function->operation != OperationType::Ref) {
            for (auto& reference : function->reference_table->get_references()) {
                // ref_ global variables
                if (reference->reference_type == SymbolType::GlobalVariable) {
                    auto ref_global_var = global_var_tree.find_global_var(reference->reference_address);
                    if (ref_global_var) {
                        if (ref_global_var->operation == OperationType::Ref) {
                            cs_insn* insn = nullptr;
                            auto instruction_content = patch_binary->get_content_from_virtual_address(reference->address, reference->size);
                            std::vector<uint8_t> instruction_bytes(instruction_content.begin(), instruction_content.end());
                            
                            size_t count = cs_disasm(handle, instruction_bytes.data(), instruction_bytes.size(), reference->address, 0, &insn);

                            if (count > 0) {
                                const cs_detail* detail = insn[0].detail;
                                cs_insn& instruction = insn[0];
                                if (detail) {
                                    uint64_t instruction_address = reference->address - function->patch_address + function->new_address;
                                    std::string new_instruction = std::string(instruction.mnemonic) + " " + instruction.op_str;

                                    // Memory on LHS
                                    if (detail->x86.operands[0].type == X86_OP_MEM && detail->x86.operands[0].mem.base == X86_REG_RIP) {
                                        uint32_t new_disp = ref_global_var->target_address + entrypoint_difference - instruction_address - instruction.size;
                                        uint32_t old_disp = detail->x86.operands[0].mem.disp;                            
                                        size_t disp_pos = new_instruction.find(decimal_to_hex(old_disp));
                                        if (disp_pos != std::string::npos) {
                                            new_instruction.replace(disp_pos, decimal_to_hex(old_disp).length(), decimal_to_hex(new_disp));
                                        }
                                    }

                                    // Memory on RHS
                                    else if (detail->x86.operands[1].type == X86_OP_MEM && detail->x86.operands[1].mem.base == X86_REG_RIP) {
                                        uint32_t new_disp = ref_global_var->target_address + entrypoint_difference - instruction_address - instruction.size;
                                        uint32_t old_disp = detail->x86.operands[1].mem.disp;
                                
                                        size_t disp_pos = new_instruction.find(decimal_to_hex(old_disp));
                                        if (disp_pos != std::string::npos) {
                                            new_instruction.replace(disp_pos, decimal_to_hex(old_disp).length(), decimal_to_hex(new_disp));
                                        }
                                    }

                                    try {
                                        std::vector<uint8_t> new_instruction_bytes = assemble_instruction(new_instruction);
                                        output_binary->patch_address(instruction_address, new_instruction_bytes);
                                    } catch (const std::exception& e) {
                                        throw std::runtime_error("Relocator failed");
                                    }
                                }
                            }
                            cs_free(insn, count);
                        }
 
                        else if (ref_global_var->operation == OperationType::Add || ref_global_var->operation == OperationType::Fix) {
                            cs_insn* insn = nullptr;
                            auto instruction_content = patch_binary->get_content_from_virtual_address(reference->address, reference->size);
                            std::vector<uint8_t> instruction_bytes(instruction_content.begin(), instruction_content.end());
                            
                            size_t count = cs_disasm(handle, instruction_bytes.data(), instruction_bytes.size(), reference->address, 0, &insn);

                            if (count > 0) {
                                const cs_detail* detail = insn[0].detail;
                                cs_insn& instruction = insn[0];
                                if (detail) {
                                    uint64_t instruction_address = reference->address - function->patch_address + function->new_address;
                                    std::string new_instruction = std::string(instruction.mnemonic) + " " + instruction.op_str;;

                                    // Memory on LHS
                                    if (detail->x86.operands[0].type == X86_OP_MEM && detail->x86.operands[0].mem.base == X86_REG_RIP) {
                                        uint32_t new_disp = ref_global_var->new_address - instruction_address - instruction.size;
                                        uint32_t old_disp = detail->x86.operands[0].mem.disp;                            
                                        size_t disp_pos = new_instruction.find(decimal_to_hex(old_disp));
                                        if (disp_pos != std::string::npos) {
                                            new_instruction.replace(disp_pos, decimal_to_hex(old_disp).length(), decimal_to_hex(new_disp));
                                        }
                                    }

                                    // Memory on RHS
                                    else if (detail->x86.operands[1].type == X86_OP_MEM && detail->x86.operands[1].mem.base == X86_REG_RIP) {
                                        uint32_t new_disp = ref_global_var->new_address - instruction_address - instruction.size;
                                        uint32_t old_disp = detail->x86.operands[1].mem.disp;
                                
                                        size_t disp_pos = new_instruction.find(decimal_to_hex(old_disp));
                                        if (disp_pos != std::string::npos) {
                                            new_instruction.replace(disp_pos, decimal_to_hex(old_disp).length(), decimal_to_hex(new_disp));
                                        }
                                    }

                                    try {
                                        std::vector<uint8_t> new_instruction_bytes = assemble_instruction(new_instruction);
                                        output_binary->patch_address(instruction_address, new_instruction_bytes);
                                    } catch (const std::exception& e) {
                                        throw std::runtime_error("Relocator failed");
                                    }
                                }
                            }
                            cs_free(insn, count);
                        }
                    } else {
                        throw std::runtime_error("Relocator failed");
                    }
                }

                // ref_ functions
                else if (reference->reference_type == SymbolType::Function) {
                    auto ref_function = function_tree.find_function(reference->reference_address);
                    if (ref_function) {
                        if (ref_function->operation == OperationType::Ref) {
                            cs_insn* insn = nullptr;
                            auto instruction_content = patch_binary->get_content_from_virtual_address(reference->address, reference->size);
                            std::vector<uint8_t> instruction_bytes(instruction_content.begin(), instruction_content.end());

                            size_t count = cs_disasm(handle, instruction_bytes.data(), instruction_bytes.size(), reference->address, 0, &insn);
                            if (count > 0) {
                                const cs_detail* detail = insn[0].detail;
                                cs_insn& instruction = insn[0];
                                if (detail) {
                                    uint64_t instruction_address = reference->address - function->patch_address + function->new_address;
                                    std::string new_instruction;

                                    if (detail->x86.operands[0].type == X86_OP_MEM && detail->x86.operands[0].mem.base == X86_REG_RIP) {
                                        uint32_t new_disp = ref_function->target_address + entrypoint_difference - instruction_address - instruction.size;
                                        uint32_t old_disp = detail->x86.operands[0].mem.disp;

                                        new_instruction = std::string(instruction.mnemonic) + " " + instruction.op_str;
                                
                                        size_t disp_pos = new_instruction.find(decimal_to_hex(old_disp));
                                        if (disp_pos != std::string::npos) {
                                            new_instruction.replace(disp_pos, decimal_to_hex(old_disp).length(), decimal_to_hex(new_disp));
                                        }
                                    }

                                    else if (detail->x86.operands[0].type == X86_OP_IMM) {
                                        uint32_t new_disp = ref_function->target_address + entrypoint_difference - instruction_address;
                                        new_instruction = std::string(instruction.mnemonic) + " " + decimal_to_hex(new_disp);  
                                    }

                                    try {
                                        std::vector<uint8_t> new_instruction_bytes = assemble_instruction(new_instruction);
                                        output_binary->patch_address(instruction_address, new_instruction_bytes);
                                    } catch (const std::exception& e) {
                                        throw std::runtime_error("Relocator failed");
                                    }
                                }
                            }
                            cs_free(insn, count);
                        }

                        else if (ref_function->operation == OperationType::Add || ref_function->operation == OperationType::Fix) {
                            cs_insn* insn = nullptr;
                            auto instruction_content = patch_binary->get_content_from_virtual_address(reference->address, reference->size);
                            std::vector<uint8_t> instruction_bytes(instruction_content.begin(), instruction_content.end());

                            size_t count = cs_disasm(handle, instruction_bytes.data(), instruction_bytes.size(), reference->address, 0, &insn);
                            if (count > 0) {
                                const cs_detail* detail = insn[0].detail;
                                cs_insn& instruction = insn[0];
                                if (detail) {
                                    uint64_t instruction_address = reference->address - function->patch_address + function->new_address;
                                    std::string new_instruction;

                                    if (detail->x86.operands[0].type == X86_OP_MEM && detail->x86.operands[0].mem.base == X86_REG_RIP) {
                                        uint32_t new_disp = ref_function->new_address - instruction_address - instruction.size;
                                        uint32_t old_disp = detail->x86.operands[0].mem.disp;

                                        new_instruction = std::string(instruction.mnemonic) + " " + instruction.op_str;
                                
                                        size_t disp_pos = new_instruction.find(decimal_to_hex(old_disp));
                                        if (disp_pos != std::string::npos) {
                                            new_instruction.replace(disp_pos, decimal_to_hex(old_disp).length(), decimal_to_hex(new_disp));
                                        }
                                    }

                                    else if (detail->x86.operands[0].type == X86_OP_IMM) {
                                        uint32_t new_disp = ref_function->new_address - instruction_address;
                                        new_instruction = std::string(instruction.mnemonic) + " " + decimal_to_hex(new_disp);  
                                    }

                                    try {
                                        std::vector<uint8_t> new_instruction_bytes = assemble_instruction(new_instruction);
                                        output_binary->patch_address(instruction_address, new_instruction_bytes);
                                    } catch (const std::exception& e) {
                                        throw std::runtime_error("Relocator failed");
                                    }
                                }
                            }
                            cs_free(insn, count);
                        }
                    } else {
                        throw std::runtime_error("Relocator failed");
                    }
                }
            }
        }

        // Replace original functions with fix_ patched functions (install hook to new function)
        if (function->operation == OperationType::Fix) {
            auto new_target_address = function->target_address + entrypoint_difference;
            
            std::string new_instruction = "jmp " + decimal_to_hex(function->new_address - new_target_address);

            std::vector<uint8_t> new_instruction_bytes = assemble_instruction(new_instruction);                  

            output_binary->patch_address(new_target_address, new_instruction_bytes);
        }        
    }
    
    std::cout << "\033[1;32m[+]\033[0m Relocated all functions" << std::endl;
    cs_close(&handle);

    output_binary->write(output_binary_path);
}

#endif // RELOCATOR_HPP