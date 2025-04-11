#include <capstone/capstone.h>

#include "utils.hpp"

#ifndef RELOCATOR_HPP
#define RELOCATOR_HPP

void relocate(const std::string& patch_binary_path, const std::string& target_binary_path, const std::string& output_binary_path,
                GlobalVarTree& global_var_tree, FunctionTree& function_tree) {
    
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

    for (auto& function : function_tree.get_functions()) {
        // Relocate ref_ symbols referenced by patched functions
        if (function->operation != OperationType::Ref) {
            for (auto& reference : function->reference_table->get_references()) {
                // ref_ global variables
                if (reference->reference_type == SymbolType::GlobalVariable) {
                    auto ref_global_var = global_var_tree.find_global_var(reference->reference_address);
                    if (ref_global_var) {
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
                                    uint64_t new_disp = ref_global_var->target_address + entrypoint_difference - instruction_address - instruction.size;
                                    uint64_t old_disp = detail->x86.operands[0].mem.disp;                            
                                    size_t disp_pos = new_instruction.find(decimal_to_hex(old_disp));
                                    if (disp_pos != std::string::npos) {
                                        new_instruction.replace(disp_pos, decimal_to_hex(old_disp).length(), decimal_to_hex(new_disp));
                                    }
                                }

                                // Memory on RHS
                                else if (detail->x86.operands[1].type == X86_OP_MEM && detail->x86.operands[1].mem.base == X86_REG_RIP) {
                                    uint64_t new_disp = ref_global_var->target_address + entrypoint_difference - instruction_address - instruction.size;
                                    uint64_t old_disp = detail->x86.operands[1].mem.disp;
                            
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
                                        uint64_t new_disp = ref_function->target_address + entrypoint_difference - instruction_address - instruction.size;
                                        uint64_t old_disp = detail->x86.operands[0].mem.disp;

                                        new_instruction = std::string(instruction.mnemonic) + " " + instruction.op_str;
                                
                                        size_t disp_pos = new_instruction.find(decimal_to_hex(old_disp));
                                        if (disp_pos != std::string::npos) {
                                            new_instruction.replace(disp_pos, decimal_to_hex(old_disp).length(), decimal_to_hex(new_disp));
                                        }
                                    }

                                    else if (detail->x86.operands[0].type == X86_OP_IMM) {
                                        uint64_t new_disp = ref_function->target_address + entrypoint_difference - instruction_address;
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

                        else if (ref_function->operation == OperationType::Add) {
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
                                        uint64_t new_disp = ref_function->new_address - instruction_address - instruction.size;
                                        uint64_t old_disp = detail->x86.operands[0].mem.disp;

                                        new_instruction = std::string(instruction.mnemonic) + " " + instruction.op_str;
                                
                                        size_t disp_pos = new_instruction.find(decimal_to_hex(old_disp));
                                        if (disp_pos != std::string::npos) {
                                            new_instruction.replace(disp_pos, decimal_to_hex(old_disp).length(), decimal_to_hex(new_disp));
                                        }
                                    }

                                    else if (detail->x86.operands[0].type == X86_OP_IMM) {
                                        uint64_t new_disp = ref_function->new_address - instruction_address;
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
    
    cs_close(&handle);

    output_binary->write(output_binary_path);
}

#endif // RELOCATOR_HPP