
#include <map>
#include <memory> 

#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include "utils.hpp"

#ifndef RELOCATOR_HPP
#define RELOCATOR_HPP

void relocate(const std::string& patch_binary_path, const std::string& target_binary_path, const std::string& output_binary_path,
                GlobalVarMap& global_var_map, FunctionMap& function_map, const std::string new_section_indicator) {
    
    std::unique_ptr<LIEF::ELF::Binary> patch_binary = LIEF::ELF::Parser::parse(patch_binary_path);
    std::unique_ptr<LIEF::ELF::Binary> target_binary = LIEF::ELF::Parser::parse(target_binary_path);
    std::unique_ptr<LIEF::ELF::Binary> output_binary = LIEF::ELF::Parser::parse(output_binary_path);

    std::map<uint64_t, uint64_t> got_entries;

    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize Capstone");
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // Map content of .got section if exists
    if (patch_binary->has_section(".got")) {
        uint64_t new_got_section_address = output_binary->get_section(".got." + new_section_indicator)->virtual_address();

        size_t index = 0;
        for (const LIEF::ELF::Relocation& rel : patch_binary->pltgot_relocations()) {
            const LIEF::ELF::Symbol* original_symbol = rel.symbol();

            LIEF::ELF::Symbol new_symbol = *original_symbol;
            LIEF::ELF::Symbol* added_symbol = &output_binary->add_dynamic_symbol(new_symbol);

            uint64_t entry_address = new_got_section_address + (index++ * 8);

            LIEF::ELF::Relocation new_relocation(entry_address, rel.type(), rel.encoding());

            new_relocation.symbol(added_symbol);

            output_binary->add_dynamic_relocation(new_relocation);

            got_entries[rel.address()] = entry_address;

            print_green("Mapped symbol " + new_symbol.name() + " to target binary");
        }
    }

    // Add and relocate .rela.dyn section if exists
    for (const LIEF::ELF::Relocation& rel : patch_binary->dynamic_relocations()) {
        if (rel.type() != LIEF::ELF::Relocation::TYPE::X86_64_RELATIVE)
            continue;

        uint64_t old_offset = rel.address();
        uint64_t old_addend = rel.addend();

        LIEF::ELF::Section* old_section = patch_binary->section_from_virtual_address(old_offset);
        if (output_binary->has_section(old_section->name() + "." + new_section_indicator)) {
            uint64_t new_offset = rel.address() - old_section->virtual_address() + output_binary->get_section(old_section->name() + "." + new_section_indicator)->virtual_address();

            LIEF::ELF::Relocation new_rel(new_offset, rel.type(), rel.encoding());
            new_rel.addend(old_addend);
            output_binary->add_dynamic_relocation(new_rel);
        }
    }

    std::cout << "\033[1;32m[+]\033[0m Relocated .rela.dyn RELATIVE entries" << std::endl;

    // Relocate content of .plt.sec section if exists
    if (patch_binary->has_section(".plt.sec")) {
        LIEF::ELF::Section* pltsec_section = patch_binary->get_section(".plt.sec");
        LIEF::ELF::Section* patched_pltsec_section = output_binary->get_section(".plt.sec." + new_section_indicator);

        auto section_content = patch_binary->get_content_from_virtual_address(pltsec_section->virtual_address(), pltsec_section->size());
        std::vector<uint8_t> section_bytes(section_content.begin(), section_content.end());

        cs_insn* insn = nullptr;

        size_t count = cs_disasm(handle, section_bytes.data(), section_bytes.size(), pltsec_section->virtual_address(), 0, &insn);
        if (count > 0) {
            for (int index = 0; index < count; ++index) {
                const cs_detail* detail = insn[index].detail;
                cs_insn& instruction = insn[index];

                if (detail && (cs_insn_group(handle, &instruction, CS_GRP_JUMP) || cs_insn_group(handle, &instruction, CS_GRP_CALL))) {
                    std::string new_instruction;
                    uint64_t patched_binary_address = instruction.address - pltsec_section->virtual_address() + patched_pltsec_section->virtual_address();

                    if (detail->x86.operands[0].type == X86_OP_MEM && detail->x86.operands[0].mem.base == X86_REG_RIP) {
                        uint64_t old_address = instruction.address + instruction.size + detail->x86.operands[0].mem.disp;
                        uint64_t new_address = got_entries[old_address];

                        uint32_t old_disp = detail->x86.operands[0].mem.disp;
                        uint32_t new_disp = new_address - instruction.size - patched_binary_address;

                        new_instruction = std::string(instruction.mnemonic) + " " + instruction.op_str;
                
                        size_t disp_pos = new_instruction.find(decimal_to_hex(old_disp));
                        if (disp_pos != std::string::npos) {
                            new_instruction.replace(disp_pos, decimal_to_hex(old_disp).length(), decimal_to_hex(new_disp));
                        }
                    }

                    else if (detail->x86.operands[0].type == X86_OP_IMM) {
                        uint64_t old_address = instruction.address + detail->x86.operands[0].mem.disp;
                        uint64_t new_address = got_entries[old_address];

                        uint32_t new_disp = new_address - patched_binary_address;
                        new_instruction = std::string(instruction.mnemonic) + " " + decimal_to_hex(new_disp);  
                    }

                    try {
                        std::vector<uint8_t> new_instruction_bytes = assemble_instruction(new_instruction);
                        output_binary->patch_address(patched_binary_address, new_instruction_bytes);
                    } catch (const std::exception& e) {
                        throw std::runtime_error("Relocator failed");
                    }
                }
            }
        }
        cs_free(insn, count);
    }

    output_binary->write(output_binary_path);

    std::cout << "\033[1;32m[+]\033[0m Relocated .got and .plt entries" << std::endl;

    // The above part pushed the target binary down
    uint64_t entrypoint_difference = output_binary->header().entrypoint() - target_binary->header().entrypoint();

    // Find new address of functions
    for (auto& function : function_map.get_functions()) {
            uint64_t new_text_section_address = output_binary->get_section(".text." + new_section_indicator)->virtual_address();
            function->new_address += new_text_section_address;
        }


    // Find new address of global variables
    for (auto& global_var : global_var_map.get_global_vars()) {
        if (global_var->operation != OperationType::Ref) {
            LIEF::ELF::Section* assoc_section = patch_binary->section_from_virtual_address(global_var->patch_address);
        
            uint64_t offset_in_section = global_var->patch_address - assoc_section->virtual_address();
            uint64_t new_address = output_binary->get_section(assoc_section->name() + "." + new_section_indicator)->virtual_address() + offset_in_section;

            global_var->new_address = new_address;
        }
    }

    // Relocate global variables
    for (auto& global_var : global_var_map.get_global_vars()) {
        auto variable_type = global_var->variable_type;

        // We only care about pointer variables
        if (variable_type.pointer_depth > 0) {
            // Recursive fix for all elements
            uint64_t element_count = std::max<uint64_t>(1, variable_type.element_count);

            for (uint64_t element_idx = 0; element_idx < element_count; ++element_idx) {
                uint64_t element_address = global_var->patch_address + 8 * element_idx;
                for (uint64_t depth = 0; depth < variable_type.pointer_depth; ++depth) {
                    // Get 8-byte content at the address (64-bit pointers)
                    auto element_content = patch_binary->get_content_from_virtual_address(element_address, 8);
                    if (element_content.size() != 8) {
                        break;
                    }

                    uint64_t element_value = vector_to_int(std::vector<uint8_t>(element_content.begin(), element_content.end()));

                    // Get original section from element value
                    LIEF::ELF::Section* assoc_section_value = patch_binary->section_from_virtual_address(element_value);
                    if (!assoc_section_value) {
                        break;
                    }

                    // Find relocated section in output binary
                    std::string new_section_value_name = assoc_section_value->name() + "." + new_section_indicator;
                    LIEF::ELF::Section* new_section_value = output_binary->get_section(new_section_value_name);
                    if (!new_section_value) {
                        break;
                    }

                    // Calculate new value for the pointer
                    uint64_t new_element_value = element_value - assoc_section_value->virtual_address() + new_section_value->virtual_address();
                    std::vector<uint8_t> new_element_content;
                    for (size_t i = 0; i < sizeof(uint64_t); ++i) {
                        new_element_content.push_back(static_cast<uint8_t>(new_element_value & 0xFF)); 
                        new_element_value >>= 8;
                    }

                    // Get original section from element address
                    LIEF::ELF::Section* assoc_section_address = patch_binary->section_from_virtual_address(element_address);
                    if (!assoc_section_address) {
                        break;
                    }

                    // Find relocated section in output binary
                    std::string new_section_address_name = assoc_section_address->name() + "." + new_section_indicator;
                    LIEF::ELF::Section* new_section_address = output_binary->get_section(new_section_address_name);

                    if (!new_section_address) {
                        break;
                    }
                    
                    uint64_t new_element_address = element_address - assoc_section_address->virtual_address() + new_section_address->virtual_address();
                    
                    // Patch the value in output binary
                    output_binary->patch_address(new_element_address, new_element_content);

                    element_address = new_element_value;
                }
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
    for (auto& function : function_map.get_functions()) {
        // Relocate references from patched functions
        if (function->operation != OperationType::Ref) {
            for (auto& reference : function->reference_table->get_references()) {
                // ref_ global variables
                if (reference->reference_type == SymbolType::GlobalVariable) {

                    // Check if it is referencing read-only data
                    LIEF::ELF::Section* original_section = patch_binary->section_from_virtual_address(reference->reference_address);
                    if (original_section && original_section->name() == ".rodata") {
                        uint64_t new_rodata_variable_address = output_binary->get_section(".rodata." + new_section_indicator)->virtual_address() + reference->reference_address - original_section->virtual_address();

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
                                    uint32_t new_disp = new_rodata_variable_address - instruction_address - instruction.size;
                                    uint32_t old_disp = detail->x86.operands[0].mem.disp;                            
                                    size_t disp_pos = new_instruction.find(decimal_to_hex(old_disp));
                                    if (disp_pos != std::string::npos) {
                                        new_instruction.replace(disp_pos, decimal_to_hex(old_disp).length(), decimal_to_hex(new_disp));
                                    }
                                }

                                // Memory on RHS
                                else if (detail->x86.operands[1].type == X86_OP_MEM && detail->x86.operands[1].mem.base == X86_REG_RIP) {
                                    uint32_t new_disp = new_rodata_variable_address - instruction_address - instruction.size;
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

                        // Skip the below check
                        continue;
                    }

                    // Check if it is referencing defined global variables in patch binary
                    GlobalVar* ref_global_var = global_var_map.find_global_var(reference->reference_address);
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
                        print_red("Failed to query for global variable at " + decimal_to_hex(reference->reference_address) + " in patch binary");
                        throw std::runtime_error("Relocator failed");
                    }
                }

                // ref_ functions
                else if (reference->reference_type == SymbolType::Function) {

                    // Check if it is referencing dynamically linked functions
                    LIEF::ELF::Section* original_section = patch_binary->section_from_virtual_address(reference->reference_address);
                    if (original_section->name() == ".plt.sec") {
                        LIEF::ELF::Section* patched_pltsec_section = output_binary->get_section(".plt.sec." + new_section_indicator);
                        uint64_t new_pltsec_address = reference->reference_address - original_section->virtual_address() + patched_pltsec_section->virtual_address();

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
                                    uint32_t new_disp = new_pltsec_address - instruction_address - instruction.size;
                                    uint32_t old_disp = detail->x86.operands[0].mem.disp;

                                    new_instruction = std::string(instruction.mnemonic) + " " + instruction.op_str;
                            
                                    size_t disp_pos = new_instruction.find(decimal_to_hex(old_disp));
                                    if (disp_pos != std::string::npos) {
                                        new_instruction.replace(disp_pos, decimal_to_hex(old_disp).length(), decimal_to_hex(new_disp));
                                    }
                                }

                                else if (detail->x86.operands[0].type == X86_OP_IMM) {
                                    uint32_t new_disp = new_pltsec_address - instruction_address;
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

                        // Skip the below part
                        continue;
                    }

                    Function* ref_function = function_map.find_function(reference->reference_address);
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
                        print_red("Failed to query for function at " + decimal_to_hex(reference->reference_address) + " in patch binary");
                        // throw std::runtime_error("Relocator failed");
                    }
                }
            }
        }

        // Replace original functions with fix_ patched functions (install hook to new function)
        if (function->operation == OperationType::Fix) {
            uint64_t new_target_address = function->target_address + entrypoint_difference;
            
            std::string new_instruction = "jmp " + decimal_to_hex(function->new_address - new_target_address);

            std::vector<uint8_t> new_instruction_bytes = assemble_instruction(new_instruction); 
             
            output_binary->patch_address(new_target_address, new_instruction_bytes);
        }        
    }
    
    cs_close(&handle);
    std::cout << "\033[1;32m[+]\033[0m Relocated all functions" << std::endl;

    // Finally, update addend of RELATIVE relocations
    for (LIEF::ELF::Relocation& r : output_binary->dynamic_relocations()) {
        if (r.type() == LIEF::ELF::Relocation::TYPE::X86_64_RELATIVE) {
            auto addend_vector = output_binary->get_content_from_virtual_address(r.address(), 8);
            r.addend(vector_to_int(std::vector<uint8_t>(addend_vector.begin(), addend_vector.end())));
        }
    }

    std::cout << "\033[1;32m[+]\033[0m Updated .rela.dyn RELATIVE addends" << std::endl;

    output_binary->write(output_binary_path);
}

#endif // RELOCATOR_HPP