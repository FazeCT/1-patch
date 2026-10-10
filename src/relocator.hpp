
#include <map>
#include <memory> 
#include <algorithm>

#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include "utils.hpp"

#ifndef RELOCATOR_HPP
#define RELOCATOR_HPP

void require_target_range(LIEF::ELF::Binary& binary, uint64_t address,
                          uint64_t size, bool executable) {
    LIEF::ELF::Section* section = binary.section_from_virtual_address(address);
    if (!section || !section->has(LIEF::ELF::Section::FLAGS::ALLOC) ||
        section->type() == LIEF::ELF::Section::TYPE::NOBITS ||
        size == 0 ||
        section->has(LIEF::ELF::Section::FLAGS::EXECINSTR) != executable ||
        address < section->virtual_address() ||
        address - section->virtual_address() > section->size() ||
        size > section->size() - (address - section->virtual_address())) {
        throw std::runtime_error("Patch write is outside a compatible target section");
    }
}

LIEF::ELF::Section* require_section(LIEF::ELF::Binary& binary,
                                    const std::string& name) {
    LIEF::ELF::Section* section = binary.get_section(name);
    if (!section) {
        throw std::runtime_error("Missing ELF section: " + name);
    }
    return section;
}

// LIEF can insert bytes inside a PT_LOAD segment while leaving its starting
// address unchanged. Map file-backed addresses through their original section
// headers so references within that segment follow the moved code and data.
// For NOBITS (notably .bss), use PT_LOAD instead: LIEF can move its section
// header independently of the zero-filled memory used by the loader.
uint64_t translate_target_address(const LIEF::ELF::Binary& original,
                                  const LIEF::ELF::Binary& output,
                                  uint64_t address) {
    const LIEF::ELF::Section* source_section =
        original.section_from_virtual_address(address);
    if (source_section &&
        source_section->has(LIEF::ELF::Section::FLAGS::ALLOC) &&
        source_section->type() != LIEF::ELF::Section::TYPE::NOBITS &&
        address >= source_section->virtual_address() &&
        address - source_section->virtual_address() < source_section->size()) {
        const LIEF::ELF::Section* destination_section =
            output.get_section(source_section->name());
        if (!destination_section ||
            !destination_section->has(LIEF::ELF::Section::FLAGS::ALLOC) ||
            destination_section->type() != source_section->type() ||
            destination_section->size() < source_section->size() ||
            destination_section->virtual_address() > UINT64_MAX -
                (address - source_section->virtual_address())) {
            throw std::runtime_error("Target section could not be mapped into output");
        }
        return destination_section->virtual_address() +
               (address - source_section->virtual_address());
    }

    // Match the original load segments to the corresponding output load
    // segments; newly added patch segments are appended after them.
    std::vector<const LIEF::ELF::Segment*> original_loads;
    std::vector<const LIEF::ELF::Segment*> output_loads;
    for (const LIEF::ELF::Segment& segment : original.segments()) {
        if (segment.is_load()) original_loads.push_back(&segment);
    }
    for (const LIEF::ELF::Segment& segment : output.segments()) {
        if (segment.is_load()) output_loads.push_back(&segment);
    }
    if (output_loads.size() < original_loads.size()) {
        throw std::runtime_error("Original load segments are missing from output");
    }

    for (size_t index = 0; index < original_loads.size(); ++index) {
        const LIEF::ELF::Segment& source = *original_loads[index];
        if (address < source.virtual_address() ||
            address - source.virtual_address() >= source.virtual_size()) {
            continue;
        }
        const LIEF::ELF::Segment& destination = *output_loads[index];
        const uint64_t offset = address - source.virtual_address();
        if (destination.flags() != source.flags() ||
            offset >= destination.virtual_size() ||
            destination.virtual_address() > UINT64_MAX - offset) {
            throw std::runtime_error("Target load segment could not be mapped into output");
        }
        return destination.virtual_address() + offset;
    }
    throw std::runtime_error("Target address has no load segment");
}

int64_t checked_relative_displacement(uint64_t target, uint64_t next_instruction,
                                      size_t encoded_size) {
    if (encoded_size != 1 && encoded_size != 2 && encoded_size != 4) {
        throw std::runtime_error("Unsupported relative displacement size");
    }
    const uint64_t positive_limit = (uint64_t{1} << (encoded_size * 8 - 1)) - 1;
    const uint64_t negative_limit = positive_limit + 1;
    auto out_of_range = [&]() {
        return std::runtime_error(
            "Relocated branch is out of range: target " + decimal_to_hex(target) +
            ", next instruction " + decimal_to_hex(next_instruction) +
            ", displacement size " + std::to_string(encoded_size) + " byte(s)");
    };
    if (target >= next_instruction) {
        const uint64_t distance = target - next_instruction;
        if (distance > positive_limit) {
            throw out_of_range();
        }
        return static_cast<int64_t>(distance);
    }
    const uint64_t distance = next_instruction - target;
    if (distance > negative_limit) {
        throw out_of_range();
    }
    return -static_cast<int64_t>(distance);
}

void write_relative_displacement(std::vector<uint8_t>& bytes, size_t offset,
                                 size_t encoded_size, uint64_t target,
                                 uint64_t next_instruction) {
    if (offset == 0 || offset > bytes.size() ||
        encoded_size > bytes.size() - offset) {
        throw std::runtime_error("Instruction displacement is outside its encoding");
    }
    uint64_t encoded = static_cast<uint64_t>(
        checked_relative_displacement(target, next_instruction, encoded_size));
    for (size_t i = 0; i < encoded_size; ++i) {
        bytes[offset + i] = static_cast<uint8_t>(encoded);
        encoded >>= 8;
    }
}

bool relative_displacement_fits(uint64_t target, uint64_t next_instruction,
                                size_t encoded_size) {
    if (encoded_size != 1 && encoded_size != 2 && encoded_size != 4) {
        return false;
    }
    const uint64_t positive_limit = (uint64_t{1} << (encoded_size * 8 - 1)) - 1;
    const uint64_t negative_limit = positive_limit + 1;
    return target >= next_instruction
        ? target - next_instruction <= positive_limit
        : next_instruction - target <= negative_limit;
}

uint64_t relocated_instruction_address(uint64_t address, uint64_t old_base,
                                       uint64_t new_base, uint64_t size) {
    if (address < old_base || address - old_base > UINT64_MAX - new_base ||
        size > UINT64_MAX - (address - old_base + new_base)) {
        throw std::runtime_error("Relocated instruction address overflows");
    }
    return address - old_base + new_base;
}

void patch_reference(csh handle, LIEF::ELF::Binary& output_binary,
                     const std::vector<uint8_t>& instruction_bytes,
                     uint64_t start_address, uint64_t old_base,
                     uint64_t new_base, uint64_t new_address,
                     bool allow_direct_branch) {
    cs_insn* insn = nullptr;
    const size_t count = cs_disasm(handle, instruction_bytes.data(),
                                   instruction_bytes.size(), start_address, 1, &insn);
    if (count != 1) {
        cs_free(insn, count);
        throw std::runtime_error("Failed to decode relocation instruction");
    }
    try {
        const cs_insn& instruction = insn[0];
        if (instruction.size != instruction_bytes.size() || !instruction.detail) {
            throw std::runtime_error("Relocation instruction has an invalid size or detail");
        }
        const cs_x86& x86 = instruction.detail->x86;
        const uint64_t output_address = relocated_instruction_address(
            instruction.address, old_base, new_base, instruction.size);
        const uint64_t next_instruction = output_address + instruction.size;
        std::vector<uint8_t> replacement = instruction_bytes;
        bool patched = false;
        for (uint8_t i = 0; i < x86.op_count; ++i) {
            if (x86.operands[i].type == X86_OP_MEM &&
                x86.operands[i].mem.base == X86_REG_RIP) {
                // RIP-relative memory operands in 64-bit mode encode a
                // signed disp32, even when an operand-size prefix is present.
                // Capstone's reported disp_size can be shorter for these
                // instructions, so use the architectural width.
                write_relative_displacement(replacement, x86.encoding.disp_offset,
                                            4, new_address,
                                            next_instruction);
                patched = true;
                break;
            }
        }
        if (!patched && allow_direct_branch && x86.op_count > 0 &&
            x86.operands[0].type == X86_OP_IMM &&
            (cs_insn_group(handle, &instruction, CS_GRP_CALL) ||
             cs_insn_group(handle, &instruction, CS_GRP_JUMP))) {
            write_relative_displacement(replacement, x86.encoding.imm_offset,
                                        x86.encoding.imm_size, new_address,
                                        next_instruction);
            patched = true;
        }
        if (!patched) {
            throw std::runtime_error("Unsupported instruction reference encoding");
        }
        output_binary.patch_address(output_address, replacement);
    } catch (...) {
        cs_free(insn, count);
        throw;
    }
    cs_free(insn, count);
}

// Adding patch sections can move allocatable sections in an ET_DYN binary.
// Repair existing references after the merge and redirect direct branches to
// fixed functions. PIE globals commonly need RIP-relative load adjustments.
void relocate_existing_target_references(
    csh handle, const LIEF::ELF::Binary& original,
    LIEF::ELF::Binary& output, const FunctionMap& function_map) {
    std::map<uint64_t, uint64_t> replacements;
    for (const Function* function : function_map.get_functions()) {
        if (function->operation == OperationType::Fix) {
            replacements[function->target_address] = function->new_address;
        }
    }

    for (const LIEF::ELF::Section& source_section : original.sections()) {
        if (!source_section.has(LIEF::ELF::Section::FLAGS::EXECINSTR) ||
            source_section.size() == 0) {
            continue;
        }

        LIEF::ELF::Section* output_section = output.get_section(source_section.name());
        if (!output_section || output_section->size() < source_section.size()) {
            throw std::runtime_error("Target executable section could not be mapped");
        }

        auto content = original.get_content_from_virtual_address(
            source_section.virtual_address(), source_section.size());
        std::vector<uint8_t> section_bytes(content.begin(), content.end());
        cs_insn* instructions = nullptr;
        const size_t count = cs_disasm(handle, section_bytes.data(),
                                       section_bytes.size(),
                                       source_section.virtual_address(), 0,
                                       &instructions);
        if (count == 0) {
            cs_free(instructions, count);
            continue;
        }

        try {
            for (size_t index = 0; index < count; ++index) {
                const cs_insn& instruction = instructions[index];
                if (!instruction.detail) continue;
                const cs_x86& x86 = instruction.detail->x86;
                uint64_t referenced_address = 0;
                bool direct_reference = false;

                for (uint8_t operand = 0; operand < x86.op_count; ++operand) {
                    if (x86.operands[operand].type == X86_OP_MEM &&
                        x86.operands[operand].mem.base == X86_REG_RIP) {
                        referenced_address = instruction.address + instruction.size +
                                             x86.operands[operand].mem.disp;
                        break;
                    }
                }
                if (referenced_address == 0 && x86.op_count > 0 &&
                    x86.operands[0].type == X86_OP_IMM &&
                    (cs_insn_group(handle, &instruction, CS_GRP_CALL) ||
                     cs_insn_group(handle, &instruction, CS_GRP_JUMP))) {
                    referenced_address = x86.operands[0].imm;
                    direct_reference = true;
                }
                if (referenced_address == 0) continue;

                uint64_t relocated_reference = 0;
                try {
                    relocated_reference = translate_target_address(
                        original, output, referenced_address);
                } catch (const std::runtime_error&) {
                    // External addresses and unresolved indirect targets are
                    // handled by the dynamic linker and need no rewrite.
                    continue;
                }

                if (instruction.address > UINT64_MAX - instruction.size) {
                    throw std::runtime_error("Target instruction address overflows");
                }
                const uint64_t output_address = relocated_instruction_address(
                    instruction.address, source_section.virtual_address(),
                    output_section->virtual_address(), instruction.size);
                // Calls and tail jumps with an immediate target can go straight
                // to fix_. Keep the old entry jump for indirect callers and
                // for branches whose encoding cannot reach the replacement.
                if (direct_reference) {
                    auto replacement = replacements.find(referenced_address);
                    if (replacement != replacements.end() &&
                        relative_displacement_fits(replacement->second,
                                                   output_address + instruction.size,
                                                   x86.encoding.imm_size)) {
                        relocated_reference = replacement->second;
                    }
                }
                // A section that moves together with its reference keeps the
                // same encoded displacement. Leave those bytes untouched.
                if (relocated_reference - (output_address + instruction.size) ==
                    referenced_address - (instruction.address + instruction.size)) {
                    continue;
                }

                const size_t offset = static_cast<size_t>(
                    instruction.address - source_section.virtual_address());
                if (offset > section_bytes.size() ||
                    instruction.size > section_bytes.size() - offset) {
                    throw std::runtime_error("Target instruction exceeds its section");
                }
                std::vector<uint8_t> instruction_bytes(
                    section_bytes.begin() + offset,
                    section_bytes.begin() + offset + instruction.size);
                patch_reference(handle, output, instruction_bytes,
                                instruction.address,
                                source_section.virtual_address(),
                                output_section->virtual_address(),
                                relocated_reference, direct_reference);
            }
        } catch (...) {
            cs_free(instructions, count);
            throw;
        }
        cs_free(instructions, count);
    }
}

void relocate(const std::string& patch_binary_path, const std::string& target_binary_path, const std::string& output_binary_path,
                GlobalVarMap& global_var_map, FunctionMap& function_map,
                std::string new_section_indicator, bool allow_unverified_targets = false) {
    
    std::unique_ptr<LIEF::ELF::Binary> patch_binary = LIEF::ELF::Parser::parse(patch_binary_path);
    std::unique_ptr<LIEF::ELF::Binary> target_binary = LIEF::ELF::Parser::parse(target_binary_path);
    std::unique_ptr<LIEF::ELF::Binary> output_binary = LIEF::ELF::Parser::parse(output_binary_path);
    if (!patch_binary || !target_binary || !output_binary) {
        throw std::runtime_error("Failed to parse a relocation input binary");
    }

    std::map<uint64_t, uint64_t> got_entries;

    csh handle;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize Capstone");
    }
    struct ScopedCapstone {
        csh& handle;
        ~ScopedCapstone() { cs_close(&handle); }
    } scoped_capstone{handle};
    if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
        throw std::runtime_error("Failed to enable Capstone instruction detail");
    }

    // Map content of .got section if exists
    if (patch_binary->has_section(".got")) {
        LIEF::ELF::Section* new_got_section = require_section(*output_binary, ".got." + new_section_indicator);
        uint64_t new_got_section_address = new_got_section->virtual_address();

        size_t index = 0;
        for (const LIEF::ELF::Relocation& rel : patch_binary->pltgot_relocations()) {
            const LIEF::ELF::Symbol* original_symbol = rel.symbol();
            if (!original_symbol) {
                throw std::runtime_error("GOT relocation has no symbol");
            }

            LIEF::ELF::Symbol new_symbol = *original_symbol;
            LIEF::ELF::Symbol* added_symbol = &output_binary->add_dynamic_symbol(new_symbol);

            if (index >= new_got_section->size() / sizeof(uint64_t)) {
                throw std::runtime_error("Relocated GOT exceeds allocated section");
            }
            uint64_t entry_address = new_got_section_address + (index++ * 8);

            LIEF::ELF::Relocation new_relocation(entry_address, rel.type(), rel.encoding());

            new_relocation.symbol(added_symbol);

            output_binary->add_dynamic_relocation(new_relocation);

            got_entries[rel.address()] = entry_address;

            verbose_print::print_green("Mapped symbol " + new_symbol.name() + " to target binary");
        }
    }

    // Add and relocate .rela.dyn section if exists
    for (const LIEF::ELF::Relocation& rel : patch_binary->dynamic_relocations()) {
        if (rel.type() != LIEF::ELF::Relocation::TYPE::X86_64_RELATIVE)
            continue;

        uint64_t old_offset = rel.address();
        uint64_t old_addend = rel.addend();

        LIEF::ELF::Section* old_section = patch_binary->section_from_virtual_address(old_offset);
        if (!old_section) {
            throw std::runtime_error("Dynamic relocation has no source section");
        }
        if (output_binary->has_section(old_section->name() + "." + new_section_indicator)) {
            uint64_t new_offset = rel.address() - old_section->virtual_address() +
                require_section(*output_binary, old_section->name() + "." + new_section_indicator)->virtual_address();

            LIEF::ELF::Relocation new_rel(new_offset, rel.type(), rel.encoding());
            new_rel.addend(old_addend);
            output_binary->add_dynamic_relocation(new_rel);
        }
    }

    // Relocate content of .plt.sec section if exists
    if (patch_binary->has_section(".plt.sec")) {
        LIEF::ELF::Section* pltsec_section = patch_binary->get_section(".plt.sec");
        LIEF::ELF::Section* patched_pltsec_section = require_section(*output_binary, ".plt.sec." + new_section_indicator);

        auto section_content = patch_binary->get_content_from_virtual_address(pltsec_section->virtual_address(), pltsec_section->size());
        std::vector<uint8_t> section_bytes(section_content.begin(), section_content.end());

        cs_insn* insn = nullptr;

        size_t count = cs_disasm(handle, section_bytes.data(), section_bytes.size(), pltsec_section->virtual_address(), 0, &insn);
        if (count > 0) {
            try {
                for (size_t index = 0; index < count; ++index) {
                    const cs_detail* detail = insn[index].detail;
                    cs_insn& instruction = insn[index];

                    if (detail && detail->x86.op_count > 0 &&
                        (cs_insn_group(handle, &instruction, CS_GRP_JUMP) ||
                         cs_insn_group(handle, &instruction, CS_GRP_CALL))) {
                        uint64_t old_address;
                        if (detail->x86.operands[0].type == X86_OP_MEM &&
                            detail->x86.operands[0].mem.base == X86_REG_RIP) {
                            old_address = instruction.address + instruction.size +
                                          detail->x86.operands[0].mem.disp;
                        } else if (detail->x86.operands[0].type == X86_OP_IMM) {
                            old_address = detail->x86.operands[0].imm;
                        } else {
                            continue;
                        }
                        auto mapped = got_entries.find(old_address);
                        if (mapped == got_entries.end()) {
                            throw std::runtime_error("PLT entry has no mapped GOT address");
                        }
                        std::vector<uint8_t> bytes(instruction.bytes,
                                                   instruction.bytes + instruction.size);
                        patch_reference(handle, *output_binary, bytes, instruction.address,
                                        pltsec_section->virtual_address(),
                                        patched_pltsec_section->virtual_address(),
                                        mapped->second, true);
                    }
                }
            } catch (...) {
                cs_free(insn, count);
                throw;
            }
        }
        cs_free(insn, count);
        verbose_print::print_green("Relocated .plt.sec entries");
    }

    output_binary->write(output_binary_path);
    output_binary = LIEF::ELF::Parser::parse(output_binary_path);
    if (!output_binary) {
        throw std::runtime_error("Failed to parse intermediate output binary");
    }

    auto translate_target = [&target_binary, &output_binary](uint64_t address) -> uint64_t {
        return translate_target_address(*target_binary, *output_binary, address);
    };

    // Find new address of functions
    for (auto& function : function_map.get_functions()) {
        if (function->operation != OperationType::Ref) {
            uint64_t new_text_section_address = require_section(*output_binary, ".text." + new_section_indicator)->virtual_address();
            function->new_address += new_text_section_address;
        }
        else {
            function->new_address = translate_target(function->target_address);
        }
    }

    relocate_existing_target_references(handle, *target_binary, *output_binary,
                                        function_map);

    // Find new address of global variables
    for (auto& global_var : global_var_map.get_global_vars()) {
        if (global_var->operation != OperationType::Ref) {
            LIEF::ELF::Section* assoc_section = patch_binary->section_from_virtual_address(global_var->patch_address);
            if (!assoc_section) {
                throw std::runtime_error("Patch variable has no source section");
            }
        
            uint64_t offset_in_section = global_var->patch_address - assoc_section->virtual_address();
            uint64_t new_address = require_section(*output_binary, assoc_section->name() + "." + new_section_indicator)->virtual_address() + offset_in_section;

            global_var->new_address = new_address;
        }
        else {
            global_var->new_address = translate_target(global_var->target_address);
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
            if (new_value.size() != global_var->size) {
                throw std::runtime_error("Patch variable data is incomplete");
            }
            bool known_extent = false;
            for (const auto& symbol : target_binary->symbols()) {
                if (symbol.is_variable() && symbol.size() > 0 &&
                    global_var->target_address >= symbol.value() &&
                    global_var->target_address - symbol.value() < symbol.size()) {
                    known_extent = true;
                    if (global_var->size > symbol.size() -
                        (global_var->target_address - symbol.value())) {
                        throw std::runtime_error("Patch variable exceeds target object size");
                    }
                }
            }
            if (!known_extent && !allow_unverified_targets) {
                throw std::runtime_error("Target variable size is unknown; use --allow-unverified-targets to proceed");
            }
            uint64_t target = translate_target(global_var->target_address);
            require_target_range(*output_binary, target, global_var->size, false);
            output_binary->patch_address(target, std::vector<uint8_t>(new_value.begin(), new_value.end()));
        }

        verbose_print::print_green("Relocated global variable at " + decimal_to_hex(global_var->patch_address) + " of patch binary");
    }   
    
    // Relocate functions
    for (auto& function : function_map.get_functions()) {
        // Relocate references from patched functions
        if (function->operation != OperationType::Ref) {
            for (auto& reference : function->reference_table->get_references()) {
                // ref_ global variables
                if (reference->reference_type == SymbolType::GlobalVariable) {
                    // Check if it is referencing defined global variables in patch binary
                    GlobalVar* ref_global_var = global_var_map.find_global_var(reference->reference_address);
                    if (ref_global_var) {
                        auto instruction_content = patch_binary->get_content_from_virtual_address(reference->address, reference->size);
                        std::vector<uint8_t> instruction_bytes(instruction_content.begin(), instruction_content.end());
                        patch_reference(handle, *output_binary, instruction_bytes, reference->address,
                                        function->patch_address, function->new_address,
                                        ref_global_var->new_address, false);
                        
                    } else {
                        // Check if it is referencing read-only data
                        LIEF::ELF::Section* original_section = patch_binary->section_from_virtual_address(reference->reference_address);
                        if (original_section && original_section->name() == ".rodata") {
                            uint64_t new_rodata_variable_address = require_section(*output_binary, ".rodata." + new_section_indicator)->virtual_address() + reference->reference_address - original_section->virtual_address();

                            auto instruction_content = patch_binary->get_content_from_virtual_address(reference->address, reference->size);
                            std::vector<uint8_t> instruction_bytes(instruction_content.begin(), instruction_content.end());

                            patch_reference(handle, *output_binary, instruction_bytes, reference->address,
                                            function->patch_address, function->new_address,
                                            new_rodata_variable_address, false);
                            continue;
                        }
                        throw std::runtime_error("Unresolved patch global reference at " +
                                                 decimal_to_hex(reference->reference_address));
                    }
                }

                // ref_ functions
                else if (reference->reference_type == SymbolType::Function) {

                    // Check if it is referencing dynamically linked functions
                    LIEF::ELF::Section* original_section = patch_binary->section_from_virtual_address(reference->reference_address);
                    if (original_section && original_section->name() == ".plt.sec") {
                        LIEF::ELF::Section* patched_pltsec_section = output_binary->get_section(".plt.sec." + new_section_indicator);
                        if (!patched_pltsec_section) {
                            throw std::runtime_error("Missing relocated PLT section");
                        }
                        uint64_t new_pltsec_address = reference->reference_address - original_section->virtual_address() + patched_pltsec_section->virtual_address();

                        auto instruction_content = patch_binary->get_content_from_virtual_address(reference->address, reference->size);
                        std::vector<uint8_t> instruction_bytes(instruction_content.begin(), instruction_content.end());

                        patch_reference(handle, *output_binary, instruction_bytes, reference->address,
                                        function->patch_address, function->new_address,
                                        new_pltsec_address, true);
                        continue;
                    }

                    Function* ref_function = function_map.find_function(reference->reference_address);
                    if (ref_function) {
                        auto instruction_content = patch_binary->get_content_from_virtual_address(reference->address, reference->size);
                        std::vector<uint8_t> instruction_bytes(instruction_content.begin(), instruction_content.end());

                        patch_reference(handle, *output_binary, instruction_bytes, reference->address,
                                        function->patch_address, function->new_address,
                                        ref_function->new_address, true);
                    
                    } else {
                        throw std::runtime_error("Unresolved patch function reference at " +
                                                 decimal_to_hex(reference->reference_address));
                    }
                }
            }
        }

        // Leave the original address usable by direct and indirect callers.
        if (function->operation == OperationType::Fix) {
            const uint64_t original_entry = translate_target(function->target_address);
            require_target_range(*output_binary, original_entry, 1, true);
            LIEF::ELF::Section* target_section = output_binary->section_from_virtual_address(original_entry);
            const uint64_t section_remaining = target_section->size() -
                (original_entry - target_section->virtual_address());

            // An indirect call into a CET binary must still land on ENDBR64.
            // The following E9 is a direct jump, so the replacement's ENDBR64
            // is supplied by the compiler rather than needed for this hop.
            auto prefix = output_binary->get_content_from_virtual_address(
                original_entry, std::min<uint64_t>(4, section_remaining));
            const uint64_t landing_pad = prefix.size() == 4 &&
                prefix[0] == 0xF3 && prefix[1] == 0x0F &&
                prefix[2] == 0x1E && prefix[3] == 0xFA ? 4 : 0;

            auto skip_short_entry = [&]() {
                std::cerr << "Skipping fix_ at " << decimal_to_hex(function->target_address)
                          << ": insufficient space for an entry jump\n";
            };
            if (section_remaining < landing_pad + 5) {
                skip_short_entry();
                continue;
            }
            if (original_entry > UINT64_MAX - landing_pad) {
                throw std::runtime_error("Target jump address overflows");
            }
            const uint64_t jump_address = original_entry + landing_pad;

            // Count complete instructions after the optional landing pad.
            // Their total span, including ENDBR64, must fit this function.
            size_t available = std::min<uint64_t>(32, section_remaining - landing_pad);
            auto code = output_binary->get_content_from_virtual_address(jump_address, available);
            cs_insn* original_insn = nullptr;
            size_t instruction_count = cs_disasm(handle, code.data(), code.size(),
                                                  jump_address, 0, &original_insn);
            size_t covered = 0;
            for (size_t i = 0; i < instruction_count && covered < 5; ++i) {
                if (original_insn[i].address != jump_address + covered ||
                    (cs_insn_group(handle, &original_insn[i], CS_GRP_RET) &&
                     covered + original_insn[i].size < 5)) {
                    break;
                }
                covered += original_insn[i].size;
            }
            cs_free(original_insn, instruction_count);
            if (covered < 5) {
                skip_short_entry();
                continue;
            }
            const uint64_t occupied = landing_pad + covered;
            bool known_extent = false;
            bool enough_space = true;
            for (const auto& symbol : target_binary->symbols()) {
                if (!symbol.is_function()) continue;
                if (symbol.value() == function->target_address && symbol.size() > 0) {
                    known_extent = true;
                    enough_space &= symbol.size() >= occupied;
                } else if (symbol.value() > function->target_address &&
                           symbol.value() - function->target_address < occupied) {
                    enough_space = false;
                }
            }
            if (!enough_space) {
                skip_short_entry();
                continue;
            }
            if (!known_extent && !allow_unverified_targets) {
                throw std::runtime_error("Target function size is unknown; use --allow-unverified-targets to proceed");
            }

            // A ref_ to this same entry means "call the original". The entry
            // jump would call the replacement again, so a trampoline is needed.
            for (const Function* candidate : function_map.get_functions()) {
                if (candidate->operation == OperationType::Ref &&
                    candidate->target_address == function->target_address) {
                    throw std::runtime_error("ref_ to a fixed function requires an original-code trampoline");
                }
            }

            require_target_range(*output_binary, original_entry, occupied, true);
            std::vector<uint8_t> new_instruction_bytes{0xE9, 0, 0, 0, 0};
            if (jump_address > UINT64_MAX - new_instruction_bytes.size()) {
                throw std::runtime_error("Target jump address overflows");
            }
            write_relative_displacement(new_instruction_bytes, 1, 4,
                                        function->new_address,
                                        jump_address + new_instruction_bytes.size());
            new_instruction_bytes.resize(covered, 0x90);
            output_binary->patch_address(jump_address, new_instruction_bytes);
        } 

        verbose_print::print_green("Relocated function at " + decimal_to_hex(function->patch_address) + " of patch binary");       
    }
    
    // Update addend of RELATIVE relocations
    for (LIEF::ELF::Relocation& r : output_binary->dynamic_relocations()) {
        if (r.type() == LIEF::ELF::Relocation::TYPE::X86_64_RELATIVE) {
            auto addend_vector = output_binary->get_content_from_virtual_address(r.address(), 8);
            r.addend(vector_to_int(std::vector<uint8_t>(addend_vector.begin(), addend_vector.end())));
        }
    }

    output_binary->write(output_binary_path);
}

#endif // RELOCATOR_HPP
