
#include <map>
#include <memory>
#include <algorithm>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include "utils.hpp"
#include "got_reuse.hpp"
#include "elf_output.hpp"
#include "runtime_bindings.hpp"
#include "original_trampoline.hpp"

#ifndef RELOCATOR_HPP
#define RELOCATOR_HPP

class RelativeDisplacementOutOfRange : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class InPlaceRelocationFailure : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

void require_target_range(LIEF::ELF::Binary& binary, uint64_t address, uint64_t size, bool executable) {
    LIEF::ELF::Section* section = binary.section_from_virtual_address(address);

    if (!section || !section->has(LIEF::ELF::Section::FLAGS::ALLOC) || section->type() == LIEF::ELF::Section::TYPE::NOBITS || size == 0 || section->has(LIEF::ELF::Section::FLAGS::EXECINSTR) != executable || address < section->virtual_address() || address - section->virtual_address() > section->size() || size > section->size() - (address - section->virtual_address())) {
        throw std::runtime_error("Patch write is outside a compatible target section");
    }
}

LIEF::ELF::Section* require_section(LIEF::ELF::Binary& binary, const std::string& name) {
    LIEF::ELF::Section* section = binary.get_section(name);

    if (!section) {
        throw std::runtime_error("Missing ELF section: " + name);
    }

    return section;
}

uint64_t translate_target_address(const LIEF::ELF::Binary& original, const LIEF::ELF::Binary& output, uint64_t address) {
    const LIEF::ELF::Section* source_section =
        original.section_from_virtual_address(address);

    if (source_section && source_section->has(LIEF::ELF::Section::FLAGS::ALLOC) && source_section->type() != LIEF::ELF::Section::TYPE::NOBITS && address >= source_section->virtual_address() && address - source_section->virtual_address() < source_section->size()) {
        const LIEF::ELF::Section* destination_section =
            output.get_section(source_section->name());

        if (!destination_section || !destination_section->has(LIEF::ELF::Section::FLAGS::ALLOC) || destination_section->type() != source_section->type() || destination_section->size() < source_section->size() || destination_section->virtual_address() > UINT64_MAX - (address - source_section->virtual_address())) {
            throw std::runtime_error("Target section could not be mapped into output");
        }

        return destination_section->virtual_address() +
               (address - source_section->virtual_address());
    }

    // Match the original load segments to the corresponding output load segments
    std::vector<const LIEF::ELF::Segment*> original_loads;
    std::vector<const LIEF::ELF::Segment*> output_loads;

    for (const LIEF::ELF::Segment& segment : original.segments()) {
        if (segment.is_load())
            original_loads.push_back(&segment);
    }

    for (const LIEF::ELF::Segment& segment : output.segments()) {
        if (segment.is_load())
            output_loads.push_back(&segment);
    }

    if (output_loads.size() < original_loads.size()) {
        throw std::runtime_error("Original load segments are missing from output");
    }

    for (size_t index = 0; index < original_loads.size(); ++index) {
        const LIEF::ELF::Segment& source = *original_loads[index];

        if (address < source.virtual_address() || address - source.virtual_address() >= source.virtual_size()) {
            continue;
        }

        const LIEF::ELF::Segment& destination = *output_loads[index];
        const uint64_t offset = address - source.virtual_address();

        if (destination.flags() != source.flags() || offset >= destination.virtual_size() || destination.virtual_address() > UINT64_MAX - offset) {
            throw std::runtime_error("Target load segment could not be mapped into output");
        }

        return destination.virtual_address() + offset;
    }

    throw std::runtime_error("Target address has no load segment");
}

int64_t checked_relative_displacement(uint64_t target, uint64_t next_instruction, size_t encoded_size) {
    if (encoded_size != 1 && encoded_size != 2 && encoded_size != 4) {
        throw std::runtime_error("Unsupported relative displacement size");
    }

    const uint64_t positive_limit = (uint64_t{1} << (encoded_size * 8 - 1)) - 1;
    const uint64_t negative_limit = positive_limit + 1;
    auto out_of_range = [&]() {
        return RelativeDisplacementOutOfRange(
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

void write_relative_displacement(std::vector<uint8_t>& bytes, size_t offset, size_t encoded_size, uint64_t target, uint64_t next_instruction) {
    if (offset == 0 || offset > bytes.size() || encoded_size > bytes.size() - offset) {
        throw std::runtime_error("Instruction displacement is outside its encoding");
    }

    uint64_t encoded = static_cast<uint64_t>(
        checked_relative_displacement(target, next_instruction, encoded_size));

    for (size_t i = 0; i < encoded_size; ++i) {
        bytes[offset + i] = static_cast<uint8_t>(encoded);
        encoded >>= 8;
    }
}

bool relative_displacement_fits(uint64_t target, uint64_t next_instruction, size_t encoded_size) {
    if (encoded_size != 1 && encoded_size != 2 && encoded_size != 4) {
        return false;
    }

    const uint64_t positive_limit = (uint64_t{1} << (encoded_size * 8 - 1)) - 1;
    const uint64_t negative_limit = positive_limit + 1;

    return target >= next_instruction ? target - next_instruction <= positive_limit : next_instruction - target <= negative_limit;
}

uint64_t relocated_instruction_address(uint64_t address, uint64_t old_base, uint64_t new_base, uint64_t size) {
    if (address < old_base || address - old_base > UINT64_MAX - new_base || size > UINT64_MAX - (address - old_base + new_base)) {
        throw std::runtime_error("Relocated instruction address overflows");
    }

    return address - old_base + new_base;
}

void patch_reference(csh handle, LIEF::ELF::Binary& output_binary, const std::vector<uint8_t>& instruction_bytes, uint64_t start_address, uint64_t old_base, uint64_t new_base, uint64_t new_address, bool allow_direct_branch) {
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
            if (x86.operands[i].type == X86_OP_MEM && x86.operands[i].mem.base == X86_REG_RIP) {
                write_relative_displacement(replacement, x86.encoding.disp_offset,
                                            4, new_address,
                                            next_instruction);
                patched = true;
                break;
            }
        }

        if (!patched && allow_direct_branch && x86.op_count > 0 && x86.operands[0].type == X86_OP_IMM && (cs_insn_group(handle, &instruction, CS_GRP_CALL) || cs_insn_group(handle, &instruction, CS_GRP_JUMP))) {
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

bool has_indirect_target_reference(csh handle, const LIEF::ELF::Binary& binary, uint64_t target_address, uint64_t rewritten_instruction = UINT64_MAX) {
    for (const auto& relocation : binary.relocations()) {
        if (static_cast<uint64_t>(relocation.addend()) != target_address)
            continue;

        const auto* section = binary.section_from_virtual_address(relocation.address());

        if (section && section->has(LIEF::ELF::Section::FLAGS::ALLOC) && !section->has(LIEF::ELF::Section::FLAGS::EXECINSTR))
            return true;
    }

    for (const auto& section : binary.sections()) {
        if (!section.has(LIEF::ELF::Section::FLAGS::ALLOC) || section.has(LIEF::ELF::Section::FLAGS::EXECINSTR) || section.type() != LIEF::ELF::Section::TYPE::PROGBITS)
            continue;

        const auto bytes = section.content();

        for (size_t offset = 0; offset + sizeof(uint64_t) <= bytes.size(); ++offset) {
            uint64_t value = 0;

            for (size_t byte = 0; byte < sizeof(uint64_t); ++byte) {
                value |= uint64_t(bytes[offset + byte]) << (8 * byte);
            }

            if (value == target_address)
                return true;
        }
    }

    for (const auto& section : binary.sections()) {
        if (!section.has(LIEF::ELF::Section::FLAGS::EXECINSTR) || !section.size())
            continue;

        const auto bytes = section.content();
        cs_insn* instructions = nullptr;
        const size_t count = cs_disasm(handle, bytes.data(), bytes.size(),
                                       section.virtual_address(), 0, &instructions);
        bool found = false;

        for (size_t index = 0; index < count && !found; ++index) {
            const auto& instruction = instructions[index];

            if (instruction.address == rewritten_instruction)
                continue;

            if (!instruction.detail)
                continue;

            const bool branch = cs_insn_group(handle, &instruction, CS_GRP_CALL) || cs_insn_group(handle, &instruction, CS_GRP_JUMP);

            for (uint8_t operand = 0; operand < instruction.detail->x86.op_count; ++operand) {
                const auto& value = instruction.detail->x86.operands[operand];

                if (value.type == X86_OP_IMM && !branch && static_cast<uint64_t>(value.imm) == target_address)
                    found = true;

                if (value.type == X86_OP_MEM && !branch && value.mem.base == X86_REG_RIP && instruction.address + instruction.size + value.mem.disp == target_address)
                    found = true;
            }
        }

        cs_free(instructions, count);
        if (found)
            return true;
    }

    return false;
}
void relocate_existing_target_references(csh handle, const LIEF::ELF::Binary& original, LIEF::ELF::Binary& output, const FunctionMap& function_map, const std::vector<OriginalTrampoline>& originals = {}) {
    std::map<uint64_t, uint64_t> replacements;

    for (const Function* function : function_map.get_functions()) {
        if (function->operation == OperationType::Fix) {
            replacements[function->target_address] = function->new_address;
        }
    }

    for (const LIEF::ELF::Section& source_section : original.sections()) {
        if (!source_section.has(LIEF::ELF::Section::FLAGS::EXECINSTR) || source_section.size() == 0) {
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

                if (!instruction.detail)
                    continue;

                const cs_x86& x86 = instruction.detail->x86;
                uint64_t referenced_address = 0;
                bool direct_reference = false;

                for (uint8_t operand = 0; operand < x86.op_count; ++operand) {
                    if (x86.operands[operand].type == X86_OP_MEM && x86.operands[operand].mem.base == X86_REG_RIP) {
                        referenced_address = instruction.address + instruction.size +
                                             x86.operands[operand].mem.disp;
                        break;
                    }
                }

                if (referenced_address == 0 && x86.op_count > 0 && x86.operands[0].type == X86_OP_IMM && (cs_insn_group(handle, &instruction, CS_GRP_CALL) || cs_insn_group(handle, &instruction, CS_GRP_JUMP))) {
                    referenced_address = x86.operands[0].imm;
                    direct_reference = true;
                }

                if (referenced_address == 0)
                    continue;

                uint64_t relocated_reference = 0;

                try {
                    relocated_reference = translate_target_address(
                        original, output, referenced_address);
                } catch (const std::runtime_error&) {
                    // External addresses and unresolved indirect targets handled by the dynamic linker
                    continue;
                }

                if (instruction.address > UINT64_MAX - instruction.size) {
                    throw std::runtime_error("Target instruction address overflows");
                }

                const uint64_t output_address = relocated_instruction_address(
                    instruction.address, source_section.virtual_address(),
                    output_section->virtual_address(), instruction.size);

                // Calls and tail jumps with an immediate target can go straight to fix_
                if (direct_reference) {
                    auto replacement = replacements.find(referenced_address);
                    uint64_t original_destination = 0;

                    for (const auto& trampoline : originals) {
                        if (instruction.address >= trampoline.target_address && instruction.address - trampoline.target_address < trampoline.target_size && referenced_address == trampoline.target_address) {
                            original_destination = trampoline.new_address;
                            break;
                        }
                    }

                    if (original_destination) {
                        if (!relative_displacement_fits(original_destination, output_address + instruction.size, x86.encoding.imm_size)) {
                            throw std::runtime_error("Original function has an out-of-range recursive branch");
                        }

                        relocated_reference = original_destination;
                    } else if (replacement != replacements.end() && relative_displacement_fits(replacement->second, output_address + instruction.size, x86.encoding.imm_size)) {
                        relocated_reference = replacement->second;
                    }
                }

                if (relocated_reference - (output_address + instruction.size) == referenced_address - (instruction.address + instruction.size)) {
                    continue;
                }

                const size_t offset = static_cast<size_t>(
                    instruction.address - source_section.virtual_address());

                if (offset > section_bytes.size() || instruction.size > section_bytes.size() - offset) {
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

std::map<uint64_t, uint64_t> relocate_startup_main_argument(csh handle, const LIEF::ELF::Binary& original, LIEF::ELF::Binary& output, const FunctionMap& functions) {
    std::map<uint64_t, uint64_t> redirected;
    std::map<uint64_t, uint64_t> fixed_functions;

    for (const Function* function : functions.get_functions()) {
        if (function->operation == OperationType::Fix)
            fixed_functions[function->target_address] = function->new_address;
    }

    if (fixed_functions.empty())
        return redirected;

    std::set<uint64_t> libc_start_main_got;

    for (const auto& relocation : original.relocations()) {
        const LIEF::ELF::Symbol* symbol = relocation.symbol();

        if (symbol && symbol->name().rfind("__libc_start_main", 0) == 0)
            libc_start_main_got.insert(relocation.address());
    }

    if (libc_start_main_got.empty())
        return redirected;

    const uint64_t entry = original.entrypoint();
    const LIEF::ELF::Section* source =
        original.section_from_virtual_address(entry);

    if (!source || !source->has(LIEF::ELF::Section::FLAGS::EXECINSTR) || entry < source->virtual_address() || entry - source->virtual_address() >= source->size())
        return redirected;

    const size_t available = static_cast<size_t>(std::min<uint64_t>(
        128, source->size() - (entry - source->virtual_address())));
    auto content = original.get_content_from_virtual_address(entry, available);
    cs_insn* instructions = nullptr;
    const size_t count = cs_disasm(handle, content.data(), content.size(),
                                   entry, 0, &instructions);

    try {
        for (size_t index = 1; index < count; ++index) {
            const cs_insn& call = instructions[index];

            if (!call.detail || !cs_insn_group(handle, &call, CS_GRP_CALL) || call.detail->x86.op_count == 0)
                continue;

            uint64_t got_address = 0;
            const cs_x86_op& call_operand = call.detail->x86.operands[0];

            if (call_operand.type == X86_OP_MEM && call_operand.mem.base == X86_REG_RIP) {
                got_address = call.address + call.size + call_operand.mem.disp;
            } else if (call_operand.type == X86_OP_IMM) {
                const uint64_t stub = call_operand.imm;
                const LIEF::ELF::Section* stub_section =
                    original.section_from_virtual_address(stub);

                if (stub_section && stub_section->name().rfind(".plt", 0) == 0 && stub >= stub_section->virtual_address() && stub - stub_section->virtual_address() < stub_section->size()) {
                    const size_t stub_size = static_cast<size_t>(std::min<uint64_t>(
                        16, stub_section->size() -
                                (stub - stub_section->virtual_address())));
                    auto stub_bytes = original.get_content_from_virtual_address(
                        stub, stub_size);
                    cs_insn* stub_instruction = nullptr;
                    const size_t stub_count = cs_disasm(
                        handle, stub_bytes.data(), stub_bytes.size(),
                        stub, 1, &stub_instruction);

                    if (stub_count == 1 && stub_instruction[0].detail && cs_insn_group(handle, &stub_instruction[0], CS_GRP_JUMP) && stub_instruction[0].detail->x86.op_count > 0) {
                        const cs_x86_op& operand =
                            stub_instruction[0].detail->x86.operands[0];

                        if (operand.type == X86_OP_MEM && operand.mem.base == X86_REG_RIP)
                            got_address = stub_instruction[0].address +
                                          stub_instruction[0].size +
                                          operand.mem.disp;
                    }

                    cs_free(stub_instruction, stub_count);
                }
            }

            if (!libc_start_main_got.count(got_address))
                continue;

            const cs_insn& loader = instructions[index - 1];

            if (!loader.detail || loader.address + loader.size != call.address || loader.detail->x86.op_count < 2)
                continue;

            const cs_x86& x86 = loader.detail->x86;
            const cs_x86_op& destination = x86.operands[0];
            const cs_x86_op& value = x86.operands[1];

            if (destination.type != X86_OP_REG || (destination.reg != X86_REG_RDI && destination.reg != X86_REG_EDI))
                continue;

            const bool rip_lea = loader.id == X86_INS_LEA && destination.reg == X86_REG_RDI && value.type == X86_OP_MEM && value.mem.base == X86_REG_RIP;
            const bool immediate_mov =
                (std::string(loader.mnemonic) == "mov" || std::string(loader.mnemonic) == "movabs") && value.type == X86_OP_IMM;

            if (!rip_lea && !immediate_mov)
                continue;

            const uint64_t original_main = rip_lea ? loader.address + loader.size + value.mem.disp : destination.reg == X86_REG_EDI ? static_cast<uint64_t>(static_cast<uint32_t>(value.imm))
                                                                                                                                    : static_cast<uint64_t>(value.imm);
            auto replacement = fixed_functions.find(original_main);

            if (replacement == fixed_functions.end())
                continue;

            LIEF::ELF::Section* destination_section =
                output.get_section(source->name());

            if (!destination_section || destination_section->size() < source->size()) {
                throw std::runtime_error("Startup section could not be mapped");
            }

            const uint64_t output_address = relocated_instruction_address(
                loader.address, source->virtual_address(),
                destination_section->virtual_address(), loader.size);
            std::vector<uint8_t> bytes(loader.bytes,
                                       loader.bytes + loader.size);

            if (rip_lea) {
                patch_reference(handle, output, bytes, loader.address,
                                source->virtual_address(),
                                destination_section->virtual_address(),
                                replacement->second, false);
            } else {
                const size_t offset = x86.encoding.imm_offset;
                const size_t width = x86.encoding.imm_size;

                if (!offset || offset > bytes.size() || width > bytes.size() - offset || (width != 4 && width != 8)) {
                    throw std::runtime_error("Unsupported main startup operand");
                }

                uint64_t encoded = replacement->second;

                if (width == 4 && destination.reg == X86_REG_EDI && encoded > UINT32_MAX) {
                    throw std::runtime_error("Replacement main does not fit startup MOV");
                }

                if (width == 4 && destination.reg == X86_REG_RDI && encoded > INT32_MAX && encoded < UINT64_MAX - static_cast<uint64_t>(INT32_MAX)) {
                    throw std::runtime_error("Replacement main does not fit startup MOV");
                }

                for (size_t byte = 0; byte < width; ++byte) {
                    bytes[offset + byte] = static_cast<uint8_t>(encoded);
                    encoded >>= 8;
                }

                output.patch_address(output_address, bytes);
            }

            redirected[original_main] = loader.address;
            break;
        }
    } catch (...) {
        cs_free(instructions, count);
        throw;
    }

    cs_free(instructions, count);

    return redirected;
}

void write_original_trampolines(csh handle, const LIEF::ELF::Binary& original, LIEF::ELF::Binary& output, std::vector<OriginalTrampoline>& trampolines, const std::string& indicator) {
    if (trampolines.empty())
        return;

    const auto* section = require_section(output, ".text.original." + indicator);

    for (auto& trampoline : trampolines) {
        trampoline.new_address = section->virtual_address() + trampoline.storage_offset;

        std::vector<uint8_t> code{0xf3, 0x0f, 0x1e, 0xfa};

        code.insert(code.end(), trampoline.prologue.begin(), trampoline.prologue.end());
        code.insert(code.end(), {0xe9, 0, 0, 0, 0});

        const uint64_t old_body = trampoline.target_address + trampoline.landing_pad;
        const uint64_t resume = translate_target_address(original, output,
                                                         old_body + trampoline.prologue.size());

        write_relative_displacement(code, code.size() - 4, 4, resume,
                                    trampoline.new_address + code.size());
        output.patch_address(trampoline.new_address, code);

        cs_insn* instructions = nullptr;
        size_t count = cs_disasm(handle, trampoline.prologue.data(), trampoline.prologue.size(),
                                 old_body, 0, &instructions);

        try {
            for (size_t i = 0; i < count; ++i) {
                const auto& instruction = instructions[i];
                uint64_t target = 0;
                bool branch = false;

                for (unsigned j = 0; j < instruction.detail->x86.op_count; ++j) {
                    const auto& operand = instruction.detail->x86.operands[j];

                    if (operand.type == X86_OP_MEM && operand.mem.base == X86_REG_RIP)
                        target = instruction.address + instruction.size + operand.mem.disp;
                    else if (operand.type == X86_OP_IMM && cs_insn_group(handle, &instruction, CS_GRP_JUMP)) {
                        target = operand.imm;
                        branch = true;
                    }
                }

                if (!target)
                    continue;

                uint64_t destination;

                if (target >= old_body && target - old_body < trampoline.prologue.size())
                    destination = trampoline.new_address + 4 + target - old_body;
                else if (branch && target == trampoline.target_address)
                    destination = trampoline.new_address;
                else
                    destination = translate_target_address(original, output, target);

                patch_reference(handle, output,
                                std::vector<uint8_t>(instruction.bytes, instruction.bytes + instruction.size),
                                instruction.address, old_body, trampoline.new_address + 4, destination, branch);
            }
        } catch (...) {
            cs_free(instructions, count);
            throw;
        }

        cs_free(instructions, count);
    }
}

void prepare_runtime_dispatch_exports(const LIEF::ELF::Binary& patch, LIEF::ELF::Binary& output, const std::string& indicator) {
    std::set<std::string> seen;

    for (const auto& symbol : patch.symbols()) {
        if (!symbol.is_variable() || symbol.name().rfind("add_patch_slot_", 0) != 0 || !seen.insert(symbol.name()).second)
            continue;

        for (const auto& existing : output.dynamic_symbols()) {
            if (existing.name() == symbol.name()) {
                throw std::runtime_error("Target uses a reserved dispatch symbol");
            }
        }

        const auto* source = patch.section_from_virtual_address(symbol.value());

        if (!source) {
            throw std::runtime_error("Missing runtime dispatch storage");
        }

        const auto* section = require_section(output, source->name() + "." + indicator);
        uint16_t index = 0;

        for (const auto& candidate : output.sections()) {
            if (&candidate == section)
                break;

            ++index;
        }

        LIEF::ELF::Symbol exported;

        exported.name(symbol.name());
        exported.type(LIEF::ELF::Symbol::TYPE::OBJECT);
        exported.binding(LIEF::ELF::Symbol::BINDING::GLOBAL);
        exported.visibility(LIEF::ELF::Symbol::VISIBILITY::DEFAULT);
        exported.shndx(index);
        exported.value(section->virtual_address() + symbol.value() - source->virtual_address());
        exported.size(symbol.size());
        output.export_symbol(exported);
    }
}

uint64_t prepare_runtime_after_init(LIEF::ELF::Binary& output, const FunctionMap& functions, uint64_t patch_address, const std::string& indicator) {
    if (patch_address == UINT64_MAX)
        return 0;

    const auto* function = functions.find_function(patch_address);

    if (!function || function->operation != OperationType::Add) {
        throw std::runtime_error("Missing post-construction replacement hook");
    }

    auto* old_entry = output.get(LIEF::ELF::DynamicEntry::TAG::INIT_ARRAY);
    auto* old_array = dynamic_cast<LIEF::ELF::DynamicEntryArray*>(old_entry);

    if (old_entry && !old_array) {
        throw std::runtime_error("Invalid target constructor array");
    }

    std::vector<uint64_t> values = old_array ? old_array->array() : std::vector<uint64_t>{};
    const uint64_t old_size = values.size() * 8;
    LIEF::ELF::Section section(".patch.init_array." + indicator);

    section.type(LIEF::ELF::Section::TYPE::INIT_ARRAY);
    section.flags(uint64_t(LIEF::ELF::Section::FLAGS::ALLOC) | uint64_t(LIEF::ELF::Section::FLAGS::WRITE));
    section.alignment(8);
    section.content(std::vector<uint8_t>(old_size + 8, 0));

    auto* added = output.add(section);

    if (!added) {
        throw std::runtime_error("Failed to allocate replacement constructor array");
    }

    old_entry = output.get(LIEF::ELF::DynamicEntry::TAG::INIT_ARRAY);
    old_array = dynamic_cast<LIEF::ELF::DynamicEntryArray*>(old_entry);

    const uint64_t old_address = old_array ? old_array->value() : 0;

    if (old_array)
        values = old_array->array();

    for (auto& relocation : output.dynamic_relocations()) {
        if (old_size && relocation.address() >= old_address && relocation.address() - old_address < old_size)
            relocation.address(added->virtual_address() + relocation.address() - old_address);
    }

    const uint64_t address = require_section(output, ".text." + indicator)->virtual_address() + function->new_address;

    values.push_back(address);

    std::vector<uint8_t> bytes(values.size() * 8, 0);

    for (size_t i = 0; i < values.size(); ++i) {
        for (unsigned j = 0; j < 8; ++j) {
            bytes[i * 8 + j] = uint8_t(values[i] >> (j * 8));
        }
    }

    added->content(bytes);
    output.remove(LIEF::ELF::DynamicEntry::TAG::INIT_ARRAY);

    LIEF::ELF::DynamicEntryArray array(LIEF::ELF::DynamicEntry::TAG::INIT_ARRAY, values);

    array.value(added->virtual_address());
    output.add(array);

    auto* size_entry = output.get(LIEF::ELF::DynamicEntry::TAG::INIT_ARRAYSZ);

    if (size_entry)
        size_entry->value(bytes.size());
    else
        output.add(LIEF::ELF::DynamicEntry(LIEF::ELF::DynamicEntry::TAG::INIT_ARRAYSZ, bytes.size()));

    if (output.header().file_type() == LIEF::ELF::Header::FILE_TYPE::DYN) {
        LIEF::ELF::Relocation relocation(added->virtual_address() + old_size,
                                         LIEF::ELF::Relocation::TYPE::X86_64_RELATIVE, LIEF::ELF::Relocation::ENCODING::RELA);

        relocation.addend(address);
        output.add_dynamic_relocation(relocation);
    }

    return old_size;
}

void prepare_runtime_reference_exports(const LIEF::ELF::Binary& original, LIEF::ELF::Binary& output, const FunctionMap& functions, const std::vector<RuntimeReference>& references, const std::vector<OriginalTrampoline>& originals = {}, const std::string& indicator = "") {
    for (const auto& reference : references) {
        if (reference.tls) {
            const auto& source = target_tls_symbol(original, reference.value);
            const auto& source_section = tls_symbol_section(original, source);
            const auto* section = output.has_section(".patch.tls_image") ? output.get_section(".patch.tls_image") : output.get_section(source_section.name());
            const auto* original_tls = original.get(LIEF::ELF::Segment::TYPE::TLS);
            const auto* output_tls = output.get(LIEF::ELF::Segment::TYPE::TLS);

            if (!section || !section->has(LIEF::ELF::Section::FLAGS::TLS) || !output_tls || output_tls->virtual_size() != original_tls->virtual_size() || (!output.has_section(".patch.tls_image") && output_tls->physical_size() != original_tls->physical_size()) || output_tls->alignment() != original_tls->alignment()) {
                throw std::runtime_error("Target TLS template changed during merge");
            }

            uint16_t section_index = 0;
            bool found = false;

            for (const auto& candidate : output.sections()) {
                if (&candidate == section) {
                    found = true;
                    break;
                }

                if (section_index == 0xff00 - 1) {
                    throw std::runtime_error("Too many sections for runtime TLS export");
                }

                ++section_index;
            }

            if (!found) {
                throw std::runtime_error("Missing runtime TLS section");
            }

            for (const auto& symbol : output.dynamic_symbols()) {
                if (symbol.name() == reference.name) {
                    throw std::runtime_error("Runtime TLS ref_ symbol already exists in target");
                }
            }

            LIEF::ELF::Symbol exported;

            exported.name(reference.name);
            exported.type(LIEF::ELF::Symbol::TYPE::TLS);
            exported.binding(LIEF::ELF::Symbol::BINDING::GLOBAL);
            exported.visibility(LIEF::ELF::Symbol::VISIBILITY::DEFAULT);
            exported.shndx(section_index);
            exported.value(reference.value);
            exported.size(source.size());
            output.export_symbol(exported);
            continue;
        }

        if (reference.original) {
            for (const auto& existing : output.dynamic_symbols()) {
                if (existing.name() == reference.name) {
                    throw std::runtime_error("Original-function alias already exists");
                }
            }

            const auto* section = require_section(output, ".text.original." + indicator);
            const OriginalTrampoline* selected = nullptr;

            for (const auto& original_entry : originals) {
                if (original_entry.target_address == reference.value) {
                    selected = &original_entry;
                    break;
                }
            }

            if (!selected) {
                throw std::runtime_error("Missing original-function trampoline");
            }

            uint16_t index = 0;

            for (const auto& candidate : output.sections()) {
                if (&candidate == section)
                    break;

                ++index;
            }

            LIEF::ELF::Symbol exported;

            exported.name(reference.name);
            exported.type(LIEF::ELF::Symbol::TYPE::FUNC);
            exported.binding(LIEF::ELF::Symbol::BINDING::GLOBAL);
            exported.visibility(LIEF::ELF::Symbol::VISIBILITY::DEFAULT);
            exported.shndx(index);
            exported.value(section->virtual_address() + selected->storage_offset);
            exported.size(selected->size());
            output.export_symbol(exported);
            continue;
        }

        for (const Function* function : functions.get_functions()) {
            if (function->operation == OperationType::Fix && function->target_address == reference.value && !reference.redirected) {
                throw std::runtime_error("ref_ to a fixed function requires an original-code trampoline");
            }
        }

        for (const auto& symbol : output.dynamic_symbols()) {
            if (symbol.name() == reference.name) {
                throw std::runtime_error("C++ runtime ref_ symbol already exists in target");
            }
        }

        const uint64_t address = translate_target_address(original, output, reference.value);
        const auto* source_section = original.section_from_virtual_address(reference.value, false);
        const auto* section = source_section ? output.get_section(source_section->name()) : nullptr;

        if (!source_section || !section || !source_section->has(LIEF::ELF::Section::FLAGS::ALLOC) || !section->has(LIEF::ELF::Section::FLAGS::ALLOC)) {
            throw std::runtime_error("C++ runtime ref_ has no allocated target section");
        }

        uint64_t symbol_size = 0;

        for (const auto& symbol : original.symbols()) {
            if (symbol.value() == reference.value && symbol.size()) {
                symbol_size = symbol.size();
                break;
            }
        }

        const uint64_t required_size = symbol_size ? symbol_size : 1;
        bool mapped = false;

        for (const auto& load : output.segments()) {
            if (!load.is_load() || address < load.virtual_address())
                continue;

            const uint64_t offset = address - load.virtual_address();

            if (offset <= load.virtual_size() && required_size <= load.virtual_size() - offset) {
                mapped = true;
                break;
            }
        }

        if (!mapped) {
            throw std::runtime_error("C++ runtime ref_ exceeds target load memory");
        }

        uint16_t section_index = 0;
        bool found_section = false;

        for (const auto& candidate : output.sections()) {
            if (&candidate == section) {
                found_section = true;
                break;
            }

            if (section_index == 0xff00 - 1) {
                throw std::runtime_error("Too many sections for C++ runtime ref_ export");
            }

            ++section_index;
        }

        if (!found_section) {
            throw std::runtime_error("C++ runtime ref_ section is missing");
        }

        LIEF::ELF::Symbol exported_symbol;

        exported_symbol.name(reference.name);
        exported_symbol.value(address);
        exported_symbol.type(section->has(LIEF::ELF::Section::FLAGS::EXECINSTR) ? LIEF::ELF::Symbol::TYPE::FUNC : LIEF::ELF::Symbol::TYPE::OBJECT);
        exported_symbol.binding(LIEF::ELF::Symbol::BINDING::GLOBAL);
        exported_symbol.visibility(LIEF::ELF::Symbol::VISIBILITY::DEFAULT);
        exported_symbol.shndx(section_index);
        exported_symbol.size(symbol_size);
        output.export_symbol(exported_symbol);
    }
}

void relocate(const std::string& patch_binary_path, const std::string& target_binary_path, const std::string& output_binary_path, GlobalVarMap& global_var_map, FunctionMap& function_map, std::string new_section_indicator, bool allow_unverified_targets = false, uint64_t runtime_init_patch_address = UINT64_MAX, const std::vector<RuntimeReference>& runtime_references = {}, std::unique_ptr<LIEF::ELF::Binary>* prepared_output = nullptr, uint64_t runtime_after_init_patch_address = UINT64_MAX) {

    std::unique_ptr<LIEF::ELF::Binary> patch_binary = LIEF::ELF::Parser::parse(patch_binary_path);
    std::unique_ptr<LIEF::ELF::Binary> target_binary = LIEF::ELF::Parser::parse(target_binary_path);
    std::unique_ptr<LIEF::ELF::Binary> output_binary = prepared_output ? std::move(*prepared_output) : LIEF::ELF::Parser::parse(output_binary_path);

    if (!patch_binary || !target_binary || !output_binary) {
        throw std::runtime_error("Failed to parse a relocation input binary");
    }

    auto originals = plan_original_trampolines(*target_binary, runtime_references);

    std::map<uint64_t, uint64_t> got_entries;

    csh handle;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize Capstone");
    }

    struct ScopedCapstone {
        csh& handle;

        ~ScopedCapstone() {
            cs_close(&handle);
        }
    } scoped_capstone{handle};

    if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
        throw std::runtime_error("Failed to enable Capstone instruction detail");
    }

    const auto reused_got = reusable_got_entries(*patch_binary, *target_binary);
    const bool needs_got_mapping =
        output_binary->has_section(".plt.sec." + new_section_indicator) || output_binary->has_section(".got." + new_section_indicator);

    if (needs_got_mapping) {
        LIEF::ELF::Section* new_got_section =
            output_binary->get_section(".got." + new_section_indicator);

        size_t index = 0;

        for (const LIEF::ELF::Relocation& rel : patch_binary->pltgot_relocations()) {
            const LIEF::ELF::Symbol* original_symbol = rel.symbol();

            if (!original_symbol) {
                throw std::runtime_error("GOT relocation has no symbol");
            }

            auto reused = reused_got.find(rel.address());

            if (reused != reused_got.end()) {
                const uint64_t entry_address = translate_target_address(
                    *target_binary, *output_binary, reused->second);

                if (!is_existing_got_slot(*output_binary, entry_address)) {
                    throw std::runtime_error("Reused GOT slot was not preserved");
                }

                got_entries[rel.address()] = entry_address;
                verbose_print::print_green("Reused GOT entry for " +
                                           original_symbol->name());
                continue;
            }

            if (!new_got_section) {
                throw std::runtime_error("Missing GOT section for new imports");
            }

            LIEF::ELF::Symbol new_symbol = *original_symbol;
            LIEF::ELF::Symbol* added_symbol = &output_binary->add_dynamic_symbol(new_symbol);

            if (index >= new_got_section->size() / sizeof(uint64_t)) {
                throw std::runtime_error("Relocated GOT exceeds allocated section");
            }

            uint64_t entry_address = new_got_section->virtual_address() +
                                     (index++ * sizeof(uint64_t));

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

    if (runtime_init_patch_address != UINT64_MAX) {
        prepare_runtime_dispatch_exports(*patch_binary, *output_binary, new_section_indicator);
        prepare_runtime_reference_exports(*target_binary, *output_binary,
                                          function_map, runtime_references, originals, new_section_indicator);
    }

    const uint64_t after_init_offset = prepare_runtime_after_init(*output_binary, function_map,
                                                                  runtime_after_init_patch_address, new_section_indicator);

    output_binary->write(output_binary_path);
    output_binary = LIEF::ELF::Parser::parse(output_binary_path);
    if (!output_binary) {
        throw std::runtime_error("Failed to parse intermediate output binary");
    }

    if (runtime_init_patch_address != UINT64_MAX)
        validate_runtime_elf_layout(*output_binary);

    if (needs_got_mapping) {
        const auto* new_got = output_binary->get_section(".got." + new_section_indicator);
        size_t index = 0;

        for (const auto& relocation : patch_binary->pltgot_relocations()) {
            auto reused = reused_got.find(relocation.address());

            if (reused != reused_got.end()) {
                got_entries[relocation.address()] = translate_target_address(
                    *target_binary, *output_binary, reused->second);
            } else {
                if (!new_got || index >= new_got->size() / sizeof(uint64_t)) {
                    throw std::runtime_error("Missing built GOT slot");
                }

                got_entries[relocation.address()] = new_got->virtual_address() + index++ * 8;
            }
        }
    }

    // Relocate content of .plt.sec section if exists
    if (output_binary->has_section(".plt.sec." + new_section_indicator)) {
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

                    if (detail && detail->x86.op_count > 0 && (cs_insn_group(handle, &instruction, CS_GRP_JUMP) || cs_insn_group(handle, &instruction, CS_GRP_CALL))) {
                        uint64_t old_address;

                        if (detail->x86.operands[0].type == X86_OP_MEM && detail->x86.operands[0].mem.base == X86_REG_RIP) {
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

    auto translate_target = [&target_binary, &output_binary](uint64_t address) -> uint64_t {
        return translate_target_address(*target_binary, *output_binary, address);
    };

    // Find new address of functions
    for (auto& function : function_map.get_functions()) {
        if (function->in_place || function->operation == OperationType::Ref) {
            function->new_address = translate_target(function->target_address);
        } else {
            uint64_t new_text_section_address = require_section(*output_binary, ".text." + new_section_indicator)->virtual_address();

            function->new_address += new_text_section_address;
        }
    }

    write_original_trampolines(handle, *target_binary, *output_binary, originals, new_section_indicator);

    relocate_existing_target_references(handle, *target_binary, *output_binary,
                                        function_map, originals);

    const std::map<uint64_t, uint64_t> redirected_startup_main =
        relocate_startup_main_argument(handle, *target_binary, *output_binary,
                                       function_map);

    // Install only after original code references have been rebased
    for (const Function* function : function_map.get_functions()) {
        if (!function->in_place)
            continue;

        require_target_range(*output_binary, function->new_address,
                             function->target_size, true);

        auto code = patch_binary->get_content_from_virtual_address(
            function->patch_address, function->size);

        if (code.size() != function->size) {
            throw std::runtime_error("In-place patch code is incomplete");
        }

        std::vector<uint8_t> replacement(code.begin(), code.end());

        replacement.resize(function->target_size, 0x90);
        output_binary->patch_address(function->new_address, replacement);
    }

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
        } else {
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

                    Function* pointed_function = function_map.find_function(element_value);

                    if (pointed_function) {
                        std::vector<uint8_t> new_element_content;
                        uint64_t value = pointed_function->new_address;

                        for (size_t i = 0; i < sizeof(value); ++i) {
                            new_element_content.push_back(static_cast<uint8_t>(value));
                            value >>= 8;
                        }

                        LIEF::ELF::Section* address_section =
                            patch_binary->section_from_virtual_address(element_address);

                        if (!address_section)
                            break;

                        LIEF::ELF::Section* mapped_section = output_binary->get_section(
                            address_section->name() + "." + new_section_indicator);

                        if (!mapped_section)
                            break;

                        uint64_t mapped_address = element_address -
                                                  address_section->virtual_address() +
                                                  mapped_section->virtual_address();

                        output_binary->patch_address(mapped_address, new_element_content);
                        element_address = pointed_function->new_address;
                        continue;
                    }

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
                if (symbol.is_variable() && symbol.size() > 0 && global_var->target_address >= symbol.value() && global_var->target_address - symbol.value() < symbol.size()) {
                    known_extent = true;
                    if (global_var->size > symbol.size() - (global_var->target_address - symbol.value())) {
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
        auto relocate_function_reference = [&](const std::vector<uint8_t>& bytes,
                                               const Reference* reference,
                                               uint64_t destination,
                                               bool direct_branch,
                                               bool destination_in_place) {
            try {
                patch_reference(handle, *output_binary, bytes, reference->address,
                                function->patch_address, function->new_address,
                                destination, direct_branch);
            } catch (const RelativeDisplacementOutOfRange&) {
                if (function->in_place || destination_in_place) {
                    throw InPlaceRelocationFailure(
                        "In-place reference is out of range");
                }

                throw;
            }
        };

        // Relocate references from patched functions
        if (function->operation != OperationType::Ref) {
            for (auto& reference : function->reference_table->get_references()) {
                // ref_ global variables
                if (reference->reference_type == SymbolType::GlobalVariable) {
                    // Check if it is referencing defined global variables in patch binary
                    GlobalVar* ref_global_var = global_var_map.find_global_var(reference->reference_address);
                    uint64_t interior_offset = 0;

                    if (!ref_global_var) {
                        for (GlobalVar* candidate : global_var_map.get_global_vars()) {
                            if (reference->reference_address >= candidate->patch_address && reference->reference_address - candidate->patch_address < candidate->size) {
                                ref_global_var = candidate;
                                interior_offset = reference->reference_address - candidate->patch_address;
                                break;
                            }
                        }
                    }

                    if (ref_global_var) {
                        if (ref_global_var->new_address == UINT64_MAX || interior_offset > UINT64_MAX - ref_global_var->new_address) {
                            throw std::runtime_error("Patch interior variable address overflows");
                        }

                        auto instruction_content = patch_binary->get_content_from_virtual_address(reference->address, reference->size);
                        std::vector<uint8_t> instruction_bytes(instruction_content.begin(), instruction_content.end());

                        relocate_function_reference(instruction_bytes, reference,
                                                    ref_global_var->new_address + interior_offset,
                                                    false, false);

                    } else {
                        // Check if it is referencing read-only data
                        LIEF::ELF::Section* original_section = patch_binary->section_from_virtual_address(reference->reference_address);

                        if (original_section && original_section->name() == ".rodata") {
                            uint64_t new_rodata_variable_address = require_section(*output_binary, ".rodata." + new_section_indicator)->virtual_address() + reference->reference_address - original_section->virtual_address();

                            auto instruction_content = patch_binary->get_content_from_virtual_address(reference->address, reference->size);
                            std::vector<uint8_t> instruction_bytes(instruction_content.begin(), instruction_content.end());

                            relocate_function_reference(instruction_bytes, reference,
                                                        new_rodata_variable_address,
                                                        false, false);
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

                        relocate_function_reference(instruction_bytes, reference,
                                                    new_pltsec_address, true, false);
                        continue;
                    }

                    Function* ref_function = function_map.find_function(reference->reference_address);

                    if (ref_function) {
                        auto instruction_content = patch_binary->get_content_from_virtual_address(reference->address, reference->size);
                        std::vector<uint8_t> instruction_bytes(instruction_content.begin(), instruction_content.end());

                        relocate_function_reference(instruction_bytes, reference,
                                                    ref_function->new_address, true,
                                                    ref_function->in_place);

                    } else {
                        throw std::runtime_error("Unresolved patch function reference at " +
                                                 decimal_to_hex(reference->reference_address));
                    }
                }
            }
        }

        // Leave the original address usable by direct and indirect callers.
        if (function->operation == OperationType::Fix) {
            if (function->in_place) {
                verbose_print::print_green("Replaced function in place at " +
                                           decimal_to_hex(function->target_address));
                continue;
            }

            const uint64_t original_entry = translate_target(function->target_address);

            require_target_range(*output_binary, original_entry, 1, true);

            LIEF::ELF::Section* target_section = output_binary->section_from_virtual_address(original_entry);
            const uint64_t section_remaining = target_section->size() -
                                               (original_entry - target_section->virtual_address());

            // An indirect call into a CET binary must still land on endbr64
            auto prefix = output_binary->get_content_from_virtual_address(
                original_entry, std::min<uint64_t>(4, section_remaining));
            const uint64_t landing_pad = prefix.size() == 4 && prefix[0] == 0xF3 && prefix[1] == 0x0F && prefix[2] == 0x1E && prefix[3] == 0xFA ? 4 : 0;

            auto skip_short_entry = [&]() {
                const auto startup = redirected_startup_main.find(
                    function->target_address);

                if (has_indirect_target_reference(handle, *target_binary, function->target_address, startup == redirected_startup_main.end() ? UINT64_MAX : startup->second)) {
                    throw std::runtime_error(
                        "Cannot redirect fix_ at " +
                        decimal_to_hex(function->target_address) +
                        ": indirect callers retain the original entry, "
                        "but it is too short for a jump");
                }

                if (!redirected_startup_main.count(function->target_address)) {
                    for (const auto& symbol : target_binary->symbols()) {
                        if (symbol.is_function() && symbol.name() == "main" && symbol.value() == function->target_address) {
                            throw std::runtime_error(
                                "Cannot redirect main: startup argument was not rewritten "
                                "and its entry cannot hold a jump");
                        }
                    }
                }

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

            // Count complete instructions after the optional landing pad
            // Total span, including ENDBR64, must fit
            size_t available = std::min<uint64_t>(32, section_remaining - landing_pad);
            auto code = output_binary->get_content_from_virtual_address(jump_address, available);
            cs_insn* original_insn = nullptr;
            size_t instruction_count = cs_disasm(handle, code.data(), code.size(),
                                                 jump_address, 0, &original_insn);
            size_t covered = 0;

            for (size_t i = 0; i < instruction_count && covered < 5; ++i) {
                if (original_insn[i].address != jump_address + covered || (cs_insn_group(handle, &original_insn[i], CS_GRP_RET) && covered + original_insn[i].size < 5)) {
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
                if (!symbol.is_function())
                    continue;

                if (symbol.value() == function->target_address && symbol.size() > 0) {
                    known_extent = true;
                    enough_space &= symbol.size() >= occupied;
                } else if (symbol.value() > function->target_address && symbol.value() - function->target_address < occupied) {
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

            for (const Function* candidate : function_map.get_functions()) {
                if (candidate->operation == OperationType::Ref && candidate->target_address == function->target_address) {
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

            const bool retained_original = std::any_of(originals.begin(), originals.end(), [&](const auto& original) {
                return original.target_address == function->target_address;
            });

            if (function->target_size > occupied && !retained_original) {
                const uint64_t tail = original_entry + occupied;

                require_target_range(*output_binary, tail,
                                     function->target_size - occupied, true);
                output_binary->patch_address(
                    tail, std::vector<uint8_t>(function->target_size - occupied, 0x90));
            }
        }

        verbose_print::print_green("Relocated function at " + decimal_to_hex(function->patch_address) + " of patch binary");
    }

    if (runtime_after_init_patch_address != UINT64_MAX) {
        const auto* after = function_map.find_function(runtime_after_init_patch_address);
        const auto* entry = output_binary->get(LIEF::ELF::DynamicEntry::TAG::INIT_ARRAY);

        if (!after || !entry) {
            throw std::runtime_error("Missing built lifecycle callback");
        }

        require_target_range(*output_binary, entry->value() + after_init_offset, 8, false);
        output_binary->patch_address(entry->value() + after_init_offset, after->new_address, 8);
    }

    // Update addend of RELATIVE relocations
    for (LIEF::ELF::Relocation& r : output_binary->dynamic_relocations()) {
        if (r.type() == LIEF::ELF::Relocation::TYPE::X86_64_RELATIVE) {
            auto addend_vector = output_binary->get_content_from_virtual_address(r.address(), 8);

            r.addend(vector_to_int(std::vector<uint8_t>(addend_vector.begin(), addend_vector.end())));
        }
    }

    if (runtime_init_patch_address != UINT64_MAX) {
        Function* initializer = function_map.find_function(runtime_init_patch_address);
        auto* init_entry = output_binary->get(LIEF::ELF::DynamicEntry::TAG::INIT);

        if (!initializer || initializer->operation != OperationType::Add || initializer->new_address == UINT64_MAX || !init_entry) {
            throw std::runtime_error("Cannot install C++ runtime initializer");
        }

        init_entry->value(initializer->new_address);

        for (const auto& reference : runtime_references) {
            bool found = false;

            for (auto& symbol : output_binary->dynamic_symbols()) {
                if (symbol.name() == reference.name) {
                    uint64_t address = reference.tls ? reference.value : translate_target(reference.value);

                    if (reference.original) {
                        bool original_found = false;

                        for (const auto& original : originals) {
                            if (original.target_address == reference.value) {
                                address = original.new_address;
                                original_found = true;
                                break;
                            }
                        }

                        if (!original_found) {
                            throw std::runtime_error("Built original trampoline is missing");
                        }
                    }

                    symbol.value(address);
                    found = true;
                    break;
                }
            }

            if (!found) {
                throw std::runtime_error("Built runtime ref_ export is missing");
            }
        }

        for (const auto& patch_symbol : patch_binary->symbols()) {
            if (!patch_symbol.is_variable() || patch_symbol.name().rfind("add_patch_slot_", 0) != 0)
                continue;

            const auto* variable = global_var_map.find_global_var(patch_symbol.value());

            if (!variable) {
                throw std::runtime_error("Missing built dispatch variable");
            }

            for (auto& exported : output_binary->dynamic_symbols()) {
                if (exported.name() == patch_symbol.name())
                    exported.value(variable->new_address);
            }
        }

        write_runtime_elf(*output_binary, output_binary_path);
    } else {
        output_binary->write(output_binary_path);
    }
}

#endif // RELOCATOR_HPP
