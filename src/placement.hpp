#include <cstdint>
#include <optional>
#include <vector>

#include <LIEF/LIEF.hpp>
#include <capstone/capstone.h>

#include "utils.hpp"

#ifndef PLACEMENT_HPP
#define PLACEMENT_HPP

// Only a bounded, file-backed function body may be reused or scrubbed. An
// unknown interior entry would make either operation unsafe.
std::optional<uint64_t> verified_function_extent(
    const LIEF::ELF::Binary& binary, uint64_t entry,
    const FunctionMap& functions) {
    uint64_t extent = 0;
    bool found = false;
    for (const auto& symbol : binary.symbols()) {
        if (!symbol.is_function() || symbol.value() != entry || !symbol.size())
            continue;
        if (found && extent != symbol.size()) return std::nullopt;
        extent = symbol.size();
        found = true;
    }
    if (!found || extent > UINT64_MAX - entry) return std::nullopt;

    const LIEF::ELF::Section* section = binary.section_from_virtual_address(entry);
    if (!section || section->type() != LIEF::ELF::Section::TYPE::PROGBITS ||
        !section->has(LIEF::ELF::Section::FLAGS::ALLOC) ||
        !section->has(LIEF::ELF::Section::FLAGS::EXECINSTR) ||
        entry < section->virtual_address() ||
        entry - section->virtual_address() > section->size() ||
        extent > section->size() - (entry - section->virtual_address()))
        return std::nullopt;

    bool loaded = false;
    for (const auto& segment : binary.segments()) {
        if (segment.is_load() &&
            (static_cast<uint32_t>(segment.flags()) &
             static_cast<uint32_t>(LIEF::ELF::Segment::FLAGS::X)) != 0 &&
            entry >= segment.virtual_address() &&
            entry - segment.virtual_address() <= segment.physical_size() &&
            extent <= segment.physical_size() -
                          (entry - segment.virtual_address())) {
            loaded = true;
            break;
        }
    }
    if (!loaded || binary.get_section(".gcc_except_table")) return std::nullopt;

    for (const auto* function : functions.get_functions()) {
        if (function->target_address == entry &&
            function->operation == OperationType::Ref)
            return std::nullopt;
    }
    for (const auto& symbol : binary.symbols()) {
        if (symbol.value() > entry && symbol.value() - entry < extent)
            return std::nullopt;
        if (symbol.value() < entry && symbol.size() &&
            entry - symbol.value() < symbol.size())
            return std::nullopt;
    }
    for (const auto& relocation : binary.relocations()) {
        const uint64_t address = relocation.address();
        if (address >= entry && address - entry < extent) return std::nullopt;
        const uint64_t addend = static_cast<uint64_t>(relocation.addend());
        if (addend > entry && addend - entry < extent) return std::nullopt;
    }

    // Absolute function pointers in allocated data can bypass the entry.
    for (const auto& data : binary.sections()) {
        if (!data.has(LIEF::ELF::Section::FLAGS::ALLOC) ||
            data.has(LIEF::ELF::Section::FLAGS::EXECINSTR) ||
            data.type() == LIEF::ELF::Section::TYPE::NOBITS)
            continue;
        auto bytes = data.content();
        for (size_t i = 0; i + sizeof(uint64_t) <= bytes.size(); ++i) {
            uint64_t value = 0;
            for (size_t j = 0; j < sizeof(value); ++j)
                value |= uint64_t(bytes[i + j]) << (j * 8);
            if (value > entry && value - entry < extent) return std::nullopt;
        }
    }

    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return std::nullopt;
    bool safe = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK;
    for (const auto& code : binary.sections()) {
        if (!safe) break;
        if (!code.has(LIEF::ELF::Section::FLAGS::EXECINSTR) || !code.size())
            continue;
        auto bytes = code.content();
        cs_insn* instructions = nullptr;
        size_t count = cs_disasm(handle, bytes.data(), bytes.size(),
                                 code.virtual_address(), 0, &instructions);
        if (!count || instructions[count - 1].address +
                          instructions[count - 1].size !=
                          code.virtual_address() + bytes.size())
            safe = false;
        for (size_t i = 0; i < count; ++i) {
            const auto& insn = instructions[i];
            if (!insn.detail) { safe = false; break; }
            if (insn.address >= entry && insn.address - entry < extent)
                continue;
            const auto& x86 = insn.detail->x86;
            for (uint8_t j = 0; j < x86.op_count; ++j) {
                uint64_t target = 0;
                if (x86.operands[j].type == X86_OP_MEM &&
                    x86.operands[j].mem.base == X86_REG_RIP)
                    target = insn.address + insn.size + x86.operands[j].mem.disp;
                else if (x86.operands[j].type == X86_OP_IMM &&
                         (cs_insn_group(handle, &insn, CS_GRP_CALL) ||
                          cs_insn_group(handle, &insn, CS_GRP_JUMP)))
                    target = x86.operands[j].imm;
                if (target > entry && target - entry < extent) safe = false;
            }
        }
        cs_free(instructions, count);
    }
    cs_close(&handle);
    return safe ? std::optional<uint64_t>(extent) : std::nullopt;
}

void plan_function_placement(const LIEF::ELF::Binary& target,
                             FunctionMap& functions, bool allow_in_place) {
    for (auto* function : functions.get_functions()) {
        function->in_place = false;
        function->target_size = 0;
        if (function->operation != OperationType::Fix) continue;
        auto extent = verified_function_extent(target, function->target_address,
                                               functions);
        if (!extent) continue;
        function->target_size = *extent;
        function->in_place = allow_in_place && function->size <= *extent;
    }
}

#endif // PLACEMENT_HPP
