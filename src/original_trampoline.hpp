#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <stdexcept>
#include <vector>
#include <LIEF/LIEF.hpp>
#include <capstone/capstone.h>
#include "runtime_bindings.hpp"

#ifndef ORIGINAL_TRAMPOLINE_HPP
#define ORIGINAL_TRAMPOLINE_HPP

struct OriginalTrampoline {
    uint64_t target_address;
    uint64_t target_size;
    uint64_t landing_pad;
    uint64_t storage_offset;
    std::vector<uint8_t> prologue;
    uint64_t new_address = 0;

    uint64_t size() const {
        return 4 + prologue.size() + 5;
    }
};

inline std::vector<OriginalTrampoline> plan_original_trampolines(const LIEF::ELF::Binary& binary, const std::vector<RuntimeReference>& references) {
    std::set<uint64_t> entries;

    for (const auto& reference : references) {
        if (reference.original && !reference.tls)
            entries.insert(reference.value);
    }

    std::vector<OriginalTrampoline> result;
    uint64_t offset = 0;

    for (uint64_t entry : entries) {
        uint64_t extent = 0;

        for (const auto& symbol : binary.symbols()) {
            if (!symbol.is_function() || symbol.value() != entry || !symbol.size())
                continue;

            if (extent && extent != symbol.size()) {
                throw std::runtime_error("Original function has conflicting extents");
            }

            extent = symbol.size();
        }

        if (!extent || extent > UINT64_MAX - entry) {
            throw std::runtime_error("Original-function calls require a bounded function symbol");
        }

        auto content = binary.get_content_from_virtual_address(entry, std::min<uint64_t>(extent, 68));
        std::vector<uint8_t> bytes(content.begin(), content.end());
        const uint64_t pad = bytes.size() >= 4 && bytes[0] == 0xf3 && bytes[1] == 0x0f && bytes[2] == 0x1e && bytes[3] == 0xfa ? 4 : 0;

        if (extent < pad + 5 || bytes.size() < pad + 5) {
            throw std::runtime_error("Original function is too short for a safe entry jump");
        }

        csh handle;

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
            throw std::runtime_error("Failed to inspect original function entry");
        }

        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

        cs_insn* instructions = nullptr;
        const size_t count = cs_disasm(handle, bytes.data() + pad, bytes.size() - pad,
                                       entry + pad, 0, &instructions);
        size_t covered = 0;
        bool safe = count != 0;

        for (size_t i = 0; safe && i < count && covered < 5; ++i) {
            const auto& instruction = instructions[i];

            if (!instruction.detail || instruction.address != entry + pad + covered || cs_insn_group(handle, &instruction, CS_GRP_CALL) || cs_insn_group(handle, &instruction, CS_GRP_RET) || cs_insn_group(handle, &instruction, CS_GRP_INT)) {
                safe = false;
                break;
            }

            if (cs_insn_group(handle, &instruction, CS_GRP_JUMP) && instruction.detail->x86.encoding.imm_size == 1) {
                safe = false;
                break;
            }

            covered += instruction.size;
        }

        cs_free(instructions, count);
        cs_close(&handle);
        if (!safe || covered < 5 || covered > extent - pad) {
            throw std::runtime_error("Original function entry cannot be relocated with preserved unwind state");
        }

        OriginalTrampoline trampoline{entry, extent, pad, offset,
                                      std::vector<uint8_t>(bytes.begin() + pad, bytes.begin() + pad + covered)};

        offset += trampoline.size();
        result.push_back(std::move(trampoline));
    }

    return result;
}

#endif
