#include <stdint.h> 
#include <ctime>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <vector>

#include <capstone/capstone.h>

#include "object.hpp"

#ifndef UTILS_HPP
#define UTILS_HPP

// Convert hexadecimal to decimal
uint64_t hex_to_decimal(const std::string& hex) {
    return std::stoull(hex, nullptr, 16);
}

// Calculate FNV-1a hash
std::string fnv1a_hash(const std::string& input) {
    const uint64_t fnv_prime = 0x100000001b3u;
    const uint64_t offset_basis = 0xcbf29ce484222325u;

    uint64_t hash = offset_basis;
    for (char c : input) {
        hash ^= static_cast<uint64_t>(c);
        hash *= fnv_prime;
    }

    std::stringstream hash_string;
    hash_string << std::hex << std::setw(16) << std::setfill('0') << hash;
    return hash_string.str();
}

// Generate random string
std::string generate_random_string() {
    std::srand(static_cast<unsigned int>(std::time(nullptr)));
    int rand = std::rand();

    return fnv1a_hash(std::to_string(rand));
}

// Extract global variables/functions references from a code section
std::vector<Reference> extract_references(const std::vector<uint8_t>& code, uint64_t start_address) {
    std::vector<Reference> references;

    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize Capstone");
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    count = cs_disasm(handle, code.data(), code.size(), start_address, 0, &insn);

    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            const cs_insn& instruction = insn[i];
            const cs_detail* detail = instruction.detail;

            if (detail) {
                bool control_flow_instruction = false;

                for (size_t j = 0; j < detail->groups_count; j++) {
                    if (detail->groups[j] == CS_GRP_JUMP || detail->groups[j] == CS_GRP_CALL) {
                        control_flow_instruction = true;
                        uint64_t resolved_address = std::stoull(instruction.op_str, nullptr, 16);
                        if (resolved_address >= start_address && resolved_address < start_address + code.size()) {
                            continue;
                        }
                        references.push_back(Reference{instruction.address, SymbolType::Function, instruction.mnemonic, resolved_address});
                        break;
                    }
                }

                if (!control_flow_instruction) {
                    for (size_t j = 0; j < detail->x86.op_count; j++) {
                        const cs_x86_op& op = detail->x86.operands[j];
                        if (op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP) {
                            uint64_t resolved_address = instruction.address + instruction.size + op.mem.disp;
                            references.push_back(Reference{instruction.address, SymbolType::GlobalVariable, instruction.mnemonic, resolved_address});
                        }
                    }
                }
            }
        }
        cs_free(insn, count);
    } else {
        throw std::runtime_error("Failed to disassemble code");
    }

    cs_close(&handle);
    return references;
}

#endif // UTILS_HPP