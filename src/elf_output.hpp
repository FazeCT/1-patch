#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#include <LIEF/LIEF.hpp>

#ifndef ELF_OUTPUT_HPP
#define ELF_OUTPUT_HPP

// Once the ELF builder has allocated its tables, further instruction patches must not invoke the builder again
// Rebuilding a reparsed binary can relocate its PHDR table into existing data and invalidate added sections in LIEF 1.0
inline void validate_runtime_elf_layout(const LIEF::ELF::Binary& binary) {
    for (const auto& section : binary.sections()) {
        if (!section.has(LIEF::ELF::Section::FLAGS::ALLOC) || !section.size() || section.type() == LIEF::ELF::Section::TYPE::NOBITS)
            continue;

        bool mapped = false;

        for (const auto& segment : binary.segments()) {
            if (!segment.is_load() || section.virtual_address() < segment.virtual_address())
                continue;

            const uint64_t delta = section.virtual_address() - segment.virtual_address();

            if (delta <= segment.physical_size() && section.size() <= segment.physical_size() - delta && section.file_offset() >= segment.file_offset() && section.file_offset() - segment.file_offset() == delta) {
                mapped = true;
                break;
            }
        }

        if (!mapped) {
            throw std::runtime_error("ELF section has no matching load mapping: " + section.name());
        }
    }

    for (const auto& phdr : binary.segments()) {
        if (phdr.type() != LIEF::ELF::Segment::TYPE::PHDR)
            continue;

        bool mapped = false;

        for (const auto& load : binary.segments()) {
            if (!load.is_load() || phdr.virtual_address() < load.virtual_address())
                continue;

            const uint64_t delta = phdr.virtual_address() - load.virtual_address();

            if (delta <= load.physical_size() && phdr.physical_size() <= load.physical_size() - delta && phdr.file_offset() >= load.file_offset() && phdr.file_offset() - load.file_offset() == delta) {
                mapped = true;
                break;
            }
        }

        if (!mapped) {
            throw std::runtime_error("ELF program headers are not fully mapped");
        }
    }
}

inline void write_runtime_elf(const LIEF::ELF::Binary& binary, const std::string& path) {
    validate_runtime_elf_layout(binary);

    std::ifstream input(path, std::ios::binary);

    if (!input) {
        throw std::runtime_error("Failed to read staged ELF");
    }

    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)),
                               std::istreambuf_iterator<char>());

    if (bytes.size() < 64 || bytes[0] != 0x7f || bytes[1] != 'E' || bytes[2] != 'L' || bytes[3] != 'F' || bytes[4] != 2 || bytes[5] != 1 || bytes[18] != 62 || bytes[19] != 0) {
        throw std::runtime_error("Runtime output must be little-endian x86-64 ELF");
    }

    auto read_le = [&](uint64_t offset, size_t size) {
        if (size > 8 || offset > bytes.size() || size > bytes.size() - offset) {
            throw std::runtime_error("ELF field is outside staged output");
        }

        uint64_t value = 0;

        for (size_t i = 0; i < size; ++i) {
            value |= uint64_t(bytes[offset + i]) << (i * 8);
        }

        return value;
    };
    auto write_le = [&](uint64_t offset, uint64_t value, size_t size) {
        if (size > 8 || offset > bytes.size() || size > bytes.size() - offset) {
            throw std::runtime_error("ELF update is outside staged output");
        }

        for (size_t i = 0; i < size; ++i) {
            bytes[offset + i] = uint8_t(value >> (i * 8));
        }
    };

    // patch_address updates section contents
    for (const auto& section : binary.sections()) {
        if (section.type() == LIEF::ELF::Section::TYPE::NOBITS)
            continue;

        const auto content = section.content();

        if (content.size() != section.size() || section.file_offset() > bytes.size() || content.size() > bytes.size() - section.file_offset()) {
            throw std::runtime_error("ELF section content is outside staged output");
        }

        std::copy(content.begin(), content.end(), bytes.begin() + section.file_offset());
    }

    const auto* dynamic = binary.get_section(".dynamic");
    const auto* init = binary.get(LIEF::ELF::DynamicEntry::TAG::INIT);

    if (!dynamic || !init || dynamic->size() % 16) {
        throw std::runtime_error("Missing runtime ELF initializer table");
    }

    bool installed_init = false;

    for (uint64_t offset = 0; offset < dynamic->size(); offset += 16) {
        if (read_le(dynamic->file_offset() + offset, 8) == 12) { // DT_INIT
            write_le(dynamic->file_offset() + offset + 8, init->value(), 8);
            installed_init = true;
        }
    }

    if (!installed_init) {
        throw std::runtime_error("Missing on-disk DT_INIT entry");
    }

    std::map<uint64_t, uint64_t> relative_addends;

    for (const auto& relocation : binary.dynamic_relocations()) {
        if (relocation.type() == LIEF::ELF::Relocation::TYPE::X86_64_RELATIVE)
            relative_addends.emplace(relocation.address(), uint64_t(relocation.addend()));
    }

    for (const auto& section : binary.sections()) {
        if (section.type() != LIEF::ELF::Section::TYPE::RELA)
            continue;

        if (section.size() % 24) {
            throw std::runtime_error("Invalid ELF64 RELA table");
        }

        for (uint64_t offset = 0; offset < section.size(); offset += 24) {
            const uint64_t entry = section.file_offset() + offset;

            if ((read_le(entry + 8, 8) & 0xffffffff) != 8)
                continue; // R_X86_64_RELATIVE

            auto addend = relative_addends.find(read_le(entry, 8));

            if (addend == relative_addends.end()) {
                throw std::runtime_error("Missing runtime relative relocation");
            }

            write_le(entry + 16, addend->second, 8);
        }
    }

    const auto* dynsym = binary.get_section(".dynsym");
    const auto* dynstr = binary.get_section(".dynstr");

    if (!dynsym || !dynstr || dynsym->size() % 24) {
        throw std::runtime_error("Invalid runtime dynamic symbol table");
    }

    size_t index = 0;

    for (const auto& symbol : binary.dynamic_symbols()) {
        if (index >= dynsym->size() / 24) {
            throw std::runtime_error("Runtime dynamic symbol count changed");
        }

        const uint64_t entry = dynsym->file_offset() + index++ * 24;
        const uint64_t name_offset = read_le(entry, 4);

        if (name_offset >= dynstr->size()) {
            throw std::runtime_error("Invalid dynamic symbol name");
        }

        std::string name;

        for (uint64_t i = name_offset; i < dynstr->size(); ++i) {
            const char c = char(bytes[dynstr->file_offset() + i]);

            if (c == 0)
                break;

            name += c;
        }

        if (name != symbol.name()) {
            throw std::runtime_error("Runtime dynamic symbols changed order");
        }

        write_le(entry + 6, symbol.shndx(), 2);
        write_le(entry + 8, symbol.value(), 8);
        write_le(entry + 16, symbol.size(), 8);
    }

    if (index != dynsym->size() / 24) {
        throw std::runtime_error("Runtime dynamic symbol count changed");
    }

    std::ofstream output(path, std::ios::binary | std::ios::trunc);

    if (!output) {
        throw std::runtime_error("Failed to update staged ELF");
    }

    output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    output.close();
    if (!output) {
        throw std::runtime_error("Failed to finish staged ELF updates");
    }
}

#endif
