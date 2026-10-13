#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <vector>
#include <LIEF/LIEF.hpp>
#include "runtime_bindings.hpp"

#ifndef RUNTIME_TLS_IMAGE_HPP
#define RUNTIME_TLS_IMAGE_HPP

inline void prepare_runtime_tls_image(LIEF::ELF::Binary& output, const std::vector<RuntimeVariablePatch>& patches) {
    if (std::none_of(patches.begin(), patches.end(), [](const auto& patch) { return patch.tls; }))
        return;

    auto* tls = output.get(LIEF::ELF::Segment::TYPE::TLS);

    if (!tls || !tls->virtual_size() || tls->virtual_size() > (16u << 20)) {
        throw std::runtime_error("Missing or oversized target TLS template");
    }

    if (output.has_section(".patch.tls_image")) {
        throw std::runtime_error("Target already has a replacement TLS template");
    }

    const uint64_t size = tls->virtual_size();
    const uint64_t alignment = tls->alignment();
    LIEF::ELF::Section image(".patch.tls_image");

    image.type(LIEF::ELF::Section::TYPE::PROGBITS);
    image.flags(uint64_t(LIEF::ELF::Section::FLAGS::ALLOC) |
                uint64_t(LIEF::ELF::Section::FLAGS::WRITE) | uint64_t(LIEF::ELF::Section::FLAGS::TLS));
    image.alignment(alignment);
    image.content(std::vector<uint8_t>(size, 0));

    auto* added = output.add(image);

    if (!added) {
        throw std::runtime_error("Failed to allocate replacement TLS template");
    }

    const uint64_t old_address = tls->virtual_address();
    const uint64_t old_size = tls->physical_size();

    if (old_size > size) {
        throw std::runtime_error("TLS file image exceeds its memory template");
    }

    std::vector<uint8_t> bytes(size, 0);

    if (old_size) {
        auto initialized = output.get_content_from_virtual_address(old_address, old_size);

        if (initialized.size() != old_size) {
            throw std::runtime_error("Truncated original TLS template");
        }

        std::copy(initialized.begin(), initialized.end(), bytes.begin());
    }

    for (auto& relocation : output.dynamic_relocations()) {
        if (relocation.address() < old_address || relocation.address() - old_address >= old_size)
            continue;

        const uint64_t offset = relocation.address() - old_address;

        if (relocation.type() == LIEF::ELF::Relocation::TYPE::X86_64_RELATIVE) {
            if (offset > size || 8 > size - offset) {
                throw std::runtime_error("TLS relocation exceeds template");
            }

            for (unsigned i = 0; i < 8; ++i) {
                bytes[offset + i] = uint8_t(uint64_t(relocation.addend()) >> (i * 8));
            }
        }

        relocation.address(added->virtual_address() + offset);
    }

    for (const auto& patch : patches) {
        if (!patch.tls)
            continue;

        if (patch.target_address > size || patch.initializer.size() > size - patch.target_address) {
            throw std::runtime_error("TLS replacement exceeds target template");
        }

        std::copy(patch.initializer.begin(), patch.initializer.end(), bytes.begin() + patch.target_address);
    }

    added->content(bytes);

    uint16_t index = 0;
    bool found = false;

    for (auto& section : output.sections()) {
        if (&section == added) {
            found = true;
            break;
        }

        if (index == 0xff00 - 1) {
            throw std::runtime_error("Too many sections for TLS replacement");
        }

        ++index;
    }

    if (!found) {
        throw std::runtime_error("Missing replacement TLS section");
    }

    for (auto& symbol : output.symbols()) {
        if (symbol.type() == LIEF::ELF::Symbol::TYPE::TLS && symbol.shndx())
            symbol.shndx(index);
    }

    for (auto& section : output.sections()) {
        if (&section == added || !section.has(LIEF::ELF::Section::FLAGS::TLS))
            continue;

        uint64_t flags = section.flags() & ~uint64_t(LIEF::ELF::Section::FLAGS::TLS);

        if (section.type() == LIEF::ELF::Section::TYPE::NOBITS)
            flags &= ~(uint64_t(LIEF::ELF::Section::FLAGS::ALLOC) | uint64_t(LIEF::ELF::Section::FLAGS::WRITE));

        section.flags(flags);
    }

    tls->file_offset(added->file_offset());
    tls->virtual_address(added->virtual_address());
    tls->physical_address(added->virtual_address());
    tls->physical_size(size);
    tls->virtual_size(size);
    tls->alignment(alignment);
}

#endif
