#ifndef GOT_REUSE_HPP
#define GOT_REUSE_HPP

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <tuple>

#include <LIEF/LIEF.hpp>

// Reuse only import slots with the same loader contract. A symbol name alone
// is insufficient: different versions and relocation kinds can resolve to
// different addresses or have different lazy-binding behavior.
struct GotReuseKey {
    std::string symbol_name;
    std::string version_name;
    std::string version_library;
    LIEF::ELF::Relocation::TYPE relocation_type;
    LIEF::ELF::Symbol::TYPE symbol_type;
    LIEF::ELF::Symbol::BINDING binding;
    LIEF::ELF::Symbol::VISIBILITY visibility;
    uint8_t version_kind = 0;
    uint16_t unqualified_version = 0;
    bool hidden_version = false;

    bool operator<(const GotReuseKey& other) const {
        return std::tie(symbol_name, version_name, version_library,
                        relocation_type, symbol_type, binding, visibility,
                        version_kind, unqualified_version, hidden_version) <
               std::tie(other.symbol_name, other.version_name,
                        other.version_library, other.relocation_type,
                        other.symbol_type, other.binding, other.visibility,
                        other.version_kind, other.unqualified_version,
                        other.hidden_version);
    }
};

inline std::optional<GotReuseKey> got_reuse_key(
    const LIEF::ELF::Binary& binary, const LIEF::ELF::Relocation& relocation) {
    const LIEF::ELF::Symbol* symbol = relocation.symbol();
    if (!symbol || symbol->name().empty() || !symbol->is_imported() ||
        relocation.addend() != 0 ||
        (relocation.type() != LIEF::ELF::Relocation::TYPE::X86_64_JUMP_SLOT &&
         relocation.type() != LIEF::ELF::Relocation::TYPE::X86_64_GLOB_DAT)) {
        return std::nullopt;
    }

    GotReuseKey key{symbol->name(), "", "", relocation.type(),
                    symbol->type(), symbol->binding(), symbol->visibility()};
    const LIEF::ELF::SymbolVersion* version = symbol->symbol_version();
    if (!version) return key;

    const LIEF::ELF::SymbolVersionAux* auxiliary =
        version->symbol_version_auxiliary();
    if (!auxiliary) {
        // Unversioned and explicitly global/local versions are kept distinct.
        if (version->value() > 1) return std::nullopt;
        key.version_kind = 1;
        key.unqualified_version = version->value();
        return key;
    }

    key.version_kind = 2;
    key.version_name = auxiliary->name();
    key.hidden_version = (version->value() & 0x8000) != 0;
    if (key.version_name.empty()) return std::nullopt;

    // Version indices are local to each ELF, so compare the required version
    // and provider library rather than comparing numeric version indices.
    bool found_provider = false;
    for (const auto& requirement : binary.symbols_version_requirement()) {
        for (const auto& candidate : requirement.auxiliary_symbols()) {
            if ((candidate.other() & 0x7fff) != (version->value() & 0x7fff) ||
                candidate.name() != key.version_name) {
                continue;
            }
            if (found_provider && key.version_library != requirement.name()) {
                return std::nullopt;
            }
            key.version_library = requirement.name();
            found_provider = true;
        }
    }
    if (!found_provider || key.version_library.empty()) return std::nullopt;
    return key;
}

inline bool is_existing_got_slot(const LIEF::ELF::Binary& binary,
                                 uint64_t address) {
    const LIEF::ELF::Section* section =
        binary.section_from_virtual_address(address);
    return section &&
           (section->name() == ".got" || section->name() == ".got.plt") &&
           section->has(LIEF::ELF::Section::FLAGS::ALLOC) &&
           section->has(LIEF::ELF::Section::FLAGS::WRITE) &&
           address >= section->virtual_address() &&
           address - section->virtual_address() <= section->size() &&
           sizeof(uint64_t) <= section->size() -
               (address - section->virtual_address());
}

// Map patch relocation addresses to original target GOT addresses. Ambiguous
// target imports are left for a new slot instead of selecting one arbitrarily.
inline std::map<uint64_t, uint64_t> reusable_got_entries(
    const LIEF::ELF::Binary& patch, const LIEF::ELF::Binary& target) {
    std::map<GotReuseKey, std::optional<uint64_t>> target_slots;
    for (const auto& relocation : target.relocations()) {
        if (!is_existing_got_slot(target, relocation.address())) continue;
        auto key = got_reuse_key(target, relocation);
        if (!key) continue;
        auto [entry, inserted] = target_slots.emplace(*key, relocation.address());
        if (!inserted) entry->second = std::nullopt;
    }

    std::map<uint64_t, uint64_t> reused;
    for (const auto& relocation : patch.pltgot_relocations()) {
        auto key = got_reuse_key(patch, relocation);
        if (!key) continue;
        auto entry = target_slots.find(*key);
        if (entry != target_slots.end() && entry->second) {
            reused.emplace(relocation.address(), *entry->second);
        }
    }
    return reused;
}

#endif // GOT_REUSE_HPP
