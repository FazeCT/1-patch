#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>
#include <LIEF/LIEF.hpp>

#ifndef RUNTIME_BINDINGS_HPP
#define RUNTIME_BINDINGS_HPP

struct RuntimeReference {
    std::string name;
    uint64_t value;
    bool tls = false;
    bool original = false;
    bool redirected = false;
};

struct RuntimeVariablePatch {
    std::string name;
    uint64_t target_address;
    std::vector<uint8_t> initializer;
    bool tls = false;
};

struct RuntimeLifecycleHook {
    std::string name;
    uint64_t value;
    uint64_t size;
    bool tls = false;
    uint64_t initializer = 0;
    uint64_t priority = 0;
};

inline bool is_tls_initializer_for(const LIEF::ELF::Symbol& initializer, const std::string& linkage_name, const std::string& display_name) {
    if (initializer.name().rfind("_ZTH", 0) != 0)
        return false;

    const std::string display = initializer.demangled_name();
    const std::string expected = "TLS init function for " + display_name;

    if (display == expected || display.rfind(expected + "[abi:", 0) == 0)
        return true;

    // GCC can retain C linkage names directly in its TLS helper symbols
    const std::string encoded = "_ZTH" + std::to_string(linkage_name.size()) + linkage_name;

    if (initializer.name() == "_ZTH" + linkage_name || initializer.name() == encoded || initializer.name().rfind(encoded + "B", 0) == 0)
        return true;

    return linkage_name.rfind("_Z", 0) == 0 && initializer.name() == "_ZTH" + linkage_name.substr(2);
}

inline const LIEF::ELF::Symbol& target_tls_symbol(const LIEF::ELF::Binary& binary, uint64_t offset) {
    const LIEF::ELF::Symbol* found = nullptr;

    for (const auto& symbol : binary.symbols()) {
        if (symbol.type() != LIEF::ELF::Symbol::TYPE::TLS || symbol.value() != offset || !symbol.shndx() || !symbol.size())
            continue;

        if (found && (found->size() != symbol.size() || found->shndx() != symbol.shndx())) {
            throw std::runtime_error("Ambiguous target TLS offset");
        }

        found = &symbol;
    }

    const auto* tls = binary.get(LIEF::ELF::Segment::TYPE::TLS);

    if (!found || !tls || offset > tls->virtual_size() || found->size() > tls->virtual_size() - offset) {
        throw std::runtime_error("Target TLS offset has no bounded TLS symbol");
    }

    return *found;
}

inline const LIEF::ELF::Section& tls_symbol_section(const LIEF::ELF::Binary& binary, const LIEF::ELF::Symbol& symbol) {
    size_t index = 0;

    for (const auto& section : binary.sections()) {
        if (index++ == symbol.shndx()) {
            if (!section.has(LIEF::ELF::Section::FLAGS::TLS))
                break;

            return section;
        }
    }

    throw std::runtime_error("Target TLS symbol has no TLS section");
}

#endif
