#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <map>
#include <tuple>
#include <utility>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <LIEF/LIEF.hpp>

#include "compiler.hpp"
#include "utils.hpp"
#include "runtime_bindings.hpp"
#include "runtime_dwarf.hpp"
#include "runtime_tls_image.hpp"

#ifndef CPP_RUNTIME_HPP
#define CPP_RUNTIME_HPP

class RuntimeCppPatch {
public:
    RuntimeCppPatch(const std::string& source, const std::string& target, const PatchCompilerOptions& options = {}) : options_(options) {
        std::string pattern = (std::filesystem::temp_directory_path() / "1-patch-cpp-XXXXXX").string();
        std::vector<char> name(pattern.begin(), pattern.end());

        name.push_back('\0');

        char* created = mkdtemp(name.data());

        if (!created) {
            throw std::runtime_error("Failed to create C++ runtime build directory");
        }

        directory_ = created;

        try {
            const auto library = library_path();

            compile_cpp_shared_object(source, library, options_);

            auto patch = LIEF::ELF::Parser::parse(library);
            auto target_elf = LIEF::ELF::Parser::parse(target);

            if (!patch || !target_elf) {
                throw std::runtime_error("Failed to parse C++ runtime patch or target");
            }

            std::ifstream target_file(target, std::ios::binary | std::ios::ate);

            if (!target_file) {
                throw std::runtime_error("Failed to read target executable");
            }

            if (target_file.tellg() >= std::streamoff(16)) {
                target_file.seekg(-16, std::ios::end);

                char magic[8] = {};

                target_file.read(magic, sizeof(magic));
                if (target_file && std::string(magic, sizeof(magic)) == "_1-PATCH_") {
                    throw std::runtime_error("Target already contains an embedded C++ patch; repeated runtime patching is unsupported");
                }
            }

            const auto* init = target_elf->get(LIEF::ELF::DynamicEntry::TAG::INIT);

            if (!init || !init->value() || !target_elf->has_section(".dynamic")) {
                throw std::runtime_error("C++ runtime mode needs a dynamically linked target with DT_INIT");
            }

            original_init_ = init->value();

            std::set<uint64_t> fixed_targets;
            std::set<std::string> seen_markers;
            std::set<std::string> seen_references;
            std::set<std::string> exported;
            size_t added_variables = 0;

            for (const auto& symbol : patch->dynamic_symbols()) {
                if (symbol.shndx() && symbol.size())
                    exported.insert(symbol.name());
            }

            static const std::regex safe_name("^[A-Za-z_][A-Za-z_0-9]*$");

            for (const auto& symbol : patch->symbols()) {
                const std::string name = symbol.name();

                if (name.rfind("__onepatch_", 0) == 0) {
                    throw std::runtime_error("C++ patch uses a reserved __onepatch_ symbol");
                }

                if (name.rfind("ref_", 0) == 0) {
                    if (!seen_references.insert(name).second)
                        continue;

                    const uint64_t address = parse_address(name.substr(4));

                    if (address == UINT64_MAX || symbol.value() != 0 || symbol.shndx() != 0) {
                        throw std::runtime_error("C++ runtime ref_ markers must be unresolved declarations with target addresses");
                    }

                    references_.push_back({name, address, symbol.type() == LIEF::ELF::Symbol::TYPE::TLS});
                    continue;
                }

                if (name.rfind("_Z", 0) == 0) {
                    const std::string demangled = symbol.demangled_name();

                    if (demangled.rfind("fix_", 0) == 0 || demangled.rfind("add_", 0) == 0 || demangled.rfind("ref_", 0) == 0) {
                        throw std::runtime_error("C++ patch markers require extern \"C\" linkage");
                    }
                }

                if (name.rfind("fix_size_", 0) == 0 || name.rfind("fix_tls_size_", 0) == 0 || name.rfind("fix_priority_", 0) == 0 || name.rfind("fix_tls_priority_", 0) == 0)
                    continue;

                if (is_lifecycle_hook(*patch, *target_elf, symbol)) {
                    if (!seen_markers.insert(name).second)
                        continue;

                    if (!std::regex_match(name, safe_name) || !symbol.is_function() || !symbol.shndx() || !exported.count(name)) {
                        throw std::runtime_error("Lifecycle fix_ hooks require exported extern C functions");
                    }

                    hooks_.push_back(lifecycle_hook(*patch, *target_elf, symbol));
                    continue;
                }

                if (name.rfind("fix_", 0) != 0 && name.rfind("add_", 0) != 0)
                    continue;

                if (!seen_markers.insert(name).second)
                    continue;

                if (!std::regex_match(name, safe_name) || !symbol.shndx() || !symbol.size() || !exported.count(name) || name.rfind("add_patch_", 0) == 0) {
                    throw std::runtime_error("C++ runtime markers must be exported definitions with unreserved names");
                }

                if (symbol.is_variable() || symbol.type() == LIEF::ELF::Symbol::TYPE::TLS) {
                    if (name.rfind("fix_", 0) == 0) {
                        const uint64_t address = parse_address(name.substr(4));

                        if (address == UINT64_MAX) {
                            throw std::runtime_error("Invalid runtime variable fix_ address");
                        }

                        variables_.push_back(variable_patch(*patch, *target_elf, symbol, address, library, target));
                        references_.push_back({name, address, symbol.type() == LIEF::ELF::Symbol::TYPE::TLS});
                    } else {
                        ++added_variables;
                    }

                    continue;
                }

                if (!symbol.is_function() || !symbol.value()) {
                    throw std::runtime_error("Unsupported C++ runtime marker kind");
                }

                if (name.rfind("fix_", 0) == 0) {
                    const uint64_t address = parse_address(name.substr(4));

                    if (address == UINT64_MAX || !fixed_targets.insert(address).second) {
                        throw std::runtime_error("Invalid or duplicate C++ runtime fix_ address");
                    }
                }

                names_.push_back(name);
            }

            std::sort(names_.begin(), names_.end());
            names_.erase(std::unique(names_.begin(), names_.end()), names_.end());
            if (names_.empty() && variables_.empty() && hooks_.empty() && !added_variables) {
                throw std::runtime_error("C++ runtime patch has no exported add_ or fix_ definition");
            }

            std::sort(hooks_.begin(), hooks_.end(), [](const auto& left, const auto& right) {
                return std::tie(left.priority, left.name) < std::tie(right.priority, right.name);
            });

            for (const auto& hook : hooks_) {
                if (!hook.tls || tls_groups_.count(hook.initializer))
                    continue;

                if (fixed_targets.count(hook.initializer)) {
                    throw std::runtime_error("TLS lifecycle hook conflicts with an explicit fix_ of its initializer");
                }

                tls_groups_.insert(hook.initializer);

                const std::string name = "fix_" + decimal_to_hex(hook.initializer) + "_runtime_tls_init";

                names_.push_back(name);
                fixed_targets.insert(hook.initializer);
                references_.push_back({"ref_" + decimal_to_hex(hook.initializer) + "_runtime_tls_original", hook.initializer, false, true});
            }

            for (const auto& hook : hooks_) {
                if (hook.tls) {
                    references_.push_back({"ref_" + decimal_to_hex(hook.value) + "_runtime_tls_storage", hook.value, true});
                }
            }

            for (auto& reference : references_) {
                if (!reference.tls && fixed_targets.count(reference.value) && !reference.redirected)
                    reference.original = true;
            }

            {
                std::map<std::string, RuntimeReference> unique;

                for (const auto& reference : references_) {
                    auto [position, inserted] = unique.emplace(reference.name, reference);

                    if (!inserted && (position->second.value != reference.value || position->second.tls != reference.tls || position->second.original != reference.original)) {
                        throw std::runtime_error("Conflicting runtime binding names");
                    }
                }

                references_.clear();

                for (const auto& binding : unique) {
                    references_.push_back(binding.second);
                }
            }

            std::vector<RuntimeReference> initializers;

            for (const auto& reference : references_) {
                if (!reference.tls)
                    continue;

                const auto& original_symbol = target_tls_symbol(*target_elf, reference.value);

                (void)tls_symbol_section(*target_elf, original_symbol);

                std::string original_name = original_symbol.demangled_name();

                if (original_name.empty())
                    original_name = original_symbol.name();

                for (const auto& imported : patch->dynamic_symbols()) {
                    if (imported.shndx() || !is_tls_initializer_for(imported, reference.name, reference.name))
                        continue;

                    for (const auto& original_initializer : target_elf->symbols()) {
                        if (original_initializer.is_function() && original_initializer.value() && is_tls_initializer_for(original_initializer, original_symbol.name(), original_name)) {
                            initializers.push_back({imported.name(), original_initializer.value(), false, false, fixed_targets.count(original_initializer.value()) != 0});
                            break;
                        }
                    }
                }
            }

            std::set<std::string> binding_names;

            for (const auto& reference : references_) {
                binding_names.insert(reference.name);
            }

            for (const auto& initializer : initializers) {
                if (binding_names.insert(initializer.name).second)
                    references_.push_back(initializer);
            }

            std::sort(names_.begin(), names_.end());
            names_.erase(std::unique(names_.begin(), names_.end()), names_.end());
            write_registration();
            compile_cpp_shared_object(source, library, options_, {(directory_ / "registration.cpp").string()}, "__onepatch_register");
            write_bootstrap();
        } catch (...) {
            std::error_code error;

            std::filesystem::remove_all(directory_, error);
            directory_.clear();
            throw;
        }
    }

    RuntimeCppPatch(const RuntimeCppPatch&) = delete;
    RuntimeCppPatch& operator=(const RuntimeCppPatch&) = delete;

    ~RuntimeCppPatch() {
        if (!directory_.empty()) {
            std::error_code error;

            std::filesystem::remove_all(directory_, error);
        }
    }

    std::string bootstrap_source() const {
        return (directory_ / "bootstrap.c").string();
    }

    std::string library_path() const {
        return (directory_ / "patch.so").string();
    }

    const std::vector<RuntimeReference>& references() const {
        return references_;
    }

    void prepare_tls_image(LIEF::ELF::Binary& binary) const {
        prepare_runtime_tls_image(binary, variables_);
    }

    uint64_t after_init_patch_address(const std::string& bootstrap_binary) const {
        if (std::none_of(hooks_.begin(), hooks_.end(), [](const auto& hook) { return !hook.tls; }))
            return UINT64_MAX;

        auto binary = LIEF::ELF::Parser::parse(bootstrap_binary);

        if (binary) {
            for (const auto& symbol : binary->symbols()) {
                if (symbol.name() == "add_patch_after_init")
                    return symbol.value();
            }
        }

        throw std::runtime_error("Missing replacement lifecycle initializer");
    }

    uint64_t init_patch_address(const std::string& bootstrap_binary) const {
        auto binary = LIEF::ELF::Parser::parse(bootstrap_binary);

        if (!binary) {
            throw std::runtime_error("Failed to parse C++ bootstrap");
        }

        for (const auto& symbol : binary->symbols()) {
            if (symbol.name() == "add_patch_init" && symbol.is_function())
                return symbol.value();
        }

        throw std::runtime_error("Missing C++ bootstrap initializer");
    }

    void append_library(const std::string& output) const {
        std::ifstream input(library_path(), std::ios::binary | std::ios::ate);

        if (!input) {
            throw std::runtime_error("Failed to read C++ patch library");
        }

        const auto length = input.tellg();

        if (length <= 0 || static_cast<uint64_t>(length) > UINT32_MAX) {
            throw std::runtime_error("C++ patch library is too large");
        }

        input.seekg(0);

        std::ofstream file(output, std::ios::binary | std::ios::app);

        if (!file) {
            throw std::runtime_error("Failed to append C++ patch library");
        }

        file << input.rdbuf();

        file.write("_1-PATCH_", 8);

        uint64_t size = static_cast<uint64_t>(length);

        for (unsigned i = 0; i < 8; ++i) {
            file.put(static_cast<char>(size >> (i * 8)));
        }

        if (!file) {
            throw std::runtime_error("Failed to finish embedded C++ patch");
        }
    }

private:
    void write_registration() const {
        std::ofstream out(directory_ / "registration.cpp", std::ios::binary | std::ios::trunc);

        if (!out) {
            throw std::runtime_error("Failed to create runtime registration source");
        }

        for (const auto& hook : hooks_) {
            out << "extern \"C\" void " << hook.name << "(void*) noexcept;\n";
        }

        size_t group = 0;

        for (uint64_t initializer : tls_groups_) {
            const std::string suffix = decimal_to_hex(initializer);

            out << "extern \"C\" void ref_" << suffix << "_runtime_tls_original();\n";

            for (const auto& hook : hooks_) {
                if (!hook.tls || hook.initializer != initializer)
                    continue;

                out << "extern \"C\" { extern __thread unsigned char ref_" << decimal_to_hex(hook.value) << "_runtime_tls_storage[" << hook.size << "]; }\n";
            }

            out << "static thread_local unsigned char __onepatch_tls_guard_" << group << ";\n"
                << "extern \"C\" void fix_" << suffix << "_runtime_tls_init() {\n"
                << "    if (__onepatch_tls_guard_" << group << ") return;\n"
                << "    __onepatch_tls_guard_" << group << " = 1;\n"
                << "    try { ref_" << suffix << "_runtime_tls_original();\n";

            for (const auto& hook : hooks_) {
                if (!hook.tls || hook.initializer != initializer)
                    continue;

                out << "        " << hook.name << "(ref_" << decimal_to_hex(hook.value) << "_runtime_tls_storage);\n";
            }

            out << "    } catch (...) { __onepatch_tls_guard_" << group << " = 0; throw; }\n}\n";
            ++group;
        }

        for (const auto& name : names_) {
            out << "__asm__(\".protected " << name << "\");\n";
        }

        out << "extern \"C\" __attribute__((naked, used, visibility(\"hidden\"))) void __onepatch_register() {\n"
               "    __asm__ volatile(\"";

        for (size_t i = 0; i < names_.size(); ++i) {
            out << "mov add_patch_slot_" << i << "@GOTPCREL(%rip), %rax\\n\\t" << "lea " << names_[i] << "(%rip), %r11\\n\\t" << "mov %r11, (%rax)\\n\\t";
        }

        out << "jmp _init\");\n}\n";
        if (!out) {
            throw std::runtime_error("Failed to write runtime registration source");
        }
    }

    bool is_lifecycle_hook(const LIEF::ELF::Binary& patch, const LIEF::ELF::Binary& target, const LIEF::ELF::Symbol& source) const {
        const std::string& name = source.name();

        if (name.rfind("fix_tls_", 0) == 0)
            return true;

        if (name.rfind("fix_", 0) != 0 || !source.is_function())
            return false;

        const std::string suffix = name.substr(4);

        for (const auto& symbol : patch.dynamic_symbols()) {
            if (symbol.name() == "fix_size_" + suffix && symbol.shndx())
                return true;
        }

        const uint64_t value = parse_address(suffix);

        if (value == UINT64_MAX)
            return false;

        for (const auto& symbol : target.symbols()) {
            if (symbol.type() == LIEF::ELF::Symbol::TYPE::OBJECT && symbol.value() == value)
                return true;
        }

        return false;
    }

    uint64_t metadata(const LIEF::ELF::Binary& patch, const std::string& name, bool required = true) const {
        for (const auto& symbol : patch.dynamic_symbols()) {
            if (symbol.name() != name || !symbol.shndx())
                continue;

            if (!symbol.is_variable() || symbol.size() != 8) {
                throw std::runtime_error("Replacement metadata must be an exported size_t constant: " + name);
            }

            for (const auto& relocation : patch.relocations()) {
                if (relocation.address() >= symbol.value() && relocation.address() - symbol.value() < 8) {
                    throw std::runtime_error("Replacement metadata must not contain relocations");
                }
            }

            auto content = patch.get_content_from_virtual_address(symbol.value(), 8);

            if (content.size() != 8) {
                throw std::runtime_error("Truncated replacement metadata");
            }

            return vector_to_int(std::vector<uint8_t>(content.begin(), content.end()));
        }

        if (required) {
            throw std::runtime_error("Missing replacement size metadata: " + name);
        }

        return 0;
    }

    RuntimeLifecycleHook lifecycle_hook(const LIEF::ELF::Binary& patch, const LIEF::ELF::Binary& target, const LIEF::ELF::Symbol& source) const {
        const bool tls = source.name().rfind("fix_tls_", 0) == 0;
        const std::string suffix = source.name().substr(tls ? 8 : 4);
        const uint64_t value = parse_address(suffix);

        if (value == UINT64_MAX) {
            throw std::runtime_error("Invalid replacement hook address or TLS offset");
        }

        const uint64_t size = metadata(patch, (tls ? "fix_tls_size_" : "fix_size_") + suffix);

        if (!size || size > (1u << 20) || value > UINT64_MAX - size) {
            throw std::runtime_error("Invalid replacement hook object size");
        }

        const LIEF::ELF::Symbol* object = nullptr;

        if (tls)
            object = &target_tls_symbol(target, value);
        else {
            for (const auto& symbol : target.symbols()) {
                if (symbol.type() == LIEF::ELF::Symbol::TYPE::OBJECT && symbol.value() == value && symbol.size()) {
                    object = &symbol;
                    break;
                }
            }

            const auto* section = target.section_from_virtual_address(value, false);

            if (!section || !section->has(LIEF::ELF::Section::FLAGS::WRITE) || section->has(LIEF::ELF::Section::FLAGS::TLS) || section->has(LIEF::ELF::Section::FLAGS::EXECINSTR)) {
                throw std::runtime_error("Object replacement needs writable ordinary storage");
            }

            for (const auto& segment : target.segments()) {
                if (segment.type() == LIEF::ELF::Segment::TYPE::GNU_RELRO && value < segment.virtual_address() + segment.virtual_size() && segment.virtual_address() < value + size) {
                    throw std::runtime_error("Object replacement cannot modify RELRO storage");
                }
            }
        }

        if (!object || object->size() != size) {
            throw std::runtime_error("Replacement hook size must match the complete target object");
        }

        uint64_t initializer = 0;

        if (tls) {
            std::string display = object->demangled_name();

            if (display.empty())
                display = object->name();

            for (const auto& symbol : target.symbols()) {
                if (symbol.is_function() && symbol.value() && is_tls_initializer_for(symbol, object->name(), display)) {
                    initializer = symbol.value();
                    break;
                }
            }

            if (!initializer) {
                throw std::runtime_error("TLS lifecycle replacement needs a target TLS initialization helper");
            }
        }

        const uint64_t priority = metadata(patch, (tls ? "fix_tls_priority_" : "fix_priority_") + suffix, false);

        return {source.name(), value, size, tls, initializer, priority};
    }

    RuntimeVariablePatch variable_patch(const LIEF::ELF::Binary& patch, const LIEF::ELF::Binary& target, const LIEF::ELF::Symbol& source, uint64_t address, const std::string& patch_path, const std::string& target_path) const {
        if (source.visibility() != LIEF::ELF::Symbol::VISIBILITY::DEFAULT || (source.binding() != LIEF::ELF::Symbol::BINDING::GLOBAL && source.binding() != LIEF::ELF::Symbol::BINDING::WEAK)) {
            throw std::runtime_error("Runtime fix_ variables require preemptible extern C definitions");
        }

        if (!source.size() || source.size() > (1u << 20) || source.size() > UINT64_MAX - address) {
            throw std::runtime_error("Invalid or oversized runtime variable fix_");
        }

        const bool is_tls = source.type() == LIEF::ELF::Symbol::TYPE::TLS;
        const LIEF::ELF::Symbol* destination = is_tls ? &target_tls_symbol(target, address) : nullptr;

        if (is_tls && destination->size() != source.size()) {
            throw std::runtime_error("Runtime TLS fix_ must match the complete target size");
        }

        if (!is_tls)
            for (const auto& symbol : target.symbols()) {
                if (symbol.type() != LIEF::ELF::Symbol::TYPE::OBJECT || symbol.value() != address || !symbol.size())
                    continue;

                if (symbol.size() != source.size()) {
                    throw std::runtime_error("Runtime variable fix_ must match the complete target size");
                }

                destination = &symbol;
                break;
            }

        if (!destination) {
            throw std::runtime_error("Runtime variable fix_ needs a bounded target object symbol");
        }

        const auto* section = is_tls ? &tls_symbol_section(target, *destination) : target.section_from_virtual_address(address, false);

        if (!section || !section->has(LIEF::ELF::Section::FLAGS::ALLOC) || !section->has(LIEF::ELF::Section::FLAGS::WRITE) || section->has(LIEF::ELF::Section::FLAGS::EXECINSTR) || (!is_tls && section->has(LIEF::ELF::Section::FLAGS::TLS))) {
            throw std::runtime_error("Runtime variable fix_ requires writable ordinary target storage");
        }

        bool writable = is_tls;

        if (!is_tls)
            for (const auto& segment : target.segments()) {
                if (segment.type() == LIEF::ELF::Segment::TYPE::GNU_RELRO && address < segment.virtual_address() + segment.virtual_size() && segment.virtual_address() < address + source.size()) {
                    throw std::runtime_error("Runtime variable fix_ cannot modify RELRO storage");
                }

                if (segment.is_load() && address >= segment.virtual_address() && address - segment.virtual_address() <= segment.virtual_size() && source.size() <= segment.virtual_size() - (address - segment.virtual_address()) && (uint32_t(segment.flags()) & uint32_t(LIEF::ELF::Segment::FLAGS::W)))
                    writable = true;
            }

        if (!writable) {
            throw std::runtime_error("Runtime variable fix_ exceeds writable target memory");
        }

        if (is_tls) {
            std::string display = destination->demangled_name();

            if (display.empty())
                display = destination->name();

            for (const auto& symbol : target.symbols()) {
                if (symbol.is_function() && symbol.value() && is_tls_initializer_for(symbol, destination->name(), display)) {
                    throw std::runtime_error("Dynamically initialized target TLS needs a fix_tls_ lifecycle hook");
                }
            }

            for (const auto& symbol : patch.symbols()) {
                if (symbol.is_function() && symbol.value() && is_tls_initializer_for(symbol, source.name(), source.name())) {
                    throw std::runtime_error("Dynamic TLS fix_ initialization needs a fix_tls_ lifecycle hook");
                }
            }
        }

        RuntimeDataResolver source_types(patch_path), target_types(target_path);
        const auto source_layout = source_types.resolve(source.name());
        const auto target_layout = target_types.resolve(destination->name());

        if (source_layout.size != source.size() || target_layout.size != destination->size() || source_layout.shape != target_layout.shape) {
            throw std::runtime_error("Runtime variable fix_ data layout does not match target");
        }

        for (const auto& previous : variables_) {
            if (is_tls == previous.tls && address < previous.target_address + previous.initializer.size() && previous.target_address < address + source.size()) {
                throw std::runtime_error("Overlapping runtime variable fixes are unsupported");
            }
        }

        const auto* source_tls = is_tls ? patch.get(LIEF::ELF::Segment::TYPE::TLS) : nullptr;

        if (is_tls && !source_tls) {
            throw std::runtime_error("Missing patch TLS template");
        }

        if (is_tls && (source.value() > source_tls->virtual_size() || source.size() > source_tls->virtual_size() - source.value())) {
            throw std::runtime_error("TLS initializer exceeds patch template");
        }

        const uint64_t source_address = is_tls ? source_tls->virtual_address() + source.value() : source.value();

        for (const auto& relocation : patch.relocations()) {
            if (relocation.address() >= source_address && relocation.address() - source_address < source.size()) {
                throw std::runtime_error("Runtime variable fix_ initializer contains a relocation");
            }
        }

        const auto* source_section = is_tls ? &tls_symbol_section(patch, source) : patch.section_from_virtual_address(source_address, false);

        if (!source_section) {
            throw std::runtime_error("Runtime variable fix_ has no initialization image");
        }

        std::vector<uint8_t> bytes(source.size(), 0);

        if (source_section->type() != LIEF::ELF::Section::TYPE::NOBITS) {
            auto content = patch.get_content_from_virtual_address(source_address, source.size());

            if (content.size() != source.size()) {
                throw std::runtime_error("Runtime variable initializer is truncated");
            }

            bytes.assign(content.begin(), content.end());
        }

        return {source.name(), address, std::move(bytes), is_tls};
    }

    void write_bootstrap() const {
        std::ofstream out(bootstrap_source(), std::ios::binary | std::ios::trunc);

        if (!out) {
            throw std::runtime_error("Failed to create C++ bootstrap source");
        }

        out << R"CPP(#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

)CPP";

        for (size_t i = 0; i < names_.size(); ++i) {
            out << "void *add_patch_slot_" << i << " = (void *)1;\n";
            out << "__attribute__((naked, used)) void " << names_[i]
                << "(void) { __asm__ volatile(\"mov add_patch_slot_" << i
                << "(%rip), %r11\\n\\t"
                << "jmp *%r11\"); }\n";
        }

        for (size_t i = 0; i < variables_.size(); ++i) {
            const auto& variable = variables_[i];

            if (variable.tls)
                continue;

            out << "unsigned char ref_0x" << std::hex << variable.target_address << std::dec
                << "_runtime_data_" << i << "[" << variable.initializer.size() << "];\n";
            out << "const unsigned char add_patch_bytes_" << i << "[] = {";

            for (uint8_t byte : variable.initializer) {
                out << unsigned(byte) << ',';
            }

            out << "};\n";
        }

        const bool after_init = std::any_of(hooks_.begin(), hooks_.end(), [](const auto& hook) { return !hook.tls; });

        if (after_init) {
            out << "void *add_patch_handle = (void*)1;\n";

            for (size_t i = 0; i < hooks_.size(); ++i) {
                if (hooks_[i].tls)
                    continue;

                out << "unsigned char ref_" << decimal_to_hex(hooks_[i].value)
                    << "_runtime_object_" << i << "[" << hooks_[i].size << "];\n";
            }
        }

        // Keep the original DT_INIT as a ref marker
        // Existing relocation code maps its call through target-address translation for PIE and ET_EXEC
        out << "void ref_0x" << std::hex << original_init_
            << "_original_init(int argc, char **argv, char **envp) "
               "{ (void)argc; (void)argv; (void)envp; }\n"
            << std::dec;
        out << R"CPP(static __attribute__((always_inline)) inline void patch_fail(void) {
    static const char message[] = "1-patch: embedded C++ initialization failed\n";
    (void)write(2, message, sizeof(message) - 1);
    _exit(127);
}

__attribute__((used)) void add_patch_init(int argc, char **argv, char **envp) {
    int source = open("/proc/self/exe", O_RDONLY);
    if (source < 0) patch_fail();
    off_t end = lseek(source, 0, SEEK_END);
    unsigned char footer[16];
    if (end < 16 || pread(source, footer, 16, end - 16) != 16 ||
        memcmp(footer, "_1-PATCH_", 8) != 0) patch_fail();
    uint64_t length = 0;
    for (unsigned i = 0; i < 8; ++i) {
        length |= (uint64_t)footer[8 + i] << (8 * i);
    }
    if (length == 0 || length > (uint64_t)(end - 16)) patch_fail();
    int payload = (int)syscall(SYS_memfd_create, "1-patch-cpp", MFD_CLOEXEC);
    if (payload < 0) patch_fail();
    off_t cursor = end - 16 - (off_t)length;
    unsigned char buffer[8192];
    uint64_t remaining = length;
    while (remaining) {
        size_t chunk = remaining < sizeof(buffer) ? (size_t)remaining : sizeof(buffer);
        ssize_t count = pread(source, buffer, chunk, cursor);
        if (count <= 0) patch_fail();
        cursor += count;
        remaining -= (uint64_t)count;
        for (ssize_t used = 0; used < count;) {
            ssize_t written = write(payload, buffer + used, (size_t)(count - used));
            if (written <= 0) patch_fail();
            used += written;
        }
    }
    close(source);
    char path[64];
    if (snprintf(path, sizeof(path), "/proc/self/fd/%d", payload) >= (int)sizeof(path))
        patch_fail();
)CPP";

        for (size_t i = 0; i < variables_.size(); ++i) {
            if (variables_[i].tls)
                continue;

            out << "    memcpy(ref_0x" << std::hex << variables_[i].target_address << std::dec
                << "_runtime_data_" << i << ", add_patch_bytes_" << i << ", "
                << variables_[i].initializer.size() << ");\n";
        }

        out << R"CPP(    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        const char *reason = dlerror();
        if (reason) {
            size_t length = 0;
            while (reason[length]) ++length;
            (void)write(2, reason, length);
            (void)write(2, "\n", 1);
        }
        patch_fail();
    }
)CPP";
        if (after_init)
            out << "    add_patch_handle = handle;\n";

        for (size_t i = 0; i < names_.size(); ++i) {
            out << "    add_patch_slot_" << i << " = dlsym(handle, \""
                << names_[i] << "\");\n"
                << "    if (!add_patch_slot_" << i << ") patch_fail();\n";
        }

        out << "    close(payload);\n"
            << "    ref_0x" << std::hex << original_init_
            << "_original_init(argc, argv, envp);\n"
            << std::dec
            << "}\nint main(void) { return 0; }\n";
        if (after_init) {
            out << "void add_patch_after_init(int argc, char **argv, char **envp) {\n"
                   "    (void)argc; (void)argv; (void)envp;\n";

            for (size_t i = 0; i < hooks_.size(); ++i) {
                const auto& hook = hooks_[i];

                if (hook.tls)
                    continue;

                out << "    void (*hook_" << i << ")(void*) = (void(*)(void*))dlsym(add_patch_handle, \""
                    << hook.name << "\");\n"
                    << "    if (!hook_" << i << ") patch_fail();\n"
                    << "    hook_" << i << "(ref_" << decimal_to_hex(hook.value)
                    << "_runtime_object_" << i << ");\n";
            }

            out << "}\n";
        }

        if (!out) {
            throw std::runtime_error("Failed to write C++ bootstrap source");
        }
    }

    std::filesystem::path directory_;
    uint64_t original_init_ = 0;
    std::vector<std::string> names_;
    std::vector<RuntimeReference> references_;
    std::vector<RuntimeVariablePatch> variables_;
    std::vector<RuntimeLifecycleHook> hooks_;
    PatchCompilerOptions options_;
    std::set<uint64_t> tls_groups_;
};

#endif
