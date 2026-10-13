#include <cstdint>
#include <set>
#include <string>
#include <vector>
#include <utility>
#include <stdexcept>
#include <fcntl.h>
#include <unistd.h>
#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>

#ifndef RUNTIME_DWARF_HPP
#define RUNTIME_DWARF_HPP

struct RuntimeDataLayout {
    uint64_t size;
    std::string shape;
};

class RuntimeDataResolver {
public:
    explicit RuntimeDataResolver(const std::string& path) {
        fd_ = open(path.c_str(), O_RDONLY);
        if (fd_ < 0 || dwarf_init(fd_, DW_DLC_READ, nullptr, nullptr, &debug_, &error_) != DW_DLV_OK) {
            if (fd_ >= 0)
                close(fd_);

            throw std::runtime_error("Runtime variable fixes require DWARF type information");
        }
    }

    RuntimeDataResolver(const RuntimeDataResolver&) = delete;

    ~RuntimeDataResolver() {
        if (debug_)
            dwarf_finish(debug_, &error_);

        if (fd_ >= 0)
            close(fd_);
    }

    RuntimeDataLayout resolve(const std::string& name) {
        if (used_) {
            dwarf_finish(debug_, &error_);
            debug_ = nullptr;
            if (dwarf_init(fd_, DW_DLC_READ, nullptr, nullptr, &debug_, &error_) != DW_DLV_OK) {
                throw std::runtime_error("Failed to restart runtime DWARF lookup");
            }
        }

        used_ = true;

        Dwarf_Unsigned length, abbrev, next;
        Dwarf_Half version, address_size;

        while (dwarf_next_cu_header(debug_, &length, &version, &abbrev, &address_size, &next, &error_) == DW_DLV_OK) {
            Dwarf_Die root = nullptr;

            if (dwarf_siblingof(debug_, nullptr, &root, &error_) != DW_DLV_OK)
                continue;

            Dwarf_Die variable = find(root, name, 0);

            if (variable) {
                std::set<Dwarf_Off> active;

                return layout(type(variable), active, 0);
            }
        }

        throw std::runtime_error("Missing runtime variable type: " + name);
    }

private:
    int fd_ = -1;
    Dwarf_Debug debug_ = nullptr;
    Dwarf_Error error_ = nullptr;
    bool used_ = false;

    bool has(Dwarf_Die die, Dwarf_Half key) {
        Dwarf_Bool exists = 0;

        return dwarf_hasattr(die, key, &exists, &error_) == DW_DLV_OK && exists;
    }

    uint64_t number(Dwarf_Die die, Dwarf_Half key) {
        Dwarf_Attribute attribute = nullptr;
        Dwarf_Unsigned value = 0;

        if (dwarf_attr(die, key, &attribute, &error_) != DW_DLV_OK) {
            throw std::runtime_error("Incomplete runtime data layout");
        }

        const int status = dwarf_formudata(attribute, &value, &error_);

        dwarf_dealloc(debug_, attribute, DW_DLA_ATTR);
        if (status != DW_DLV_OK) {
            throw std::runtime_error("Runtime data layout is not constant");
        }

        return value;
    }

    std::string text(Dwarf_Die die, Dwarf_Half key) {
        Dwarf_Attribute attribute = nullptr;
        char* value = nullptr;

        if (dwarf_attr(die, key, &attribute, &error_) != DW_DLV_OK)
            return {};

        std::string result;

        if (dwarf_formstring(attribute, &value, &error_) == DW_DLV_OK && value)
            result = value;

        dwarf_dealloc(debug_, attribute, DW_DLA_ATTR);

        return result;
    }

    Dwarf_Die referenced(Dwarf_Die die, Dwarf_Half key) {
        Dwarf_Attribute attribute = nullptr;
        Dwarf_Off offset;
        Dwarf_Die result = nullptr;

        if (dwarf_attr(die, key, &attribute, &error_) != DW_DLV_OK)
            return nullptr;

        const int status = dwarf_global_formref(attribute, &offset, &error_);

        dwarf_dealloc(debug_, attribute, DW_DLA_ATTR);
        if (status == DW_DLV_OK)
            dwarf_offdie(debug_, offset, &result, &error_);

        return result;
    }

    Dwarf_Die type(Dwarf_Die die) {
        for (unsigned i = 0; die && i < 16; ++i) {
            if (auto result = referenced(die, DW_AT_type))
                return result;

            die = referenced(die, DW_AT_specification);
        }

        throw std::runtime_error("Missing runtime variable type reference");
    }

    Dwarf_Die find(Dwarf_Die first, const std::string& name, unsigned depth) {
        if (depth > 128) {
            throw std::runtime_error("Runtime DWARF tree is too deep");
        }

        for (Dwarf_Die die = first; die;) {
            Dwarf_Half tag = 0;

            dwarf_tag(die, &tag, &error_);
            if (tag == DW_TAG_variable && (text(die, DW_AT_name) == name || text(die, DW_AT_linkage_name) == name || text(die, DW_AT_MIPS_linkage_name) == name))
                return die;

            Dwarf_Die child = nullptr;

            if (dwarf_child(die, &child, &error_) == DW_DLV_OK) {
                if (auto result = find(child, name, depth + 1))
                    return result;
            }

            Dwarf_Die sibling = nullptr;

            if (dwarf_siblingof(debug_, die, &sibling, &error_) != DW_DLV_OK)
                break;

            die = sibling;
        }

        return nullptr;
    }

    RuntimeDataLayout layout(Dwarf_Die die, std::set<Dwarf_Off>& active, unsigned depth) {
        Dwarf_Half tag = 0;
        Dwarf_Off offset;

        if (!die || depth > 32 || dwarf_tag(die, &tag, &error_) != DW_DLV_OK || dwarf_dieoffset(die, &offset, &error_) != DW_DLV_OK || !active.insert(offset).second) {
            throw std::runtime_error("Unsupported recursive runtime data layout");
        }

        struct Guard {
            std::set<Dwarf_Off>& active;
            Dwarf_Off offset;

            ~Guard() {
                active.erase(offset);
            }
        } guard{active, offset};

        if (tag == DW_TAG_typedef || tag == DW_TAG_volatile_type || tag == DW_TAG_restrict_type)
            return layout(type(die), active, depth + 1);

        if (tag == DW_TAG_base_type) {
            const auto size = number(die, DW_AT_byte_size);
            const auto encoding = number(die, DW_AT_encoding);

            if (!size || (encoding != DW_ATE_boolean && encoding != DW_ATE_signed && encoding != DW_ATE_unsigned && encoding != DW_ATE_signed_char && encoding != DW_ATE_unsigned_char && encoding != DW_ATE_float)) {
                throw std::runtime_error("Unsupported runtime scalar type");
            }

            return {size, "scalar:" + std::to_string(encoding) + ":" + std::to_string(size)};
        }

        if (tag == DW_TAG_enumeration_type) {
            auto underlying = layout(type(die), active, depth + 1);

            return {underlying.size, "enum:" + underlying.shape};
        }

        if (tag == DW_TAG_array_type) {
            auto element = layout(type(die), active, depth + 1);
            uint64_t count = 1;
            std::string dimensions;
            Dwarf_Die child = nullptr;

            if (dwarf_child(die, &child, &error_) != DW_DLV_OK) {
                throw std::runtime_error("Runtime array has no fixed extent");
            }

            for (; child;) {
                Dwarf_Half child_tag = 0;

                dwarf_tag(child, &child_tag, &error_);
                if (child_tag == DW_TAG_subrange_type) {
                    if (has(child, DW_AT_lower_bound) && number(child, DW_AT_lower_bound) != 0) {
                        throw std::runtime_error("Unsupported runtime array lower bound");
                    }

                    uint64_t extent;

                    if (has(child, DW_AT_count))
                        extent = number(child, DW_AT_count);
                    else {
                        const auto upper = number(child, DW_AT_upper_bound);

                        if (upper == UINT64_MAX) {
                            throw std::runtime_error("Runtime array extent overflows");
                        }

                        extent = upper + 1;
                    }

                    if (!extent || count > UINT64_MAX / extent) {
                        throw std::runtime_error("Runtime array extent overflows");
                    }

                    count *= extent;
                    dimensions += ":" + std::to_string(extent);
                }

                Dwarf_Die sibling = nullptr;

                if (dwarf_siblingof(debug_, child, &sibling, &error_) != DW_DLV_OK)
                    break;

                child = sibling;
            }

            if (dimensions.empty() || element.size > UINT64_MAX / count) {
                throw std::runtime_error("Runtime array size overflows");
            }

            return {element.size * count, "array" + dimensions + "(" + element.shape + ")"};
        }

        if (tag == DW_TAG_structure_type || tag == DW_TAG_class_type) {
            const auto size = number(die, DW_AT_byte_size);

            if (!size) {
                throw std::runtime_error("Empty runtime data layout");
            }

            std::string shape = "record:" + std::to_string(size);
            std::vector<std::pair<uint64_t, uint64_t>> occupied;
            Dwarf_Die child = nullptr;

            if (dwarf_child(die, &child, &error_) == DW_DLV_OK) {
                for (; child;) {
                    Dwarf_Half child_tag = 0;

                    dwarf_tag(child, &child_tag, &error_);
                    if (child_tag == DW_TAG_subprogram || child_tag == DW_TAG_inheritance || child_tag == DW_TAG_variant_part) {
                        throw std::runtime_error("Runtime variable replacement requires a data-only type");
                    }

                    if (child_tag == DW_TAG_member) {
                        if (has(child, DW_AT_bit_size) || has(child, DW_AT_data_bit_offset)) {
                            throw std::runtime_error("Runtime bit-field replacement is unsupported");
                        }

                        const auto position = number(child, DW_AT_data_member_location);
                        auto member = layout(type(child), active, depth + 1);

                        if (position > size || member.size > size - position) {
                            throw std::runtime_error("Runtime member exceeds record size");
                        }

                        for (const auto& range : occupied) {
                            if (position < range.second && range.first < position + member.size) {
                                throw std::runtime_error("Overlapping runtime members are unsupported");
                            }
                        }

                        occupied.emplace_back(position, position + member.size);
                        shape += ";" + std::to_string(position) + "=" + member.shape;
                    }

                    Dwarf_Die sibling = nullptr;

                    if (dwarf_siblingof(debug_, child, &sibling, &error_) != DW_DLV_OK)
                        break;

                    child = sibling;
                }
            }

            return {size, shape};
        }

        throw std::runtime_error("Unsupported runtime variable type or lifetime");
    }
};

#endif
