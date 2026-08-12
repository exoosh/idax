// Copyright (c) 2019-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * @file registry.hpp
 * @brief Thin wrappers over IDA's registry (settings/list persistence).
 *
 * Convenience helpers over the reg_* API for the common cases of persisting
 * plugin settings and string lists in IDA's registry. Complements the netnode
 * storage (which is per-database); the registry is global to the user's IDA.
 *
 * @author Elias Bachaalany <elias.bachaalany@gmail.com>
 * @copyright 2019-2026
 *
 * @par Example:
 * @code
 * namespace reg = libidacpp::storage::registry;
 *
 * reg::set_string("last_dir", "C:/work", "my-plugin");
 * if (auto d = reg::get_string("last_dir", "my-plugin")) msg("%s\n", d->c_str());
 *
 * reg::strlist_t recent("my-plugin.recent", 20);
 * recent.add("file.bin");
 * for (const auto& s : recent.read()) msg("%s\n", s.c_str());
 * @endcode
 */
#pragma once

#include <optional>
#include <string>
#include <vector>

#include <pro.h>
#include <registry.hpp>

namespace libidacpp::storage::registry
{

//------------------------------------------------------------------------------
// Scalar values. `name` is the value name; `subkey` is the optional parent key.
//------------------------------------------------------------------------------

inline std::optional<std::string> get_string(const char* name, const char* subkey = nullptr)
{
    qstring out;
    if (!reg_read_string(&out, name, subkey))
        return std::nullopt;
    return std::string(out.c_str());
}

inline void set_string(const char* name, const char* value, const char* subkey = nullptr)
{
    reg_write_string(name, value, subkey);
}

inline int get_int(const char* name, int defval = 0, const char* subkey = nullptr)
{
    return reg_read_int(name, defval, subkey);
}

inline void set_int(const char* name, int value, const char* subkey = nullptr)
{
    reg_write_int(name, value, subkey);
}

inline bool get_bool(const char* name, bool defval = false, const char* subkey = nullptr)
{
    return reg_read_bool(name, defval, subkey);
}

inline void set_bool(const char* name, bool value, const char* subkey = nullptr)
{
    reg_write_bool(name, value, subkey);
}

inline void remove(const char* name, const char* subkey = nullptr)
{
    reg_delete(name, subkey);
}

//------------------------------------------------------------------------------
/**
 * @brief A string list persisted under a single registry key (IDA's strlist).
 *
 * Wraps reg_read_strlist / reg_update_strlist. Entries are de-duplicated and
 * capped at @c max_records by IDA (most-recent semantics), matching how IDA
 * stores histories.
 */
class strlist_t
{
public:
    explicit strlist_t(const char* key, size_t max_records = 1024)
        : m_key(key), m_max(max_records)
    {
    }

    std::vector<std::string> read() const
    {
        qstrvec_t v;
        reg_read_strlist(&v, m_key.c_str());
        std::vector<std::string> out;
        out.reserve(v.size());
        for (const qstring& s : v)
            out.push_back(s.c_str());
        return out;
    }

    void add(const std::string& value)
    {
        reg_update_strlist(m_key.c_str(), value.c_str(), m_max);
    }

    void remove(const std::string& value)
    {
        reg_update_strlist(m_key.c_str(), nullptr, m_max, value.c_str());
    }

private:
    std::string m_key;
    size_t      m_max;
};

}  // namespace libidacpp::storage::registry
