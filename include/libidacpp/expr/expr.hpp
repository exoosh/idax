// Copyright (c) 2019-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * @file expr.hpp
 * @brief Expression evaluation and external language utilities.
 *
 * This module provides helpers for working with IDA's expression evaluation
 * and external language integration (IDAPython, IDC, etc.).
 *
 * @author Elias Bachaalany <elias.bachaalany@gmail.com>
 * @copyright 2019-2026
 *
 * @par Example - Find Python:
 * @code
 * if (auto* py = libidacpp::expr::pylang())
 * {
 *     idc_value_t result;
 *     py->eval_snippet("print('Hello')", &result, nullptr, 0);
 * }
 * @endcode
 *
 * @par Example - Find any language:
 * @code
 * if (auto* idc = libidacpp::expr::find_extlang("idc"))
 * {
 *     // IDC is available
 * }
 * @endcode
 *
 * @par Example - Collect all languages:
 * @code
 * auto langs = libidacpp::expr::collect_extlangs();
 * for (auto* lang : langs)
 *     msg("Language: %s (.%s)\n", lang->name, lang->fileext);
 * @endcode
 */
#pragma once

#include <optional>
#include <string>
#include <vector>
#include <expr.hpp>

namespace libidacpp::expr
{

//-------------------------------------------------------------------------
/**
 * @brief Find an external language by file extension.
 *
 * @param ext File extension to search for (e.g., "py", "idc")
 * @return Pointer to extlang_t, or nullptr if not found
 *
 * @note Results are not cached - each call searches again.
 *       For repeated access to the same language, cache the result yourself.
 */
inline extlang_t* find_extlang(const char* ext)
{
    struct finder_t : extlang_visitor_t
    {
        const char* target;
        extlang_t* found = nullptr;

        ssize_t idaapi visit_extlang(extlang_t* extlang) override
        {
            if (streq(extlang->fileext, target))
            {
                found = extlang;
                return 1;  // Stop iteration
            }
            return 0;
        }

        finder_t(const char* ext) : target(ext)
        {
            for_all_extlangs(*this, false);
        }
    };

    return finder_t(ext).found;
}

//-------------------------------------------------------------------------
/**
 * @brief Collect all registered external languages.
 *
 * @param selected_only If true, only return selected/active languages
 * @return Vector of extlang_t pointers
 */
inline std::vector<extlang_t*> collect_extlangs(bool selected_only = false)
{
    struct collector_t : extlang_visitor_t
    {
        std::vector<extlang_t*> langs;

        ssize_t idaapi visit_extlang(extlang_t* extlang) override
        {
            langs.push_back(extlang);
            return 0;  // Continue iteration
        }

        collector_t(bool selected)
        {
            for_all_extlangs(*this, selected);
        }
    };

    return collector_t(selected_only).langs;
}

//-------------------------------------------------------------------------
/**
 * @brief Get the Python external language (cached).
 *
 * Convenience wrapper that caches the Python extlang for repeated access.
 *
 * @param force If true, force re-search even if cached
 * @return Pointer to Python extlang_t, or nullptr if not found
 */
inline extlang_t* pylang(bool force = false)
{
    static extlang_t* cached = nullptr;
    if (force || cached == nullptr)
        cached = find_extlang("py");
    return cached;
}

//-------------------------------------------------------------------------
/**
 * @brief Get the IDC external language (cached).
 *
 * Convenience wrapper that caches the IDC extlang for repeated access.
 *
 * @param force If true, force re-search even if cached
 * @return Pointer to IDC extlang_t, or nullptr if not found
 */
inline extlang_t* idclang(bool force = false)
{
    static extlang_t* cached = nullptr;
    if (force || cached == nullptr)
        cached = find_extlang("idc");
    return cached;
}

//-------------------------------------------------------------------------
/**
 * @brief Evaluate an expression through an extlang and return it as a string.
 *
 * @param el          language to evaluate with (nullptr -> nullopt)
 * @param expr        expression source
 * @param current_ea  address used to resolve names (BADADDR if not applicable)
 * @param errbuf      optional error message buffer
 * @return the result as a std::string, or nullopt if el is null, evaluation
 *         fails, or the result is not a string value
 */
inline std::optional<std::string> eval_expr_string(
        extlang_t* el,
        const char* expr,
        ea_t current_ea = BADADDR,
        qstring* errbuf = nullptr)
{
    if (el == nullptr || el->eval_expr == nullptr)
        return std::nullopt;

    idc_value_t rv;
    qstring local_err;
    if (!el->eval_expr(&rv, current_ea, expr, errbuf != nullptr ? errbuf : &local_err))
        return std::nullopt;
    if (rv.vtype != VT_STR)
        return std::nullopt;
    return std::string(rv.qstr().c_str());
}

//-------------------------------------------------------------------------
/**
 * @brief Convenience: evaluate a Python expression to a string.
 *
 * Uses the cached Python extlang (pylang()); see eval_expr_string().
 */
inline std::optional<std::string> eval_python_string(
        const char* expr,
        ea_t current_ea = BADADDR,
        qstring* errbuf = nullptr)
{
    return eval_expr_string(pylang(), expr, current_ea, errbuf);
}

}  // namespace libidacpp::expr
