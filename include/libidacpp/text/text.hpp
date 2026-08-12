// Copyright (c) 2019-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * @file text.hpp
 * @brief Small text utilities (pure C++, no IDA SDK).
 *
 * @author Elias Bachaalany <elias.bachaalany@gmail.com>
 * @copyright 2019-2026
 *
 * @par Example:
 * @code
 * std::regex re(R"(\d+)");
 * auto out = libidacpp::text::regex_replace_cb(
 *     std::string("a1b22c"), re,
 *     [](const std::smatch& m) { return "[" + m.str(0) + "]"; });
 * // out == "a[1]b[22]c"
 * @endcode
 */
#pragma once

#include <algorithm>
#include <iterator>
#include <regex>
#include <string>

namespace libidacpp::text
{

//------------------------------------------------------------------------------
/**
 * @brief std::regex_replace with a callback replacement (Python's re.sub with a
 *        function): @p make_replacement receives each match and returns the text
 *        to substitute. Non-matching spans are copied verbatim.
 *
 * Based on https://stackoverflow.com/a/37516316
 */
template <class BidirIt, class Traits, class CharT, class UnaryFunction>
std::basic_string<CharT> regex_replace_cb(
        BidirIt first,
        BidirIt last,
        const std::basic_regex<CharT, Traits>& re,
        UnaryFunction make_replacement)
{
    std::basic_string<CharT> s;

    typename std::match_results<BidirIt>::difference_type position_of_last_match = 0;
    auto end_of_last_match = first;

    auto callback = [&](const std::match_results<BidirIt>& match)
    {
        auto position_of_this_match = match.position(0);
        auto diff = position_of_this_match - position_of_last_match;

        auto start_of_this_match = end_of_last_match;
        std::advance(start_of_this_match, diff);

        s.append(end_of_last_match, start_of_this_match);
        s.append(make_replacement(match));

        auto length_of_match = match.length(0);
        position_of_last_match = position_of_this_match + length_of_match;

        end_of_last_match = start_of_this_match;
        std::advance(end_of_last_match, length_of_match);
    };

    std::regex_iterator<BidirIt> begin(first, last, re), end;
    std::for_each(begin, end, callback);

    s.append(end_of_last_match, last);
    return s;
}

/// Convenience overload operating on a whole string.
template <class Traits, class CharT, class UnaryFunction>
std::basic_string<CharT> regex_replace_cb(
        const std::basic_string<CharT>& s,
        const std::basic_regex<CharT, Traits>& re,
        UnaryFunction make_replacement)
{
    return regex_replace_cb(s.cbegin(), s.cend(), re, make_replacement);
}

}  // namespace libidacpp::text
