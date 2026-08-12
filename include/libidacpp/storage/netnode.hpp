// Copyright (c) 2019-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * @file netnode.hpp
 * @brief Netnode persistence utilities for IDA plugins.
 *
 * This module provides easy-to-use wrappers for persisting data in IDA's
 * netnode database. Features include:
 * - EA set storage with ASLR-relative addressing
 * - Generic vector save/load for trivially copyable types
 * - Automatic serialization to netnode blobs
 *
 * @author Elias Bachaalany <elias.bachaalany@gmail.com>
 * @copyright 2019-2026
 *
 * @par Example:
 * @code
 * // Persist a set of marked addresses
 * ea_set_t marked("$ my-plugin-data");
 * marked.add(some_ea);
 * marked.save();
 *
 * // Later, in another session:
 * marked.load();
 * if (marked.contains(some_ea)) { ... }
 * @endcode
 */
#pragma once

#include <set>
#include <type_traits>

#include <pro.h>
#include <nalt.hpp>
#include <netnode.hpp>
#include <segment.hpp>

namespace libidacpp::storage::netnode
{

/// Set of effective addresses
using easet_t = std::set<ea_t>;

//--------------------------------------------------------------------------
/**
 * @brief EA set persisted to netnode blob.
 *
 * Stores a set of effective addresses in IDA's netnode database.
 * Supports relative addressing for ASLR compatibility.
 */
class ea_set_t
{
    qstring nodename_;
    bool use_relative_;
    easet_t cached_;

public:
    /**
     * @brief Construct EA set storage.
     * @param name Netnode name (should start with "$ " for plugin data)
     * @param relative Use relative addresses for ASLR support
     */
    ea_set_t(const char* name, bool relative = true)
        : nodename_(name), use_relative_(relative)
    {
    }

    /**
     * @brief Load EA set from netnode.
     * @return true if netnode existed, false if newly created
     */
    bool load()
    {
        cached_.clear();
        ::netnode node;
        if (node.create(nodename_.c_str()))
            return false;  // create succeeded = didn't exist

        ea_t image_base = get_image_base();

        size_t n;
        void* blob = node.getblob(nullptr, &n, 0, 'I');
        if (blob != nullptr)
        {
            auto pea = (ea_t*)blob;
            for (size_t i = 0, count = n / sizeof(ea_t); i < count; ++i, ++pea)
                cached_.insert(*pea + image_base);
            qfree(blob);
        }
        return true;
    }

    /**
     * @brief Save EA set to netnode.
     */
    void save()
    {
        ::netnode node;
        node.create(nodename_.c_str());

        ea_t image_base = get_image_base();

        eavec_t copy;
        copy.resize(cached_.size());
        size_t idx = 0;
        for (auto ea : cached_)
            copy[idx++] = ea - image_base;

        node.setblob(copy.begin(), copy.size() * sizeof(ea_t), 0, 'I');
    }

    /**
     * @brief Add EA to set.
     * @param ea Address to add
     * @param flush Save immediately if true
     */
    void add(ea_t ea, bool flush = true)
    {
        cached_.insert(ea);
        if (flush)
            save();
    }

    /**
     * @brief Remove EA from set.
     * @param ea Address to remove
     * @param flush Save immediately if true
     */
    void remove(ea_t ea, bool flush = true)
    {
        cached_.erase(ea);
        if (flush)
            save();
    }

    /**
     * @brief Clear cached set (does not affect netnode).
     */
    void clear()
    {
        cached_.clear();
    }

    /**
     * @brief Reset storage - clear cache and delete netnode.
     */
    void reset()
    {
        ::netnode node;
        node.create(nodename_.c_str());
        node.delblob(0, 'I');
        node.kill();
        cached_.clear();
    }

    bool contains(ea_t ea) const { return cached_.find(ea) != cached_.end(); }
    bool empty() const { return cached_.empty(); }
    size_t size() const { return cached_.size(); }

    const easet_t& get() const { return cached_; }
    easet_t& get() { return cached_; }

    // Iteration support
    auto begin() const { return cached_.begin(); }
    auto end() const { return cached_.end(); }

private:
    ea_t get_image_base() const
    {
        if (!use_relative_)
            return 0;
        ea_t base = get_imagebase();
        return (base == BADADDR) ? 0 : base;
    }
};

//--------------------------------------------------------------------------
/**
 * @brief Load vector from netnode blob.
 * @tparam T Element type (must be trivially copyable)
 * @param name Netnode name
 * @param out Output vector
 * @param tag Blob tag (default 'D')
 * @return true if loaded, false if netnode didn't exist
 */
template<typename T>
bool load_vec(const char* name, qvector<T>& out, char tag = 'D')
{
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");

    out.clear();
    ::netnode node;
    if (node.create(name))
        return false;

    size_t n;
    void* blob = node.getblob(nullptr, &n, 0, tag);
    if (blob != nullptr)
    {
        size_t count = n / sizeof(T);
        out.resize(count);
        memcpy(out.begin(), blob, count * sizeof(T));
        qfree(blob);
    }
    return true;
}

/**
 * @brief Save vector to netnode blob.
 * @tparam T Element type (must be trivially copyable)
 * @param name Netnode name
 * @param data Data to save
 * @param tag Blob tag (default 'D')
 */
template<typename T>
void save_vec(const char* name, const qvector<T>& data, char tag = 'D')
{
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");

    ::netnode node;
    node.create(name);
    node.setblob(data.begin(), data.size() * sizeof(T), 0, tag);
}

/**
 * @brief Delete a single netnode blob (one tag).
 *
 * Removes only the blob stored under @p tag. Other tags, altvals, supvals, and
 * the node itself are left intact. Use delete_node() to destroy an entire node.
 *
 * @param name Netnode name
 * @param tag Blob tag (default 'D')
 */
inline void delete_blob(const char* name, char tag = 'D')
{
    ::netnode node(name);       // do_create=false: never materialize a missing node
    if (exist(node))
        node.delblob(0, tag);   // remove only this tag's blob
}

/**
 * @brief Delete an entire netnode (all tags and values).
 *
 * No-op if the node does not exist (does not create it).
 * @param name Netnode name
 */
inline void delete_node(const char* name)
{
    ::netnode node(name);       // do_create=false
    if (exist(node))
        node.kill();
}

}  // namespace libidacpp::storage::netnode
