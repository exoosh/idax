// Copyright (c) 2019-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * @file inplace_hook.hpp
 * @brief Hook a bare C function pointer in place, with save/restore.
 *
 * Generalises the pattern of wrapping a function-pointer member of an IDA SDK
 * struct (e.g. extlang_t::eval_snippet) so it runs custom logic and then the
 * original: save the original pointer, install a std::function bridged to a C
 * function pointer via callback_registry, and restore on unhook. Slots are
 * reused, so repeated hook/unhook cannot exhaust the underlying registry.
 *
 * The pointed-to storage (the field being patched) must outlive the hook, and
 * its owning module must be writable (true for registered IDA structs).
 *
 * @author Elias Bachaalany <elias.bachaalany@gmail.com>
 * @copyright 2019-2026
 *
 * @par Example:
 * @code
 * // One pool per (signature, purpose). Give each a unique tag.
 * using snippet_hook_t =
 *     libidacpp::callbacks::inplace_hook<bool(const char*, qstring*), 16, struct snippet_tag>;
 * static snippet_hook_t g_hook;
 *
 * // el->eval_snippet is bool (idaapi*)(const char*, qstring*)
 * g_hook.hook(&el->eval_snippet, [](auto original) {
 *     return [original](const char* s, qstring* eb) {
 *         return original(rewrite(s).c_str(), eb);   // pre-process, then call original
 *     };
 * });
 * g_hook.unhook(&el->eval_snippet);   // restores the original pointer
 * @endcode
 */
#pragma once

#include <array>
#include <functional>
#include <type_traits>

#include <libidacpp/callbacks/callbacks.hpp>

namespace libidacpp::callbacks
{

//------------------------------------------------------------------------------
/**
 * @brief In-place function-pointer hook pool. Primary template; use the
 *        R(Args...) specialization below.
 *
 * @tparam Signature Function type being hooked, e.g. bool(const char*, qstring*).
 * @tparam MaxHooks  Maximum number of concurrently hooked locations.
 * @tparam Tag       Type tag selecting an independent trampoline registry. Give
 *                   each distinct hook pool its own tag.
 */
template <typename Signature, size_t MaxHooks = 16, typename Tag = void>
class inplace_hook;

template <typename R, typename... Args, size_t MaxHooks, typename Tag>
class inplace_hook<R(Args...), MaxHooks, Tag>
{
public:
    // Pointer to the hooked function type. For Signature bool(const char*, qstring*)
    // this deduces to bool(*)(const char*, qstring*); it always follows Signature.
    using fnptr_t   = std::add_pointer_t<R(Args...)>;
    using lambda_t  = std::function<R(Args...)>;
    // Given the captured original, produce the replacement callable.
    using factory_t = std::function<lambda_t(fnptr_t original)>;

    /**
     * @brief Hook the function pointer at @p location.
     *
     * Saves *location, builds the replacement via @p make(original) and installs a
     * trampoline. Idempotent per location; if the field was re-pointed elsewhere
     * since we last hooked it (e.g. a struct reload at the same address), the
     * original is re-captured and re-installed. Never adopts one of our own
     * trampolines as the "original".
     *
     * @return true if @p location is hooked afterwards; false if @p location or
     *         *location is null, or no free slot / registry capacity remains.
     */
    bool hook(fnptr_t* location, factory_t make)
    {
        if (location == nullptr || *location == nullptr)
            return false;

        if (slot_t* s = find(location); s != nullptr)
        {
            if (*location == s->tramp)
                return true;                       // still hooked
            if (is_our_trampoline(*location))
                return true;                       // don't capture our own trampoline
            s->orig   = *location;                 // stale: re-capture + re-install
            s->active = make(s->orig);
            *location = s->tramp;
            return true;
        }

        if (is_our_trampoline(*location))
            return false;                          // untracked but already ours: inconsistent

        slot_t* s = free_slot();
        if (s == nullptr)
            return false;

        if (s->tramp == nullptr)
        {
            const size_t i = size_t(s - slots_.data());
            auto result = registry_t::instance().register_callback(
                [this, i](Args... a) -> R
                {
                    slot_t& sl = slots_[i];
                    if (sl.location != nullptr && sl.active)
                        return sl.active(a...);
                    if constexpr (!std::is_void_v<R>)
                        return R{};                // detached slot: harmless default
                });
            if (!result)
                return false;                      // registry full
            s->tramp = result->second;
        }

        s->location = location;
        s->orig     = *location;
        s->active   = make(s->orig);
        *location   = s->tramp;
        return true;
    }

    /// Restore *location to the saved original (if still ours) and free the slot.
    bool unhook(fnptr_t* location)
    {
        slot_t* s = find(location);
        if (s == nullptr)
            return false;
        if (*s->location == s->tramp)
            *s->location = s->orig;
        clear(*s);
        return true;
    }

    bool is_hooked(const fnptr_t* location) const { return find(location) != nullptr; }

    /// Restore every hooked location. Dereferences each location; use only while
    /// the hooked structs are known to be alive.
    void unhook_all()
    {
        for (slot_t& s : slots_)
        {
            if (s.location == nullptr)
                continue;
            if (*s.location == s.tramp)
                *s.location = s.orig;
            clear(s);
        }
    }

    /// Free every slot WITHOUT touching the hooked locations. Safe at teardown
    /// when an owning module may already be gone and the trampoline code is kept
    /// alive (e.g. a pinned plugin DLL) — a leftover trampoline call then hits a
    /// detached slot and returns a default.
    void detach_all()
    {
        for (slot_t& s : slots_)
            clear(s);
    }

private:
    struct slot_t
    {
        fnptr_t* location = nullptr;   // hooked field (nullptr => free)
        fnptr_t  orig     = nullptr;   // saved original
        lambda_t active;               // current replacement (calls orig)
        fnptr_t  tramp    = nullptr;   // this slot's trampoline (registered once)
    };

    using registry_t = callback_registry<fnptr_t, MaxHooks, Tag>;

    slot_t* find(const fnptr_t* location)
    {
        for (slot_t& s : slots_)
            if (s.location == location)
                return &s;
        return nullptr;
    }
    const slot_t* find(const fnptr_t* location) const
    {
        for (const slot_t& s : slots_)
            if (s.location == location)
                return &s;
        return nullptr;
    }
    slot_t* free_slot()
    {
        for (slot_t& s : slots_)
            if (s.location == nullptr)
                return &s;
        return nullptr;
    }
    bool is_our_trampoline(fnptr_t fp) const
    {
        if (fp == nullptr)
            return false;
        for (const slot_t& s : slots_)
            if (s.tramp == fp)
                return true;
        return false;
    }
    static void clear(slot_t& s)
    {
        s.location = nullptr;
        s.orig     = nullptr;
        s.active   = nullptr;
        // s.tramp is intentionally kept for reuse.
    }

    std::array<slot_t, MaxHooks> slots_{};
};

}  // namespace libidacpp::callbacks
