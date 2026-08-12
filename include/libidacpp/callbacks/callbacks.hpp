// Copyright (c) 2019-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * @file callbacks.hpp
 * @brief Callback utilities - Bridge C APIs with C++ lambdas.
 *
 * This module provides infrastructure for converting C++ lambdas to C function
 * pointers, enabling modern callback patterns with IDA's C-style APIs.
 *
 * Features:
 * - Thread-safe callback registry with handle-based lifecycle
 * - Compile-time wrapper generation for type safety
 * - RAII scoped_callback for automatic cleanup
 *
 * @author Elias Bachaalany <elias.bachaalany@gmail.com>
 * @copyright 2019-2026
 *
 * @par Example:
 * @code
 * // Register a callback that can be passed to C APIs
 * using my_registry = callback_registry<void(*)(int), 32>;
 * auto result = my_registry::instance().register_callback([](int x) {
 *     msg("Got: %d\n", x);
 * });
 * if (result) {
 *     auto [handle, c_func] = *result;
 *     some_c_api_set_callback(c_func);
 *     // Later: my_registry::instance().unregister_callback(handle);
 * }
 *
 * // Or use RAII scoped_callback for automatic cleanup
 * {
 *     scoped_callback<void(*)(int)> cb([](int x) { msg("x=%d\n", x); });
 *     if (cb) some_c_api_set_callback(*cb);
 * } // Automatically unregistered
 * @endcode
 */
#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <type_traits>
#include <utility>
#include <vector>

namespace libidacpp::callbacks
{

//------------------------------------------------------------------------------
/// Opaque handle for registered callbacks
using callback_handle_t = uint32_t;

/// Invalid callback handle constant
constexpr callback_handle_t INVALID_CALLBACK_HANDLE = 0;

//------------------------------------------------------------------------------
/**
 * @brief Thread-safe callback registry for bridging C APIs with C++ lambdas.
 *
 * Provides handle-based lifecycle management for callbacks. Uses compile-time
 * wrapper generation to convert C++ lambdas to C function pointers.
 *
 * @tparam CPrototype C function pointer type (e.g., void(*)(int))
 * @tparam MaxCallbacks Maximum number of callbacks (default: 256)
 * @tparam Tag Type tag for creating independent registries with same signature
 *
 * @note Thread-safe for concurrent register/unregister operations.
 *
 * @warning **Slot identity & lifetime.** A returned C function pointer identifies
 *          a fixed *slot*, not a specific registration. To avoid an ABA hazard
 *          (a stale pointer dispatching to a later registration), freed slots are
 *          **not reused**: each register_callback() consumes a new slot up to
 *          MaxCallbacks. unregister_all() clears live callbacks but does NOT
 *          reclaim slots; only reset_quiescent() reclaims them (and is unsafe
 *          unless no returned pointer is still live). High register/unregister
 *          churn therefore exhausts capacity — size MaxCallbacks accordingly.
 * @warning unregister_callback() does not wait for an in-flight invocation to
 *          finish; it only guarantees no *future* dispatch through that slot
 *          (the slot's stored lambda becomes null). The internal lock prevents a
 *          std::function data race, not callback quiescence.
 *
 * @example
 * @code
 * using my_registry = callback_registry<void(*)(int), 32>;
 * auto result = my_registry::instance().register_callback([](int x) {
 *     msg("Got: %d\n", x);
 * });
 * if (result) {
 *     auto [handle, c_func] = *result;
 *     // Pass c_func to C API
 *     // ...
 *     my_registry::instance().unregister_callback(handle);
 * }
 * @endcode
 */
template <typename CPrototype, size_t MaxCallbacks = 256, typename Tag = void>
class callback_registry
{
public:
    using callback_t = CPrototype;
    using lambda_t = std::function<std::remove_pointer_t<CPrototype>>;

    /**
     * @brief Get singleton instance of the registry.
     */
    static callback_registry& instance()
    {
        static callback_registry inst;
        return inst;
    }

private:
    callback_registry() = default;
    ~callback_registry() = default;

    callback_registry(const callback_registry&) = delete;
    callback_registry& operator=(const callback_registry&) = delete;

public:
    /**
     * @brief Register a callback lambda and get a C function pointer.
     *
     * @param cb Lambda/function to register
     * @return Optional pair of (handle, C function pointer), or nullopt if registry is full
     */
    std::optional<std::pair<callback_handle_t, callback_t>> register_callback(lambda_t cb)
    {
        std::unique_lock lock(mutex_);

        // Allocate a fresh slot via a high-water mark. Freed slots are NOT
        // reused (only reset_quiescent() reclaims them): a slot's C function pointer is its
        // only identity, so reusing slot i would let a stale pointer handed out
        // for a previous registration dispatch to the NEW callback (ABA).
        if (next_slot_ >= MaxCallbacks)
            return std::nullopt;  // capacity exhausted (see class docs on churn)

        size_t i = next_slot_++;
        callback_handle_t handle = next_handle_++;
        callbacks_[i] = std::move(cb);
        handles_[i] = handle;
        return std::make_pair(handle, get_wrapper_for_index(i));
    }

    /**
     * @brief Unregister a callback by handle.
     *
     * @param handle Handle returned from register_callback()
     * @return true if unregistered, false if handle not found
     */
    bool unregister_callback(callback_handle_t handle)
    {
        if (handle == INVALID_CALLBACK_HANDLE)
            return false;

        std::unique_lock lock(mutex_);

        for (size_t i = 0; i < MaxCallbacks; ++i)
        {
            if (handles_[i] == handle && callbacks_[i])
            {
                callbacks_[i] = nullptr;
                handles_[i] = INVALID_CALLBACK_HANDLE;
                return true;
            }
        }

        return false;
    }

    /**
     * @brief Unregister all callbacks so no wrapper dispatches any more.
     *
     * Tombstones every live callback. It does **not** reclaim slots: previously
     * handed-out C function pointers stay dead (an empty slot returns a
     * value-initialized result), and new registrations continue to consume fresh
     * slots. This is the ABA-safe way to clear the registry. To recover slot
     * capacity, use reset_quiescent() and read its precondition.
     */
    void unregister_all()
    {
        std::unique_lock lock(mutex_);

        for (size_t i = 0; i < MaxCallbacks; ++i)
        {
            callbacks_[i] = nullptr;
            handles_[i] = INVALID_CALLBACK_HANDLE;
        }
        // next_slot_ intentionally NOT reset: reusing a slot would let a stale
        // pointer dispatch to a future registration (ABA). See reset_quiescent().
    }

    /**
     * @brief Clear the registry AND reclaim all slots for reuse (UNSAFE).
     *
     * @warning Quiescence precondition: only call this when you can guarantee
     *          that **no** C function pointer previously returned by
     *          register_callback() is still reachable or callable anywhere.
     *          After this, slot indices — and therefore the same C function
     *          pointers — are handed out again; a surviving stale pointer would
     *          dispatch to a NEW callback (ABA). If you cannot guarantee
     *          quiescence, use unregister_all() instead.
     */
    void reset_quiescent()
    {
        std::unique_lock lock(mutex_);

        for (size_t i = 0; i < MaxCallbacks; ++i)
        {
            callbacks_[i] = nullptr;
            handles_[i] = INVALID_CALLBACK_HANDLE;
        }
        next_slot_ = 0;
    }

    /**
     * @brief Get number of registered callbacks.
     */
    size_t size() const
    {
        std::shared_lock lock(mutex_);
        size_t count = 0;
        for (const auto& cb : callbacks_)
            if (cb)
                ++count;
        return count;
    }

    /**
     * @brief Get maximum capacity of the registry.
     */
    size_t capacity() const { return MaxCallbacks; }

private:
    // Static wrapper function for index
    template <size_t Index>
    static auto wrapper_function(auto... args) -> decltype(std::declval<lambda_t>()(args...))
    {
        using return_t = decltype(std::declval<lambda_t>()(args...));

        auto& self = instance();

        // Copy callback to avoid concurrent unregistration issues
        lambda_t callback_copy;
        {
            std::shared_lock lock(self.mutex_);
            if (Index < MaxCallbacks)
                callback_copy = self.callbacks_[Index];
        }

        // Call outside lock
        if (callback_copy)
            return callback_copy(args...);

        if constexpr (!std::is_void_v<return_t>)
            return return_t{};
    }

    // Generate array of wrapper functions at compile time
    template <size_t... Is>
    static constexpr auto make_wrapper_array(std::index_sequence<Is...>)
    {
        return std::array<callback_t, sizeof...(Is)>{&wrapper_function<Is>...};
    }

    // Get wrapper for specific index
    static callback_t get_wrapper_for_index(size_t index)
    {
        static constexpr auto wrappers = make_wrapper_array(std::make_index_sequence<MaxCallbacks>{});

        if (index < MaxCallbacks)
            return wrappers[index];

        return nullptr;
    }

    std::array<lambda_t, MaxCallbacks> callbacks_{};
    std::array<callback_handle_t, MaxCallbacks> handles_{};
    callback_handle_t next_handle_ = 1;
    size_t next_slot_ = 0;  ///< high-water slot allocator; freed slots are not reused
    mutable std::shared_mutex mutex_;
};

//------------------------------------------------------------------------------
/**
 * @brief Macro to define a callback registry with tag-based disambiguation.
 *
 * Creates a type alias and global instance for a callback registry.
 *
 * @param name Name for the registry
 * @param Prototype C function pointer type
 * @param MaxCallbacks Maximum number of callbacks
 *
 * @example
 * @code
 * DEFINE_CALLBACK_REGISTRY(my_callbacks, void(*)(int), 32);
 * auto result = my_callbacks.register_callback([](int x) { ... });
 * @endcode
 */
#define DEFINE_CALLBACK_REGISTRY(name, Prototype, MaxCallbacks)                               \
    struct name##_tag                                                                          \
    {                                                                                          \
    };                                                                                         \
    using name##_type = libidacpp::callbacks::callback_registry<Prototype, MaxCallbacks, name##_tag>; \
    inline name##_type& name = name##_type::instance();

//------------------------------------------------------------------------------
/**
 * @brief Register a callback (simplified API).
 *
 * @tparam CPrototype C function pointer type
 * @tparam MaxCallbacks Maximum callbacks (default: 256)
 * @tparam Tag Type tag for registry disambiguation
 * @tparam Lambda Lambda type (deduced)
 * @param cb Lambda to register
 * @return Optional pair of (handle, C function pointer)
 */
template <typename CPrototype, size_t MaxCallbacks = 256, typename Tag = void, typename Lambda>
inline std::optional<std::pair<callback_handle_t, CPrototype>> register_callback(Lambda&& cb)
{
    return callback_registry<CPrototype, MaxCallbacks, Tag>::instance().register_callback(
        std::forward<Lambda>(cb));
}

/**
 * @brief Unregister a callback (simplified API).
 *
 * @tparam CPrototype C function pointer type
 * @tparam MaxCallbacks Maximum callbacks (default: 256)
 * @tparam Tag Type tag for registry disambiguation
 * @param handle Handle from register_callback()
 * @return true if unregistered successfully
 */
template <typename CPrototype, size_t MaxCallbacks = 256, typename Tag = void>
inline bool unregister_callback(callback_handle_t handle)
{
    return callback_registry<CPrototype, MaxCallbacks, Tag>::instance().unregister_callback(handle);
}

//------------------------------------------------------------------------------
/**
 * @brief RAII wrapper for automatic callback unregistration.
 *
 * Automatically unregisters callback when the object goes out of scope.
 *
 * @tparam CPrototype C function pointer type
 * @tparam MaxCallbacks Maximum callbacks (default: 256)
 * @tparam Tag Type tag for registry disambiguation
 *
 * @example
 * @code
 * {
 *     scoped_callback<void(*)(int)> cb([](int x) { msg("x=%d\n", x); });
 *     if (cb) {
 *         some_c_api_register(*cb);  // Get C function pointer
 *     }
 *     // Automatically unregistered when cb goes out of scope
 * }
 * @endcode
 */
template <typename CPrototype, size_t MaxCallbacks = 256, typename Tag = void>
class scoped_callback
{
public:
    using callback_t = CPrototype;
    using registry_t = callback_registry<CPrototype, MaxCallbacks, Tag>;

    /**
     * @brief Construct and register a callback.
     */
    template <typename Lambda>
    explicit scoped_callback(Lambda&& cb) : handle_(INVALID_CALLBACK_HANDLE), callback_(nullptr)
    {
        auto result = registry_t::instance().register_callback(std::forward<Lambda>(cb));
        if (result)
        {
            handle_ = result->first;
            callback_ = result->second;
        }
    }

    /**
     * @brief Destructor - automatically unregisters callback.
     */
    ~scoped_callback()
    {
        reset();
    }

    // Move semantics
    scoped_callback(scoped_callback&& other) noexcept
        : handle_(std::exchange(other.handle_, INVALID_CALLBACK_HANDLE)),
          callback_(std::exchange(other.callback_, nullptr))
    {
    }

    scoped_callback& operator=(scoped_callback&& other) noexcept
    {
        if (this != &other)
        {
            reset();
            handle_ = std::exchange(other.handle_, INVALID_CALLBACK_HANDLE);
            callback_ = std::exchange(other.callback_, nullptr);
        }
        return *this;
    }

    // Non-copyable
    scoped_callback(const scoped_callback&) = delete;
    scoped_callback& operator=(const scoped_callback&) = delete;

    // Access
    callback_t get() const { return callback_; }
    callback_t operator*() const { return callback_; }

    explicit operator bool() const { return callback_ != nullptr; }
    bool is_valid() const { return callback_ != nullptr; }

    /**
     * @brief Manually unregister the callback.
     */
    void reset()
    {
        if (handle_ != INVALID_CALLBACK_HANDLE)
        {
            registry_t::instance().unregister_callback(handle_);
            handle_ = INVALID_CALLBACK_HANDLE;
            callback_ = nullptr;
        }
    }

    /**
     * @brief Release ownership without unregistering.
     *
     * @return The C function pointer (caller responsible for cleanup)
     */
    callback_t release()
    {
        handle_ = INVALID_CALLBACK_HANDLE;
        return std::exchange(callback_, nullptr);
    }

    /**
     * @brief Get the callback handle.
     */
    callback_handle_t handle() const { return handle_; }

private:
    callback_handle_t handle_;
    callback_t callback_;
};

//------------------------------------------------------------------------------
/**
 * @brief Factory function for creating scoped callbacks.
 *
 * @tparam CPrototype C function pointer type
 * @tparam MaxCallbacks Maximum callbacks (default: 256)
 * @tparam Tag Type tag for registry disambiguation
 * @tparam Lambda Lambda type (deduced)
 * @param cb Lambda to register
 * @return scoped_callback object
 */
template <typename CPrototype, size_t MaxCallbacks = 256, typename Tag = void, typename Lambda>
auto make_scoped_callback(Lambda&& cb)
{
    return scoped_callback<CPrototype, MaxCallbacks, Tag>(std::forward<Lambda>(cb));
}

}  // namespace libidacpp::callbacks
