// Copyright (c) 2019-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * @file core.hpp
 * @brief Core utilities and container classes.
 *
 * This module provides fundamental utilities for IDA plugin development:
 * - RAII object containers with automatic lifetime management
 * - Common helper classes and patterns
 *
 * @author Elias Bachaalany <elias.bachaalany@gmail.com>
 * @copyright 2019-2026
 *
 * @par Example:
 * @code
 * using namespace libidacpp::core;
 *
 * // Object container with automatic cleanup
 * objcontainer_t<my_handler_t> handlers;
 * auto* h1 = create(handlers, arg1, arg2);
 * auto* h2 = create(handlers, arg3);
 *
 * // Access helpers
 * auto* last = back(handlers);   // Last element
 * auto* first = at(handlers, 0); // By index
 *
 * // All objects automatically deleted when container is destroyed
 * @endcode
 */
#pragma once

#include <memory>
#include <vector>

namespace libidacpp::core
{

//----------------------------------------------------------------------------------
/**
 * @brief RAII object container - alias for vector of unique_ptr.
 *
 * A simple ownership container for dynamically allocated objects.
 * Objects are automatically destroyed when the container is destroyed.
 *
 * @tparam T The type of objects to store
 */
template<typename T>
using objcontainer_t = std::vector<std::unique_ptr<T>>;

//----------------------------------------------------------------------------------
/**
 * @brief Create and store a new object in the container.
 *
 * @tparam T Object type (deduced from container)
 * @tparam Args Constructor argument types (deduced)
 * @param container Target container
 * @param args Arguments forwarded to T's constructor
 * @return T* Pointer to the newly created object
 *
 * @par Example:
 * @code
 * objcontainer_t<handler_t> handlers;
 * auto* h = create(handlers, "name", callback);
 * @endcode
 */
template<typename T, typename... Args>
T* create(objcontainer_t<T>& container, Args&&... args)
{
    container.push_back(std::make_unique<T>(std::forward<Args>(args)...));
    return container.back().get();
}

//----------------------------------------------------------------------------------
/**
 * @brief Get pointer to last element in container (nullptr if empty).
 *
 * Const-correct: a const container yields a `const T*`, a mutable one a `T*`.
 */
template<typename T>
T* back(objcontainer_t<T>& container)
{
    return container.empty() ? nullptr : container.back().get();
}

template<typename T>
const T* back(const objcontainer_t<T>& container)
{
    return container.empty() ? nullptr : container.back().get();
}

//----------------------------------------------------------------------------------
/**
 * @brief Get pointer to element at index, or nullptr if out of range.
 *
 * Bounds-checked (mirrors back()'s null-safety) and const-correct.
 *
 * @param container Source container
 * @param index Element index
 * @return Pointer to the element, or nullptr if @p index >= size()
 */
template<typename T>
T* at(objcontainer_t<T>& container, size_t index)
{
    return index < container.size() ? container[index].get() : nullptr;
}

template<typename T>
const T* at(const objcontainer_t<T>& container, size_t index)
{
    return index < container.size() ? container[index].get() : nullptr;
}

}  // namespace libidacpp::core
