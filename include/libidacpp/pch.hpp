// Copyright (c) 2019-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * @file pch.hpp
 * @brief Precompiled header for libidacpp - IDA SDK and standard library headers.
 *
 * Include this file in your project's precompiled header to speed up compilation.
 * Contains stable headers that rarely change: IDA SDK core and STL.
 *
 * @author Elias Bachaalany <elias.bachaalany@gmail.com>
 * @copyright 2019-2026
 *
 * @par Usage in CMakeLists.txt:
 * @code
 * target_precompile_headers(my_plugin PRIVATE
 *     <libidacpp/pch.hpp>
 * )
 * @endcode
 *
 * @par Or create your own pch.h that includes this:
 * @code
 * // pch.h
 * #pragma once
 * #include <libidacpp/pch.hpp>
 * // Add your project-specific stable headers here
 * @endcode
 */
#pragma once

// ============================================================================
// Standard Library Headers (most stable, rarely change)
// ============================================================================

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

// ============================================================================
// IDA SDK Core Headers (stable API)
// ============================================================================

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <auto.hpp>
#include <nalt.hpp>
#include <netnode.hpp>
#include <segment.hpp>
#include <name.hpp>
#include <ua.hpp>
#include <xref.hpp>
#include <expr.hpp>

// ============================================================================
// Hex-Rays Decompiler Headers
// ============================================================================
// Note: Always included since many libidacpp utilities depend on it.
// For non-decompiler plugins, the symbols are simply unused.

#include <hexrays.hpp>
