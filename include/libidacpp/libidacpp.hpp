// Copyright (c) 2019-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * @file libidacpp.hpp
 * @brief Master convenience header - includes all libidacpp modules.
 *
 * This single header includes all libidacpp modules for convenience.
 * For more granular control, include individual module headers.
 *
 * @author Elias Bachaalany <elias.bachaalany@gmail.com>
 * @copyright 2019-2026
 *
 * @par Example:
 * @code
 * #include <libidacpp/libidacpp.hpp>
 *
 * using namespace libidacpp::kernwin;
 * using namespace libidacpp::hexrays;
 *
 * // Now all libidacpp modules are available
 * @endcode
 */
#pragma once

// Core utilities
#include <libidacpp/core/core.hpp>

// Hexrays utilities (decompiler)
// NOTE: included BEFORE kernwin so that __HEXRAYS_HPP is defined when kernwin.hpp
// is parsed — kernwin's enable::when_vdui* helpers are guarded on it. Reversing
// this order silently drops those helpers for umbrella users.
#include <libidacpp/hexrays/hexrays.hpp>

// Kernwin utilities (UI and actions)
#include <libidacpp/kernwin/kernwin.hpp>

// Expression utilities
#include <libidacpp/expr/expr.hpp>

// Callback utilities
#include <libidacpp/callbacks/callbacks.hpp>
#include <libidacpp/callbacks/inplace_hook.hpp>

// Storage utilities (netnode + registry persistence)
#include <libidacpp/storage/netnode.hpp>
#include <libidacpp/storage/registry.hpp>

// Text utilities (pure, no IDA SDK)
#include <libidacpp/text/text.hpp>

// Bytes utilities (disassembly and patching)
#include <libidacpp/bytes/bytes.hpp>

// NOTE: idalib session is NOT auto-included (for headless use only)
// Include directly when using idalib: #include <libidacpp/idalib/session.hpp>

// NOTE: the mem module is NOT auto-included — its module_range() pulls in platform
// headers (<windows.h> / <dlfcn.h> …). Include directly, from a .cpp, when needed:
// #include <libidacpp/mem/mem.hpp>

/**
 * @mainpage libidacpp - Modern C++ Extensions for IDA SDK
 *
 * @section intro_sec Introduction
 *
 * libidacpp is a modern C++20 library providing high-level utilities and abstractions
 * for IDA Pro plugin development with proper namespacing, modern C++ features,
 * and ida-cmake integration.
 *
 * @section modules_sec Modules
 *
 * - @ref libidacpp::core "Core" - Base utilities and containers
 * - @ref libidacpp::kernwin "Kernwin" - UI and action management
 * - @ref libidacpp::hexrays "Hexrays" - Decompiler utilities
 * - @ref libidacpp::expr "Expr" - Expression evaluation
 * - @ref libidacpp::callbacks "Callbacks" - C API bridging + in-place fn-ptr hooks
 * - @ref libidacpp::storage::netnode "Storage" - Netnode + registry persistence
 * - @ref libidacpp::text "Text" - Small text utilities (pure)
 * - @ref libidacpp::bytes "Bytes" - Disassembly and patching
 * - @ref libidacpp::mem "Mem" - Cross-platform memory/module scanning (include separately)
 * - @ref libidacpp::idalib "Idalib" - Headless IDA session (include separately)
 *
 * @section usage_sec Quick Start
 *
 * @code
 * #include <libidacpp/libidacpp.hpp>  // All modules
 *
 * using namespace libidacpp::kernwin;
 *
 * action_manager_t actions;
 * actions.add_action(...);
 * @endcode
 *
 * @section license_sec License
 *
 * Human-Origin Source License v1.0 (source-available) - see LICENSE file for details
 */
