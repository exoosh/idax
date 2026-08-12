/**
 * @file pch_dummy.cpp
 * @brief Dummy source file for PCH target.
 *
 * This file exists solely to create a static library target that can
 * hold the precompiled header for REUSE_FROM in CMake.
 */

// Include the PCH header to ensure it compiles
#include <libidacpp/pch.hpp>

// Empty - this file just enables the PCH target
