cmake_minimum_required(VERSION 3.27)
project(libidacpp VERSION 1.0.0 LANGUAGES CXX)

# C++ Standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Include IDA SDK bootstrap (only if not already included)
if(NOT TARGET ida_platform_settings)
    include($ENV{IDASDK}/ida-cmake/bootstrap.cmake)
    find_package(idasdk REQUIRED)
endif()

# libidacpp is a header-only library
add_library(libidacpp INTERFACE)
add_library(libidacpp::libidacpp ALIAS libidacpp)

target_include_directories(libidacpp INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

# Propagate the C++20 requirement to consumers. The directory-scope
# CMAKE_CXX_STANDARD above only affects this project's own build; the INTERFACE
# usage-requirement is what carries C++20 to anyone linking libidacpp::libidacpp.
target_compile_features(libidacpp INTERFACE cxx_std_20)

# Link to IDA SDK if available
if(TARGET idasdk::idasdk)
    target_link_libraries(libidacpp INTERFACE idasdk::idasdk)
endif()

# ============================================================================
# Precompiled Header Support
# ============================================================================
# Consumers can use libidacpp's PCH by adding to their CMakeLists.txt:
#
#   target_precompile_headers(my_target PRIVATE <libidacpp/pch.hpp>)
#
# Or reuse libidacpp's PCH interface (if LIBIDACPP_ENABLE_PCH is ON):
#
#   target_precompile_headers(my_target REUSE_FROM libidacpp_pch)
#
# ============================================================================

option(LIBIDACPP_ENABLE_PCH "Create a PCH target that consumers can reuse" OFF)

if(LIBIDACPP_ENABLE_PCH)
    # Create a static library to hold the PCH
    # This allows consumers to REUSE_FROM this target
    add_library(libidacpp_pch STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/pch_dummy.cpp
    )
    add_library(libidacpp::pch ALIAS libidacpp_pch)

    target_link_libraries(libidacpp_pch PUBLIC libidacpp)

    target_precompile_headers(libidacpp_pch PUBLIC
        <libidacpp/pch.hpp>
    )

    # Export PCH header path for consumers
    set(LIBIDACPP_PCH_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/include/libidacpp/pch.hpp"
        CACHE FILEPATH "Path to libidacpp precompiled header")
endif()

# ============================================================================
# Helper Functions
# ============================================================================

#[============================================================================[
Enable delay-loading of IDA DLLs for threaded idalib usage.

Required when using libidacpp::idalib::session_t which runs IDA in a worker thread.
Without delay-loading, init_library() will deadlock because DLLs are loaded
at process startup on the main thread, but session_t initializes from worker.

Usage:
    libidacpp_enable_threaded_idalib(my_target)

This adds:
    - /DELAYLOAD:ida.dll
    - /DELAYLOAD:idalib.dll
    - delayimp.lib
#]============================================================================]
function(libidacpp_enable_threaded_idalib target)
    if(MSVC)
        target_link_options(${target} PRIVATE
            "/DELAYLOAD:ida.dll"
            "/DELAYLOAD:idalib.dll"
        )
        target_link_libraries(${target} PRIVATE delayimp.lib)
    endif()
endfunction()
