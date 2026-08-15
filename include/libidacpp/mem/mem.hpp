// Copyright (c) 2019-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * @file mem.hpp
 * @brief Cross-platform in-memory scanning helpers (no IDA SDK).
 *
 * Two small utilities that plugins reach for when they need to poke at a loaded
 * module's image directly:
 *   - @ref libidacpp::mem::find_pattern — fast byte-pattern search in a buffer.
 *   - @ref libidacpp::mem::module_range — a loaded module's [base, size) range,
 *     parsed from the PE / ELF / Mach-O headers of the running process.
 *
 * @author Elias Bachaalany <elias.bachaalany@gmail.com>
 * @copyright 2019-2026
 *
 * @par Example:
 * @code
 * if (auto r = libidacpp::mem::module_range("idapython3.dll"))
 * {
 *     const char pat[] = "Python - IDAPython plugin";
 *     const uint8_t *hit = libidacpp::mem::find_pattern(
 *         r->base, r->size, (const uint8_t *)pat, sizeof(pat) - 1);
 * }
 * @endcode
 *
 * @note The platform bodies of @ref module_range pull in @c <windows.h> /
 *       @c <dlfcn.h> etc.; include this header from a .cpp, not a widely-shared
 *       header, to keep that out of unrelated translation units.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>

#if defined(_WIN32)
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
#else
    #include <dlfcn.h>
    #if defined(__APPLE__)
        #include <mach-o/dyld.h>
        #include <mach-o/getsect.h>
    #else
        #include <link.h>
        #include <elf.h>
    #endif
#endif

namespace libidacpp::mem
{

//------------------------------------------------------------------------------
/**
 * @brief Search for a byte pattern in a buffer.
 *
 * Uses @c memchr to jump between first-byte candidates, then verifies the rest
 * of the pattern with @c memcmp — noticeably faster than a naive scan on real
 * module images.
 *
 * @param start        Start of the buffer to search.
 * @param size         Size of the buffer in bytes.
 * @param pattern      Pattern bytes to look for.
 * @param pattern_len  Length of @p pattern.
 * @return Pointer to the first match within @p start, or @c nullptr if not found
 *         (also @c nullptr when @p pattern_len is 0 or larger than @p size).
 */
inline const uint8_t *find_pattern(
        const uint8_t *start,
        size_t size,
        const uint8_t *pattern,
        size_t pattern_len)
{
    if (size < pattern_len || pattern_len == 0)
        return nullptr;

    const uint8_t first_byte = pattern[0];
    const uint8_t *search_end = start + size - pattern_len;
    const uint8_t *p = start;

    while (p <= search_end)
    {
        // Quickly find the next occurrence of the first byte.
        p = (const uint8_t *)memchr(p, first_byte, search_end - p + 1);
        if (p == nullptr)
            return nullptr;

        // First byte matched: check the remainder.
        if (pattern_len == 1 || memcmp(p + 1, pattern + 1, pattern_len - 1) == 0)
            return p;

        ++p;
    }

    return nullptr;
}

//------------------------------------------------------------------------------
/// A loaded module's in-memory image range.
struct module_range_t
{
    const uint8_t *base = nullptr;   ///< Image base address in this process.
    size_t         size = 0;         ///< Image size in bytes (SizeOfImage / span of PT_LOAD / segments).
};

//------------------------------------------------------------------------------
/**
 * @brief Locate an already-loaded module by name and return its image range.
 *
 * @param module_name Platform module name (e.g. "idapython3.dll",
 *                    "idapython3.so", "idapython3.dylib", "ida.exe").
 * @return The module's [base, size), or @c std::nullopt if it is not loaded or
 *         its headers cannot be parsed.
 */
inline std::optional<module_range_t> module_range(const char *module_name)
{
#if defined(_WIN32)

    HMODULE hmod = GetModuleHandleA(module_name);
    if (hmod == nullptr)
        return std::nullopt;

    uint8_t *base = (uint8_t *)hmod;
    auto *dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return std::nullopt;

    auto *nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return std::nullopt;

    size_t module_size;
    const WORD magic = nt->OptionalHeader.Magic;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        module_size = ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.SizeOfImage;
    else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        module_size = ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.SizeOfImage;
    else
        return std::nullopt;

    return module_range_t{ base, module_size };

#elif defined(__linux__)

    void *handle = dlopen(module_name, RTLD_NOLOAD | RTLD_NOW);
    if (handle == nullptr)
        return std::nullopt;

    struct link_map *map = nullptr;
    if (dlinfo(handle, RTLD_DI_LINKMAP, &map) != 0 || map == nullptr)
    {
        dlclose(handle);
        return std::nullopt;
    }

    uint8_t *base = (uint8_t *)map->l_addr;
    auto *ehdr = (Elf64_Ehdr *)base;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
    {
        dlclose(handle);
        return std::nullopt;
    }

    auto *phdr = (Elf64_Phdr *)(base + ehdr->e_phoff);
    size_t module_size = 0;
    for (int i = 0; i < ehdr->e_phnum; ++i)
    {
        if (phdr[i].p_type == PT_LOAD)
        {
            size_t end = phdr[i].p_vaddr + phdr[i].p_memsz;
            if (end > module_size)
                module_size = end;
        }
    }

    dlclose(handle);   // RTLD_NOLOAD only bumped the refcount; base stays valid.
    return module_range_t{ base, module_size };

#elif defined(__APPLE__)

    void *handle = dlopen(module_name, RTLD_NOLOAD | RTLD_NOW);
    if (handle == nullptr)
        return std::nullopt;

    Dl_info info;
    if (dladdr(handle, &info) == 0)
    {
        dlclose(handle);
        return std::nullopt;
    }

    uint8_t *base = (uint8_t *)info.dli_fbase;
    auto *mh = (struct mach_header_64 *)base;
    if (mh->magic != MH_MAGIC_64)
    {
        dlclose(handle);
        return std::nullopt;
    }

    auto *lc = (struct load_command *)(base + sizeof(struct mach_header_64));
    size_t module_size = 0;
    for (uint32_t i = 0; i < mh->ncmds; ++i)
    {
        if (lc->cmd == LC_SEGMENT_64)
        {
            auto *seg = (struct segment_command_64 *)lc;
            size_t end = seg->vmaddr + seg->vmsize;
            if (end > module_size)
                module_size = end;
        }
        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }

    dlclose(handle);   // RTLD_NOLOAD only bumped the refcount; base stays valid.
    return module_range_t{ base, module_size };

#else

    (void)module_name;
    return std::nullopt;

#endif
}

}  // namespace libidacpp::mem
