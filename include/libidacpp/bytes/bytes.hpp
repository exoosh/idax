// Copyright (c) 2019-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * @file bytes.hpp
 * @brief Disassembly byte manipulation and patching utilities.
 *
 * This module provides helpers for working with raw instruction bytes:
 * - Capturing and pasting instructions (with comments)
 * - NOP-filling address ranges
 * - Safe instruction patching
 *
 * @author Elias Bachaalany <elias.bachaalany@gmail.com>
 * @copyright 2019-2026
 *
 * @par Example:
 * @code
 * // Swap two instructions
 * code_snippet_t inst1(ea1), inst2(ea2);
 * del_items(ea1, 0, inst1.size() + inst2.size());
 * ea_t next = inst2.paste(ea1);
 * inst1.paste(next);
 *
 * // NOP out unwanted code
 * nop_range(start_ea, end_ea);
 * @endcode
 */
#pragma once

#include <pro.h>
#include <bytes.hpp>
#include <ua.hpp>
#include <idp.hpp>

namespace libidacpp::bytes
{

//--------------------------------------------------------------------------
/**
 * @brief Captured instruction with bytes and comments.
 *
 * Used for copying/pasting instructions (e.g., line swapping).
 * Captures instruction bytes, regular comment, and repeatable comment.
 */
struct code_snippet_t
{
    ea_t ea = BADADDR;
    bytevec_t bytes;
    qstring cmt;
    qstring rep_cmt;

    code_snippet_t() = default;

    /**
     * @brief Construct by capturing instruction at EA.
     */
    explicit code_snippet_t(ea_t src_ea) { capture(src_ea); }

    /**
     * @brief Capture instruction at EA.
     * @param src_ea Source address
     * @return true if captured, false if invalid instruction or block-ending
     */
    bool capture(ea_t src_ea)
    {
        ea = BADADDR;
        bytes.clear();
        cmt.clear();
        rep_cmt.clear();

        insn_t inst;
        if (!decode_insn(&inst, src_ea) || is_basic_block_end(inst, true))
            return false;

        auto sz = inst.size;

        get_cmt(&cmt, src_ea, false);
        get_cmt(&rep_cmt, src_ea, true);

        bytes.resize(sz);
        if (get_bytes(bytes.begin(), sz, src_ea) != sz)
        {
            // Partial/failed read: do not keep a half-captured snippet that
            // paste() would later write out as corrupt bytes.
            bytes.clear();
            return false;
        }

        ea = src_ea;
        return true;
    }

    /**
     * @brief Paste captured instruction at destination.
     * @param dst_ea Destination address
     * @return Address after pasted bytes
     */
    ea_t paste(ea_t dst_ea) const
    {
        if (ea == BADADDR || bytes.empty())
            return dst_ea;

        patch_bytes(dst_ea, bytes.begin(), bytes.size());

        if (!cmt.empty())
            set_cmt(dst_ea, cmt.c_str(), false);
        if (!rep_cmt.empty())
            set_cmt(dst_ea, rep_cmt.c_str(), true);

        return dst_ea + ea_t(bytes.size());
    }

    size_t size() const { return bytes.size(); }
    explicit operator bool() const { return ea != BADADDR; }
    bool operator!() const { return ea == BADADDR; }
};

//--------------------------------------------------------------------------
/**
 * @brief Fill range with NOP bytes.
 *
 * @warning x86/x64 ONLY. The 0x90 opcode is the Intel NOP; writing it on other
 * architectures (ARM, MIPS, PPC, ...) produces invalid/incorrect code. This
 * function refuses to write anything on non-x86 processors.
 *
 * @param start Start address
 * @param end End address (exclusive)
 * @return true if the range was NOP-filled; false if the processor is unsupported
 */
inline bool nop_range(ea_t start, ea_t end)
{
    if (PH.id != PLFM_386)
        return false;  // only x86/x64 use 0x90; refuse rather than corrupt other ISAs

    for (ea_t ea = start; ea < end; ++ea)
        patch_byte(ea, 0x90);
    return true;
}

/**
 * @brief NOP a single instruction.
 *
 * @warning x86/x64 ONLY (see nop_range()).
 * @param ea Instruction address
 * @return true if NOP-filled; false on decode failure or unsupported processor
 */
inline bool nop_instruction(ea_t ea)
{
    insn_t inst;
    if (!decode_insn(&inst, ea))
        return false;
    return nop_range(ea, ea + inst.size);
}

}  // namespace libidacpp::bytes
