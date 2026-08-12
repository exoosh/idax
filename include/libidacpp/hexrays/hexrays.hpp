// Copyright (c) 2019-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * @file hexrays.hpp
 * @brief Hex-Rays decompiler utilities for ctree manipulation.
 *
 * This module provides helpers for working with the Hex-Rays decompiler:
 * - Parent-tracking ctree visitor with EA mapping
 * - Statement collection by EA set
 * - Statement erasure from ctree
 * - LCA (Lowest Common Ancestor) filtering
 * - Selection range helpers
 *
 * @author Elias Bachaalany <elias.bachaalany@gmail.com>
 * @copyright 2019-2026
 *
 * @par Example - Delete statements by EA:
 * @code
 * easet_t eas_to_delete;
 * eas_to_delete.insert(stmt->ea);
 *
 * ctreeparent_visitor_t helper;
 * helper.apply_to(&cfunc->body, nullptr);
 *
 * cinsnptrvec_t stmts;
 * collect_statements_by_eas(cfunc, eas_to_delete, stmts, &helper);
 * keep_lca_cinsns(cfunc, &helper, stmts);
 * erase_statements(cfunc, stmts, &helper);
 * @endcode
 */
#pragma once

#include <algorithm>
#include <functional>
#include <map>
#include <memory>

#include <hexrays.hpp>

#include <libidacpp/kernwin/kernwin.hpp>

namespace libidacpp::hexrays
{

//----------------------------------------------------------------------------------
/**
 * @brief Default update state handler for Hexrays decompiler views (expression selected).
 *
 * Enables action only when a decompiler widget is active and an expression is selected.
 */
inline kernwin::update_state_ah_t default_enable_for_vd_expr = FO_ACTION_UPDATE([],
    auto vu = get_widget_vdui(widget);
    return (vu == nullptr) ? AST_DISABLE_FOR_WIDGET
                            : vu->item.citype == VDI_EXPR ? AST_ENABLE : AST_DISABLE;
);

/**
 * @brief Default update state handler for Hexrays decompiler views.
 *
 * Enables action whenever a decompiler widget is active.
 */
inline kernwin::update_state_ah_t default_enable_for_vd = FO_ACTION_UPDATE([],
    auto vu = get_widget_vdui(widget);
    return vu == nullptr ? AST_DISABLE_FOR_WIDGET : AST_ENABLE;
);

//----------------------------------------------------------------------------------
/**
 * @brief Enhanced ctree visitor with parent tracking and EA mapping.
 *
 * Extends ctree_parentee_t to build and maintain maps of parent relationships
 * and effective address to item mappings during tree traversal.
 */
class ctreeparent_visitor_t : public ctree_parentee_t
{
private:
    std::map<const citem_t*, const citem_t*> parent;   ///< Parent map
    std::map<const ea_t, const citem_t*> ea2item;      ///< EA to item map

public:
    /**
     * @brief Visit expression node.
     */
    int idaapi visit_expr(cexpr_t* e) override
    {
        // Use parent_item() not parent_expr() - parent may be cinsn_t
        parent[e] = parent_item();
        // Don't overwrite instruction entries - prefer instructions over expressions
        // for statement collection when same EA. Skip BADADDR (synthetic nodes).
        if (e->ea != BADADDR && ea2item.find(e->ea) == ea2item.end())
            ea2item[e->ea] = e;
        return 0;
    }

    /**
     * @brief Visit instruction node.
     */
    int idaapi visit_insn(cinsn_t* ins) override
    {
        parent[ins] = parent_insn();
        // Instructions take priority over expressions for same EA. Skip BADADDR.
        if (ins->ea != BADADDR)
            ea2item[ins->ea] = ins;
        return 0;
    }

    /**
     * @brief Get parent of a tree item.
     *
     * @param item Tree item
     * @return Parent item, or nullptr if root
     */
    const citem_t* parent_of(const citem_t* item)
    {
        return parent[item];
    }

    /**
     * @brief Find tree item by effective address.
     *
     * @param ea Effective address
     * @return Tree item at EA, or nullptr if not found
     */
    const citem_t* by_ea(ea_t ea) const
    {
        auto p = ea2item.find(ea);
        return p == std::end(ea2item) ? nullptr : p->second;
    }

    /**
     * @brief Check if parent_item is ancestor of item.
     *
     * @param parent_item Potential ancestor
     * @param item Child item to check
     * @return true if parent_item is an ancestor of item
     */
    bool is_ancestor_of(const citem_t* parent_item, const citem_t* item)
    {
        while (item != nullptr)
        {
            item = parent_of(item);
            if (item == parent_item)
                return true;
        }
        return false;
    }
};

/// Unique pointer to ctree parent visitor
using ctreeparent_visitor_ptr_t = std::unique_ptr<ctreeparent_visitor_t>;

//----------------------------------------------------------------------------------
/**
 * @brief Get selection range from widget.
 *
 * @param widget Target widget
 * @param end_ea Output parameter for end address (optional)
 * @param widget_type Expected widget type, or -1 for any
 * @return Start address, or BADADDR if no selection
 */
inline ea_t get_selection_range(
    TWidget* widget,
    ea_t* end_ea = nullptr,
    int widget_type = BWN_DISASM)
{
    ea_t ea1 = BADADDR, ea2 = BADADDR;
    do
    {
        if (widget == nullptr || (widget_type != -1 && get_widget_type(widget) != widget_type))
            break;

        if (!read_range_selection(widget, &ea1, &ea2))
        {
            ea1 = get_screen_ea();

            if (ea1 == BADADDR)
                break;

            ea2 = next_head(ea1, BADADDR);
            if (ea2 == BADADDR)
                ea2 = ea1 + 1;
        }
    } while (false);

    if (end_ea != nullptr)
        *end_ea = ea2;

    return ea1;
}

//----------------------------------------------------------------------------------
/**
 * @brief Get the statement instruction containing a UI item.
 *
 * @param cfunc Decompiled function
 * @param ui_item Current UI item
 * @param ohelper Optional in/out parameter for parent visitor (for reuse)
 * @return Statement instruction, or nullptr if not found
 */
inline const cinsn_t* get_stmt_insn(
    cfunc_t* cfunc,
    const citem_t* ui_item,
    ctreeparent_visitor_ptr_t* ohelper = nullptr)
{
    auto func_body = &cfunc->body;

    const citem_t* item = ui_item;
    const citem_t* stmt_item;

    ctreeparent_visitor_t* helper = nullptr;

    if (ohelper != nullptr)
    {
        // Start a new helper
        if (*ohelper == nullptr)
        {
            helper = new ctreeparent_visitor_t();
            helper->apply_to(func_body, nullptr);

            ohelper->reset(helper);
        }
        else
        {
            helper = ohelper->get();
        }
    }

    auto get_parent = [func_body, &helper](const citem_t* item)
    {
        return helper == nullptr ? func_body->find_parent_of(item)
                                 : helper->parent_of(item);
    };

    // Get the top level statement from this item
    for (stmt_item = item;
         item != nullptr && item->is_expr();
         item = get_parent(item))
    {
        stmt_item = item;
    }

    // ...then the actual instruction item
    if (stmt_item->is_expr())
        stmt_item = get_parent(stmt_item);

    return (const cinsn_t*)stmt_item;
}

//----------------------------------------------------------------------------------
/**
 * @brief Get the block and position of a statement.
 *
 * @param cfunc Decompiled function
 * @param stmt_item Statement item
 * @param p_cblock Output parameter for containing block
 * @param p_pos Output parameter for position in block
 * @param helper Optional parent visitor
 * @return true if found, false otherwise
 */
inline bool get_stmt_block_pos(
    cfunc_t* cfunc,
    const citem_t* stmt_item,
    cblock_t** p_cblock,
    cblock_t::iterator* p_pos,
    ctreeparent_visitor_t* helper = nullptr)
{
    auto func_body = &cfunc->body;
    auto cblock_insn = (cinsn_t*)(
        helper == nullptr ? func_body->find_parent_of(stmt_item)
                          : helper->parent_of(stmt_item));

    if (cblock_insn == nullptr || cblock_insn->op != cit_block)
        return false;

    cblock_t* cblock = cblock_insn->cblock;

    for (auto p = cblock->begin(); p != cblock->end(); ++p)
    {
        if (&*p == stmt_item)
        {
            *p_pos = p;
            *p_cblock = cblock;
            return true;
        }
    }
    return false;
}

//----------------------------------------------------------------------------------
/**
 * @brief Check if any instruction in list is ancestor of item.
 *
 * @param h Parent visitor
 * @param inst Instruction list
 * @param item Item to check
 * @return true if any instruction is ancestor of item
 */
inline bool are_ancestor_of(
    ctreeparent_visitor_t* h,
    cinsnptrvec_t& inst,
    citem_t* item)
{
    for (auto parent : inst)
    {
        if (h->is_ancestor_of(parent, item))
            return true;
    }
    return false;
}

//----------------------------------------------------------------------------------
/**
 * @brief Filter out statements that are descendants of other statements in the list.
 *
 * When deleting multiple statements, we must only delete the outermost ones.
 * If we delete a parent statement, its children are destroyed along with it.
 * Attempting to also delete a child would access freed memory and crash.
 *
 * This function removes any statement from the list if another statement in the
 * list is its ancestor, keeping only the outermost (topmost) statements.
 *
 * @note This filtering is for DELETION safety only. The original marked EAs
 *       should be preserved in storage so users can edit/remove individual marks.
 *       Call this function only when about to erase, not during collection.
 *
 * @param cfunc Decompiled function
 * @param helper Parent visitor
 * @param bulk_list Instruction list (modified in place)
 *
 * @par Example:
 * Given statements [if_stmt, printf_inside_if], where if_stmt contains printf:
 * - printf is filtered out (it's a descendant of if_stmt)
 * - Only if_stmt remains for deletion
 * - Deleting if_stmt automatically removes printf from the tree
 */
inline void filter_descendant_statements(
    cfunc_t* cfunc,
    ctreeparent_visitor_t* helper,
    cinsnptrvec_t& bulk_list)
{
    cinsnptrvec_t new_list;
    while (!bulk_list.empty())
    {
        auto item = bulk_list.back();
        bulk_list.pop_back();

        // Keep only if no other statement (in remaining or already-kept) is our ancestor
        if (!are_ancestor_of(helper, bulk_list, item) &&
            !are_ancestor_of(helper, new_list, item))
            new_list.push_back(item);
    }
    new_list.swap(bulk_list);
}

/// @deprecated Use filter_descendant_statements instead
inline void keep_lca_cinsns(
    cfunc_t* cfunc,
    ctreeparent_visitor_t* helper,
    cinsnptrvec_t& bulk_list)
{
    filter_descendant_statements(cfunc, helper, bulk_list);
}

//----------------------------------------------------------------------------------
/**
 * @brief Find expressions in decompiled function using callback.
 *
 * @param func Decompiled function
 * @param cb Callback invoked for each expression (return 0 to continue, non-zero to stop)
 * @param flags Visitor flags (default: CV_FAST)
 * @param parent Starting parent item (nullptr for entire function)
 */
inline void find_expr(
    cfuncptr_t func,
    std::function<int(cexpr_t*)> cb,
    int flags = CV_FAST,
    citem_t* parent = nullptr)
{
    struct visitor_wrapper : public ctree_visitor_t
    {
        std::function<int(cexpr_t*)> cb;

        visitor_wrapper(int flags, std::function<int(cexpr_t*)> cb)
            : ctree_visitor_t(flags), cb(cb) {}

        virtual int idaapi visit_expr(cexpr_t* expr)
        {
            return cb(expr);
        }
    };

    visitor_wrapper v(flags, cb);
    v.apply_to(&func->body, parent);
}

//----------------------------------------------------------------------------------
/**
 * @brief Collect statements matching a set of effective addresses.
 *
 * Traverses the ctree and collects cinsn_t nodes whose EA is in the given set.
 * Skips cit_block nodes since they are containers, not statements.
 *
 * @param cfunc Decompiled function
 * @param eas Set of EAs to match
 * @param out Output vector of matching statements
 * @param helper Optional parent visitor (created if nullptr, reused if provided)
 */
inline void collect_statements_by_eas(
    cfunc_t* cfunc,
    const easet_t& eas,
    cinsnptrvec_t& out,
    ctreeparent_visitor_t* helper = nullptr)
{
    struct collector_t : public ctreeparent_visitor_t
    {
        const easet_t* eas;
        cinsnptrvec_t* out;

        collector_t(const easet_t* eas, cinsnptrvec_t* out)
            : eas(eas), out(out) {}

        int idaapi visit_insn(cinsn_t* ins) override
        {
            ctreeparent_visitor_t::visit_insn(ins);
            if (ins->op != cit_block && eas->count(ins->ea))
                out->push_back(ins);
            return 0;
        }
    };

    out.clear();

    if (helper != nullptr)
    {
        // Use existing helper - just iterate its cached data
        for (ea_t ea : eas)
        {
            auto item = helper->by_ea(ea);
            if (item != nullptr && !item->is_expr())
            {
                auto ins = (cinsn_t*)item;
                if (ins->op != cit_block)
                    out.push_back(ins);
            }
        }
    }
    else
    {
        collector_t collector(&eas, &out);
        collector.apply_to(&cfunc->body, nullptr);
    }
}

//----------------------------------------------------------------------------------
/**
 * @brief Erase a statement from its parent block.
 *
 * Finds the parent cblock_t and removes the statement from it.
 *
 * @param cfunc Decompiled function
 * @param stmt Statement to erase
 * @param helper Optional parent visitor
 * @return true if erased, false if not found or not in a block
 */
inline bool erase_statement(
    cfunc_t* cfunc,
    const cinsn_t* stmt,
    ctreeparent_visitor_t* helper = nullptr)
{
    cblock_t* cblock;
    cblock_t::iterator pos;

    if (!get_stmt_block_pos(cfunc, stmt, &cblock, &pos, helper))
        return false;

    cblock->erase(pos);
    return true;
}

//----------------------------------------------------------------------------------
/**
 * @brief Erase multiple statements from the ctree.
 *
 * Erases all statements in the list from their parent blocks, then removes
 * unused labels.
 *
 * @note This is safe against parent/child pairs: the list is filtered with
 *       filter_descendant_statements() first, so only the outermost statements
 *       are erased. Erasing a parent frees its descendants, so erasing a
 *       descendant afterwards would be a use-after-free — the internal filtering
 *       prevents that. @p stmts is modified in place (descendants removed).
 *
 * @param cfunc Decompiled function
 * @param stmts Statements to erase (filtered in place)
 * @param helper Optional parent visitor
 * @return Number of statements erased
 */
inline size_t erase_statements(
    cfunc_t* cfunc,
    cinsnptrvec_t& stmts,
    ctreeparent_visitor_t* helper = nullptr)
{
    ctreeparent_visitor_ptr_t local_helper;
    if (helper == nullptr)
    {
        local_helper.reset(new ctreeparent_visitor_t());
        local_helper->apply_to(&cfunc->body, nullptr);
        helper = local_helper.get();
    }

    // Safety: keep only outermost statements. Deleting a parent destroys its
    // children, so deleting a child afterwards would access freed memory.
    filter_descendant_statements(cfunc, helper, stmts);

    size_t count = 0;
    for (auto stmt : stmts)
    {
        if (erase_statement(cfunc, stmt, helper))
            ++count;
    }

    if (count > 0)
        cfunc->remove_unused_labels();

    return count;
}

}  // namespace libidacpp::hexrays
