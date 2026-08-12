// Copyright (c) 2019-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * @file kernwin.hpp
 * @brief UI and action management utilities for IDA plugins.
 *
 * This module provides modern C++ wrappers for IDA's action system:
 * - Builder-pattern API for registering actions
 * - Pre-built enable conditions for common scenarios
 * - Automatic popup menu attachment
 * - Function object-based action handlers
 *
 * @author Elias Bachaalany <elias.bachaalany@gmail.com>
 * @copyright 2019-2026
 *
 * @par Example - Modern Builder API:
 * @code
 * actions_t actions(this);
 *
 * actions.popup_path("MyPlugin/");
 *
 * actions.add("my-action", "Do Something")
 *     .shortcut("Ctrl-D")
 *     .hxe_popup()
 *     .enable(enable::when_vdui_expr)
 *     .on_activate([this](auto* ctx) {
 *         msg("Activated!\n");
 *         return 1;
 *     });
 *
 * // In event handlers:
 * actions.on_hxe_popup(widget, popup);  // hxe_populating_popup
 * actions.on_popup(widget, popup);      // ui_finish_populating_widget_popup
 * @endcode
 */
#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <kernwin.hpp>

#include <libidacpp/core/core.hpp>

namespace libidacpp::kernwin
{

//----------------------------------------------------------------------------------
/**
 * @brief Named constants for IDA's built-in GUI icons.
 *
 * Makes icon usage more readable than magic numbers.
 */
namespace IDAICONS
{
enum
{
    EYE_GLASSES_EDIT      = 43,   ///< Eye glasses with a small pencil overlay
    GREEN_DOT             = 356,  ///< Filled green circle (used to designate a disabled breakpoint)
    GREEN_PLAY_BUTTON     = 376,  ///< Green play button (start process)
    RED_DOT               = 59,   ///< Filled red circle (used to designate an active breakpoint)
    DISABLED              = 62,   ///< Circle with line through it (used to designate a disabled item)
    GRAPH_WITH_FUNC       = 77,   ///< Nodes in a graph icon with a smaller function icon overlapped on top
    YELLOW_COG_WHEEL      = 156,  ///< Yellow cog wheel
    FLASH                 = 171,  ///< Flash icon
    KEYBOARD_GRAY         = 173,  ///< A grayish keyboard
    EYE_GREEN             = 50,   ///< Eye icon with a green color
    PRINTER               = 158,  ///< Printer icon
    GRAY_X_CIRCLE         = 175,  ///< A filled gray circle with an X in it
    NOTEPAD_1             = 73,   ///< A notepad icon
    NOTEPAD_2             = 339,  ///< A notepad icon
    LIGHT_BULB            = 174,  ///< A light bulb icon
    TABLE_BLUE_CELLS_3X2  = 100,  ///< A table with blue cells (3x2)
    TABLE_WHITE_CELLS_4X2 = 418,  ///< A table with white cells (4x2)
};
}  // namespace IDAICONS

//----------------------------------------------------------------------------------
/// Function type for action update/state callbacks
using update_state_ah_t = std::function<action_state_t(action_update_ctx_t* ctx, bool is_widget)>;

/// Function type for action activation callbacks
using activate_ah_t = std::function<int(action_activation_ctx_t* ctx)>;

//----------------------------------------------------------------------------------
/**
 * @brief Function object-based action handler.
 *
 * Utility class that allows using function objects instead of inheriting from
 * action_handler_t each time.
 */
struct function_action_handler_t : public action_handler_t
{
    qstring name;                    ///< Action name
    const char* popup_path;          ///< Popup menu path for attachment
    update_state_ah_t f_update;      ///< Update/state callback
    activate_ah_t f_activate;        ///< Activation callback

    function_action_handler_t(
        const char* name,
        update_state_ah_t f_update,
        activate_ah_t f_activate,
        const char* popup_path = nullptr)
        : name(name), f_update(f_update), f_activate(f_activate), popup_path(popup_path)
    {
    }

    action_state_t idaapi update(action_update_ctx_t* ctx) override
    {
        return f_update(ctx, false);
    }

    virtual int idaapi activate(action_activation_ctx_t* ctx) override
    {
        return f_activate(ctx);
    }

    action_state_t idaapi get_state(TWidget* widget)
    {
        return f_update((action_update_ctx_t*)widget, true);
    }
};

/// Vector of action handler pointers
using function_action_handler_vec_t = std::vector<function_action_handler_t*>;

//----------------------------------------------------------------------------------
/**
 * @brief Helper macro to create update/state lambda for actions.
 *
 * @param captures Lambda capture list (e.g., [], [this], [&])
 * @param update Function body that returns action_state_t
 *
 * @example
 * @code
 * update_state_ah_t my_update = FO_ACTION_UPDATE([],
 *     return get_screen_ea() != BADADDR ? AST_ENABLE : AST_DISABLE;
 * );
 * @endcode
 */
#define FO_ACTION_UPDATE(captures, update)                             \
    captures(action_update_ctx_t* ctx, bool is_widget)->action_state_t \
    {                                                                  \
        TWidget* widget = is_widget ? (TWidget*)ctx : ctx->widget;    \
        update                                                         \
    }

/**
 * @brief Helper macro to create activation lambda for actions.
 *
 * @param captures Lambda capture list (e.g., [], [this], [&])
 *
 * @example
 * @code
 * activate_ah_t my_activate = FO_ACTION_ACTIVATE([](action_activation_ctx_t* ctx) {
 *     msg("Action activated!\n");
 *     return 1;
 * });
 * @endcode
 */
#define FO_ACTION_ACTIVATE(captures) \
    captures(action_activation_ctx_t* ctx)->int

//----------------------------------------------------------------------------------
/**
 * @brief Manages IDA action lifecycle and popup menu attachment.
 *
 * Provides simplified interface for creating and managing IDA actions with
 * automatic cleanup and popup menu integration.
 */
class action_manager_t
{
    // Action manager action handler flags:
    #define AMAHF_NONE      0x00  ///< No special flags
    #define AMAHF_HXE_POPUP 0x01  ///< Attach to Hexrays popup
    #define AMAHF_IDA_POPUP 0x04  ///< Attach to IDA popup

    core::objcontainer_t<function_action_handler_t> action_handlers;  ///< Owned action handlers
    core::objcontainer_t<qstring> popup_paths;                        ///< Owned popup path strings

    function_action_handler_vec_t want_hxe_popup;  ///< Actions for Hexrays popup
    function_action_handler_vec_t want_ida_popup;  ///< Actions for IDA popup
    const void* plg_owner;                   ///< Plugin owner
    const char* current_popup_path = nullptr;///< Current popup path for new actions

public:
    /// Default enable state for disassembly view
    update_state_ah_t default_enable_for_disasm = FO_ACTION_UPDATE([],
        return get_widget_type(widget) == BWN_DISASM ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
    );

    /// Default enable state for both disassembly and decompiler views
    update_state_ah_t default_enable_for_vd_disasm = FO_ACTION_UPDATE([],
        auto t = get_widget_type(widget);
        return (t == BWN_DISASM || t == BWN_PSEUDOCODE) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
    );

    /**
     * @brief Set popup path for subsequently created actions.
     *
     * @param path Popup menu path, or nullptr to clear
     */
    void set_popup_path(const char* path = nullptr)
    {
        if (path == nullptr)
            current_popup_path = nullptr;
        else
            current_popup_path = core::create(popup_paths, path)->c_str();
    }

    /**
     * @brief UI notification handler for IDA popup menus.
     */
    ssize_t on_ui_finish_populating_widget_popup(va_list va)
    {
        TWidget* widget          = va_arg(va, TWidget*);
        TPopupMenu* popup_handle = va_arg(va, TPopupMenu*);
        maybe_attach_to_popup(false, widget, popup_handle);
        return 0;
    }

    /**
     * @brief Hexrays notification handler for decompiler popup menus.
     */
    ssize_t on_hxe_populating_popup(va_list va)
    {
        TWidget* widget   = va_arg(va, TWidget*);
        TPopupMenu* popup = va_arg(va, TPopupMenu*);
        maybe_attach_to_popup(true, widget, popup);
        return 0;
    }

    /**
     * @brief Attach specific action to popup menu.
     *
     * @param act Action handler to attach
     * @param widget Target widget
     * @param popup_handle Popup menu handle
     * @param popuppath Menu path (uses action's path if nullptr)
     * @param flags Attachment flags
     * @return true if attached successfully
     */
    bool attach_to_popup(
        function_action_handler_t* act,
        TWidget* widget,
        TPopupMenu* popup_handle,
        const char* popuppath = nullptr,
        int flags = 0)
    {
        if (popuppath == nullptr)
            popuppath = act->popup_path;

        return attach_action_to_popup(
            widget,
            popup_handle,
            act->name.c_str(),
            popuppath,
            flags);
    }

    /**
     * @brief Maybe attach registered actions to popup menu.
     *
     * @param via_hxe true if called from Hexrays, false if from IDA
     * @param widget Target widget
     * @param popup_handle Popup menu handle
     * @param popuppath Override popup path (optional)
     * @param flags Attachment flags
     */
    void maybe_attach_to_popup(
        bool via_hxe,
        TWidget* widget,
        TPopupMenu* popup_handle,
        const char* popuppath = nullptr,
        int flags = 0)
    {
        auto& lst = via_hxe ? want_hxe_popup : want_ida_popup;
        for (auto& act : lst)
        {
            if (is_action_enabled(act->get_state(widget)))
            {
                attach_action_to_popup(
                    widget,
                    popup_handle,
                    act->name.c_str(),
                    popuppath == nullptr ? act->popup_path : popuppath,
                    flags);
            }
        }
    }

    /**
     * @brief Construct action manager.
     *
     * @param owner Plugin owner pointer (for plugmod_t)
     */
    action_manager_t(const void* owner = nullptr) : plg_owner(owner) {}

    /**
     * @brief Destructor - unregisters all managed actions.
     *
     * Without this, owned handlers are destroyed while IDA may still hold them,
     * and popup handling could dereference freed pointers.
     */
    ~action_manager_t() { remove_actions(); }

    /**
     * @brief Register and add a new action.
     *
     * @param amflags Action manager flags (AMAHF_*)
     * @param name Action name (must be unique)
     * @param label Action label (displayed in UI)
     * @param shortcut Keyboard shortcut (e.g., "Ctrl-Shift-A")
     * @param f_update Update/state callback
     * @param f_activate Activation callback
     * @param tooltip Tooltip text (optional)
     * @param icon Icon ID (use IDAICONS or -1 for none)
     * @return Pointer to created action handler, or nullptr on failure
     */
    function_action_handler_t* add_action(
        int amflags,  // one of AMAHF_* flags
        const char* name,
        const char* label,
        const char* shortcut,
        update_state_ah_t f_update,
        activate_ah_t f_activate,
        const char* tooltip = nullptr,
        int icon = -1)
    {
        bool ok = register_action(ACTION_DESC_LITERAL_PLUGMOD(
            name,
            label,
            core::create(action_handlers, name, f_update, f_activate, current_popup_path),
            plg_owner,
            shortcut,
            tooltip,
            icon));

        function_action_handler_t* act = nullptr;

        if (ok)
        {
            act = core::back(action_handlers);
            if (amflags & AMAHF_HXE_POPUP)
                want_hxe_popup.push_back(act);
            if (amflags & AMAHF_IDA_POPUP)
                want_ida_popup.push_back(act);
        }
        else
        {
            action_handlers.pop_back();
        }

        return act;
    }

    /**
     * @brief Remove and unregister all managed actions.
     */
    void remove_actions()
    {
        for (auto& ah : action_handlers)
            unregister_action(ah->name.c_str());
        // Clear the popup membership lists too: they hold raw pointers into
        // action_handlers, which we are about to free. Leaving them populated
        // would let maybe_attach_to_popup() dereference dangling handlers.
        want_hxe_popup.clear();
        want_ida_popup.clear();
        action_handlers.clear();
    }
};

//----------------------------------------------------------------------------------
// New Builder-Pattern Action API
//----------------------------------------------------------------------------------

/// Simple activation callback type (cleaner than FO_ACTION_ACTIVATE macro)
using action_callback_t = std::function<int(action_activation_ctx_t*)>;

/// Enable condition callback type
using enable_callback_t = std::function<action_state_t(TWidget*)>;

//----------------------------------------------------------------------------------
/**
 * @brief Pre-built enable conditions for common scenarios.
 */
namespace enable
{
    /// Always enabled
    inline action_state_t always(TWidget*) { return AST_ENABLE; }

    /// Enabled only in disassembly view
    inline action_state_t in_disasm(TWidget* w)
    {
        return get_widget_type(w) == BWN_DISASM ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
    }

    /// Enabled only in pseudocode view
    inline action_state_t in_pseudocode(TWidget* w)
    {
        return get_widget_type(w) == BWN_PSEUDOCODE ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
    }

    /// Enabled in both disassembly and pseudocode views
    inline action_state_t in_disasm_or_pseudocode(TWidget* w)
    {
        auto t = get_widget_type(w);
        return (t == BWN_DISASM || t == BWN_PSEUDOCODE) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
    }

#ifdef __HEXRAYS_HPP
    /// Enabled when pseudocode view has an expression selected
    /// @note Requires hexrays.hpp to be included before kernwin.hpp
    inline action_state_t when_vdui_expr(TWidget* w)
    {
        auto vu = get_widget_vdui(w);
        if (vu == nullptr)
            return AST_DISABLE_FOR_WIDGET;
        return vu->item.citype == VDI_EXPR ? AST_ENABLE : AST_DISABLE;
    }

    /// Enabled when in any decompiler view
    /// @note Requires hexrays.hpp to be included before kernwin.hpp
    inline action_state_t when_vdui(TWidget* w)
    {
        return get_widget_vdui(w) != nullptr ? AST_ENABLE : AST_DISABLE_FOR_WIDGET;
    }
#endif  // __HEXRAYS_HPP
}

//----------------------------------------------------------------------------------
// Forward declaration
class action_builder_t;

/**
 * @brief Modern action manager with builder-pattern API.
 *
 * Example usage:
 * @code
 * actions_t am(this);
 *
 * am.add("my-action", "Do Something")
 *   .shortcut("Ctrl-D")
 *   .hxe_popup()
 *   .enable(enable::when_vdui_expr)
 *   .on_activate([this](auto* ctx) {
 *       msg("Action activated!\n");
 *       return 1;
 *   });
 * @endcode
 */
class actions_t
{
    friend class action_builder_t;

    struct action_entry_t : public action_handler_t
    {
        std::string name;
        std::string popup_path;
        enable_callback_t enable_cb;
        action_callback_t activate_cb;
        bool want_hxe = false;
        bool want_ida = false;
        bool registered = false;  ///< true only after register_action() succeeded

        action_state_t idaapi update(action_update_ctx_t* ctx) override
        {
            return enable_cb ? enable_cb(ctx->widget) : AST_ENABLE;
        }

        int idaapi activate(action_activation_ctx_t* ctx) override
        {
            return activate_cb ? activate_cb(ctx) : 0;
        }

        action_state_t get_state(TWidget* w)
        {
            return enable_cb ? enable_cb(w) : AST_ENABLE;
        }
    };

    std::vector<std::unique_ptr<action_entry_t>> entries_;
    std::vector<action_entry_t*> hxe_actions_;
    std::vector<action_entry_t*> ida_actions_;
    const void* owner_ = nullptr;
    std::string current_popup_path_;

public:
    /**
     * @brief Construct actions manager.
     * @param owner Plugin owner (for plugmod_t integration)
     */
    explicit actions_t(const void* owner = nullptr) : owner_(owner) {}

    ~actions_t() { remove_all(); }

    /**
     * @brief Set popup path for subsequent actions.
     * @param path Menu path (e.g., "MyPlugin/") or empty to clear
     */
    void popup_path(const std::string& path = {}) { current_popup_path_ = path; }

    /**
     * @brief Start building a new action.
     * @param name Unique action identifier
     * @param label Display label in menus
     * @return Builder for fluent configuration
     */
    action_builder_t add(const char* name, const char* label);

    /**
     * @brief Handle IDA UI popup event.
     * Call from ui_finish_populating_widget_popup handler.
     */
    void on_popup(TWidget* widget, TPopupMenu* popup)
    {
        attach_actions(ida_actions_, widget, popup);
    }

    /**
     * @brief Handle Hex-Rays popup event.
     * Call from hxe_populating_popup handler.
     */
    void on_hxe_popup(TWidget* widget, TPopupMenu* popup)
    {
        attach_actions(hxe_actions_, widget, popup);
    }

    /**
     * @brief Remove and unregister all actions.
     */
    void remove_all()
    {
        // Only unregister actions we actually registered. A failed registration
        // (e.g. duplicate name owned by another plugin) must NOT be unregistered,
        // or we would tear down someone else's action.
        for (auto& e : entries_)
        {
            if (e->registered)
            {
                unregister_action(e->name.c_str());
                e->registered = false;
            }
        }
        entries_.clear();
        hxe_actions_.clear();
        ida_actions_.clear();
    }

private:
    void attach_actions(std::vector<action_entry_t*>& list, TWidget* w, TPopupMenu* popup)
    {
        for (auto* e : list)
        {
            if (is_action_enabled(e->get_state(w)))
            {
                attach_action_to_popup(w, popup, e->name.c_str(),
                    e->popup_path.empty() ? nullptr : e->popup_path.c_str());
            }
        }
    }

    bool register_entry(action_entry_t* e, const char* label, const char* shortcut,
                        const char* tooltip, int icon)
    {
        bool ok = register_action(ACTION_DESC_LITERAL_PLUGMOD(
            e->name.c_str(), label, e, owner_, shortcut, tooltip, icon));

        if (ok)
        {
            e->registered = true;
            if (e->want_hxe) hxe_actions_.push_back(e);
            if (e->want_ida) ida_actions_.push_back(e);
        }
        return ok;
    }
};

//----------------------------------------------------------------------------------
/**
 * @brief Fluent builder for action configuration.
 */
class action_builder_t
{
    actions_t& mgr_;
    actions_t::action_entry_t* entry_;
    std::string label_;
    std::string shortcut_;
    std::string tooltip_;
    int icon_ = -1;

public:
    action_builder_t(actions_t& mgr, const char* name, const char* label)
        : mgr_(mgr), label_(label)
    {
        auto e = std::make_unique<actions_t::action_entry_t>();
        e->name = name;
        e->popup_path = mgr_.current_popup_path_;
        e->enable_cb = enable::always;
        entry_ = e.get();
        mgr_.entries_.push_back(std::move(e));
    }

    /// Set keyboard shortcut (e.g., "Ctrl-D", "Alt-Shift-X")
    action_builder_t& shortcut(const char* sc) { shortcut_ = sc; return *this; }

    /// Set tooltip text
    action_builder_t& tooltip(const char* tt) { tooltip_ = tt; return *this; }

    /// Set icon ID (use IDAICONS constants)
    action_builder_t& icon(int id) { icon_ = id; return *this; }

    /// Add to Hex-Rays decompiler popup menu
    action_builder_t& hxe_popup() { entry_->want_hxe = true; return *this; }

    /// Add to IDA disassembly popup menu
    action_builder_t& ida_popup() { entry_->want_ida = true; return *this; }

    /// Add to both Hex-Rays and IDA popup menus
    action_builder_t& popup() { entry_->want_hxe = entry_->want_ida = true; return *this; }

    /// Set custom popup path for this action
    action_builder_t& popup_path(const char* path) { entry_->popup_path = path; return *this; }

    /// Set enable condition using pre-built function
    action_builder_t& enable(enable_callback_t cb) { entry_->enable_cb = cb; return *this; }

    /// Set enable condition using inline lambda
    template<typename F>
    action_builder_t& enable_when(F&& f) { entry_->enable_cb = std::forward<F>(f); return *this; }

    /**
     * @brief Set activation handler and finalize registration.
     * @param cb Callback invoked when action is triggered
     * @return true if the action registered successfully, false otherwise
     *          (e.g. a duplicate name already owned by another plugin).
     *
     * This must be called last - it registers the action with IDA.
     */
    bool on_activate(action_callback_t cb)
    {
        entry_->activate_cb = std::move(cb);
        return mgr_.register_entry(entry_,
            label_.c_str(),
            shortcut_.empty() ? nullptr : shortcut_.c_str(),
            tooltip_.empty() ? nullptr : tooltip_.c_str(),
            icon_);
    }
};

inline action_builder_t actions_t::add(const char* name, const char* label)
{
    return action_builder_t(*this, name, label);
}

}  // namespace libidacpp::kernwin
