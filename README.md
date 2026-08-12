# libidacpp - Modern C++ Extensions for IDA SDK

A modern, namespace-organized **C++20** library of high-level utilities and RAII abstractions over the
IDA Pro SDK — header-only, with clean `libidacpp::` namespacing and first-class ida-cmake integration.

**Contents:** [Features](#features) · [Modules](#modules) · [Requirements](#requirements) ·
[Quick Start](#quick-start) · [Integration](#integration) · [Usage](#usage-examples) ·
[Headless (idalib)](#headless-idalib-session) · [Project Structure](#project-structure) · [License](#license)

## Features

- **Modern C++20** - Leverages modern C++ features and best practices
- **Namespace Organized** - Clean `libidacpp::module` namespace structure
- **Header-Only** - Easy integration, no linking required (with optional compiled components)
- **ida-cmake Integration** - Seamless integration with IDA plugin build workflow
- **Type-Safe Utilities** - RAII wrappers and smart abstractions over IDA SDK

## Modules

### Core (`libidacpp::core`)
Low-level utilities and container types:
- `objcontainer_t` - RAII object container with automatic lifetime management

### Kernwin (`libidacpp::kernwin`)
UI and action management utilities:
- `actions_t` - **recommended** fluent builder for IDA actions (`add(...).enable(...).on_activate(...)`; RAII auto-unregister)
- `action_manager_t` - older, still-supported action manager
- `function_action_handler_t` - Function object-based action handlers
- `IDAICONS` - Named constants for IDA's built-in icons
- Action helper macros for lambda-based handlers

### Hexrays (`libidacpp::hexrays`)
Decompiler utilities:
- `ctreeparent_visitor_t` - Enhanced ctree visitor with parent tracking
- Selection and range utilities for decompiler views
- Default action state handlers for Hexrays widgets

### Expr (`libidacpp::expr`)
External-language helpers: `pylang()`, `find_extlang()`, `collect_extlangs()`, plus string evaluation
(`eval_expr_string()`, `eval_python_string()`)

### Callbacks (`libidacpp::callbacks`)
Bridge C callback APIs to C++ lambdas: `callback_registry`, RAII `scoped_callback`; plus `inplace_hook` —
swap a function pointer to route through a C++ lambda, with RAII unhook

### Storage (`libidacpp::storage`)
- `storage::netnode` — netnode-backed persistence: `ea_set_t` (ASLR-relative EA sets), `load_vec`/`save_vec`
- `storage::registry` — IDA registry key/value helpers: get/set string/int/bool, `remove`, string lists

### Text (`libidacpp::text`)
Small pure text utilities (no IDA SDK): `regex_replace_cb()` — regex replace with a per-match callback

### Bytes (`libidacpp::bytes`)
Instruction byte capture/paste (`code_snippet_t`) and x86/x64 NOP helpers

### Idalib (`libidacpp::idalib`) — opt-in, headless
Threaded headless-IDA session wrapper (`session_t`). **Not** included by the umbrella header;
include `<libidacpp/idalib/session.hpp>` directly. Windows requires delay-loading — see the
`libidacpp_enable_threaded_idalib()` CMake helper.

## Requirements

- **IDA SDK** with ida-cmake
- **C++20 compiler** (MSVC 2019+, GCC 10+, Clang 10+)
- **CMake 3.27+**

## Quick Start

### 1. Clone into your plugin project

```bash
cd your_plugin_project
git submodule add https://github.com/allthingsida/libidacpp.git external/libidacpp
```

### 2. Add to your CMakeLists.txt

```cmake
add_subdirectory(external/libidacpp)

ida_add_plugin(your_plugin
    SOURCES your_plugin.cpp
)

target_link_libraries(your_plugin PRIVATE libidacpp::libidacpp)
```

### 3. Use in your code

```cpp
#include <libidacpp/libidacpp.hpp>  // All modules
// or
#include <libidacpp/kernwin/kernwin.hpp>  // Specific module

using namespace libidacpp::kernwin;

// Register actions with the fluent builder. Keep the actions_t as a plugin
// member so it unregisters everything in its destructor.
actions_t actions(this);   // 'this' = your plugmod_t owner (or nullptr)

actions.add("my:action", "My Action")
    .shortcut("Ctrl-Shift-A")
    .enable(enable::always)
    .on_activate([](action_activation_ctx_t* ctx) {
        msg("Hello from libidacpp!\n");
        return 1;
    });
```

## Integration

libidacpp is header-only; pick whichever way of pulling it in suits your project. Either way it exposes the
`libidacpp::libidacpp` target, and it bootstraps the IDA SDK **only if your project hasn't already** (it is
guarded on the `ida_platform_settings` target), so when your plugin already includes ida-cmake's bootstrap,
libidacpp simply inherits it.

**As a submodule (good for local development):**

```cmake
add_subdirectory(external/libidacpp)
target_link_libraries(your_plugin PRIVATE libidacpp::libidacpp)
```

**Via FetchContent (good for pinned / out-of-tree builds and CI):**

```cmake
include(FetchContent)
FetchContent_Declare(libidacpp
    GIT_REPOSITORY https://github.com/allthingsida/libidacpp.git
    GIT_TAG main)               # or pin a specific tag/commit
FetchContent_MakeAvailable(libidacpp)

target_link_libraries(your_plugin PRIVATE libidacpp::libidacpp)
```

**Includes:** use the umbrella `<libidacpp/libidacpp.hpp>` for everything, or a single module header
(e.g. `<libidacpp/kernwin/kernwin.hpp>`) to keep compile times down. The `idalib` session is **not** pulled
by the umbrella — include `<libidacpp/idalib/session.hpp>` explicitly (see [Headless](#headless-idalib-session)).

## Usage Examples

### Action Management

```cpp
#include <libidacpp/kernwin/kernwin.hpp>

using namespace libidacpp::kernwin;

actions_t mgr(this);            // keep as a plugin member; auto-unregisters on destruction
mgr.popup_path("MyPlugin/");

mgr.add("analyze:func", "Analyze Function")
    .ida_popup()
    .enable(enable::in_disasm)
    .on_activate([](action_activation_ctx_t*) {
        ea_t ea = get_screen_ea();
        msg("Analyzing function at %a\n", ea);
        return 1;
    });

// In your ui_finish_populating_widget_popup handler:
//   mgr.on_popup(widget, popup);
```

### Hexrays Visitor with Parent Tracking

```cpp
#include <libidacpp/hexrays/hexrays.hpp>

using namespace libidacpp::hexrays;

ctreeparent_visitor_t visitor;
visitor.apply_to(*cfunc, nullptr);

// Find parent of an expression
const citem_t* parent = visitor.parent_of(expr);

// Check ancestry
if (visitor.is_ancestor_of(parent, child)) {
    // ...
}
```

### Object Container

```cpp
#include <libidacpp/core/core.hpp>

using namespace libidacpp::core;

objcontainer_t<my_object_t> objects;

// Create object (automatically managed)
auto* obj = create(objects, constructor_args...);

// Access elements
auto* first = at(objects, 0);
auto* last = back(objects);

// Automatic cleanup when container goes out of scope
```

## Headless (idalib session)

`libidacpp::idalib::session_t` runs IDA's kernel on a dedicated worker thread and marshals every SDK call
onto it, so your main thread stays responsive. `init_library()` runs on that worker (via delay-loaded
imports), which cleanly makes the worker the kernel's owner thread. It is opt-in — include it directly, and
it is not part of the umbrella header.

```cpp
#include <libidacpp/idalib/session.hpp>

using namespace libidacpp::idalib;

session_t ida;
if (!ida.start())                 // init_library() runs on the session's worker thread
    return 1;

{
    auto db = ida.open_scoped("sample.i64",
                  open_options_t().with_auto_analysis(true));
    if (!db)
        return 1;                 // db.error_message() has the reason

    // Every IDA SDK call is marshaled onto the kernel's owner thread:
    size_t nfuncs = ida.exec([]      { return get_func_qty(); });   // sync
    auto   segs   = ida.exec_async([]{ return get_segm_qty(); });   // std::future
    msg("funcs=%zu segs=%zu\n", nfuncs, segs.get());
}                                 // db auto-closes here (open_scoped is RAII)
ida.stop();                       // worker joined (the destructor also does this)
```

On Windows the threaded pattern **requires delay-loading** `ida.dll`/`idalib.dll` so nothing loads the kernel
on the main thread first. The CMake helper wires that up for you:

```cmake
ida_add_idalib(my_app TYPE EXECUTABLE SOURCES main.cpp)
target_link_libraries(my_app PRIVATE libidacpp::libidacpp)
libidacpp_enable_threaded_idalib(my_app)   # adds /DELAYLOAD:ida.dll /DELAYLOAD:idalib.dll
```

## Project Structure

```
libidacpp/
├── include/libidacpp/        # Public headers
│   ├── core/              # objcontainer_t
│   ├── kernwin/           # actions (builder + manager), IDAICONS
│   ├── hexrays/           # decompiler / ctree utilities
│   ├── expr/              # external-language helpers + string eval
│   ├── callbacks/         # C-callback bridge + inplace_hook
│   ├── storage/           # netnode + registry persistence
│   ├── text/              # small pure text utilities
│   ├── bytes/             # instruction bytes / patching
│   ├── idalib/            # headless session (opt-in)
│   └── libidacpp.hpp      # umbrella (all modules except idalib)
├── src/                   # pch_dummy.cpp (optional PCH support)
├── CMakeLists.txt
└── README.md
```

## License

Human-Origin Source License v1.0 (source-available) — see [LICENSE](LICENSE) and the per-file
`SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0` headers. Copyright (c) 2019-2026 Elias Bachaalany.

## Author

Elias Bachaalany - [@0xeb](https://github.com/0xeb)

## Contributing

Contributions welcome! This project follows modern C++ best practices and maintains consistency with the IDA SDK's patterns.
