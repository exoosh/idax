// Copyright (c) 2019-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * @file session.hpp
 * @brief Threaded idalib session for headless IDA operations.
 *
 * This module provides a thread-safe wrapper around IDA's idalib, allowing
 * headless IDA operations to run in a dedicated worker thread while keeping
 * the main thread responsive.
 *
 * @note WINDOWS ONLY: Requires delay-loading of both ida.dll and idalib.dll:
 * @code
 * target_link_options(app PRIVATE "/DELAYLOAD:idalib.dll" "/DELAYLOAD:ida.dll")
 * target_link_libraries(app PRIVATE delayimp.lib)
 * @endcode
 *
 * @author Elias Bachaalany <elias.bachaalany@gmail.com>
 * @copyright 2019-2026
 *
 * @par State Machine:
 * @code
 *   IDLE --start()--> STARTING --init ok--> READY --open()--> DATABASE_OPEN
 *                        |                    ^                     |
 *                        |                    +------ close() ------+
 *                        +--init fail--> STOPPED
 *   stop():  IDLE --stop()--> IDLE (no-op; a never-started session stays startable)
 *            READY / DATABASE_OPEN --stop()--> STOPPED   (once STOPPED, cannot restart)
 *   (stop() from the IDA worker thread is refused with an error)
 * @endcode
 *
 * @par Example - Basic Usage:
 * @code
 * using namespace libidacpp::idalib;
 *
 * session_t ida;
 * if (!ida.start())
 *     return 1;
 *
 * if (!ida.open("sample.i64"))
 *     return 1;
 *
 * int count = ida.exec([] { return get_func_qty(); });
 * std::cout << "Functions: " << count << std::endl;
 *
 * ida.close();
 * ida.stop();
 * @endcode
 *
 * @par Example - RAII Scoped Database:
 * @code
 * session_t ida;
 * ida.start();
 *
 * {
 *     auto guard = ida.open_scoped("sample.i64");
 *     if (!guard)
 *         return;
 *
 *     ida.exec([] { set_name(0x401000, "my_func", SN_FORCE); });
 *     guard.save();  // Explicitly save
 * }  // Auto-closes on scope exit
 * @endcode
 *
 * @par Example - Async Operations:
 * @code
 * session_t ida;
 * ida.start();
 * ida.open("sample.i64");
 *
 * auto f1 = ida.exec_async([] { return get_func_qty(); });
 * auto f2 = ida.exec_async([] { return get_segm_qty(); });
 *
 * // Do other work while IDA processes...
 *
 * std::cout << "Funcs: " << f1.get() << ", Segs: " << f2.get() << std::endl;
 * @endcode
 */
#pragma once

#include <atomic>
#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

// IDA SDK headers
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <auto.hpp>
#include <idalib.hpp>
#include <funcs.hpp>
#include <nalt.hpp>
#include <name.hpp>

// Undefine IDA macros that conflict with STL
#undef wait

namespace libidacpp::idalib
{

//----------------------------------------------------------------------------------
/**
 * @brief Result of session operations.
 *
 * A simple result type that indicates success/failure with optional error details.
 */
struct result_t
{
    bool success = false;
    int code = 0;
    std::string message;

    /** @brief Check if operation succeeded */
    operator bool() const { return success; }

    /** @brief Create a success result */
    static result_t ok()
    {
        return {true, 0, {}};
    }

    /** @brief Create an error result */
    static result_t error(int code, std::string msg)
    {
        return {false, code, std::move(msg)};
    }
};

//----------------------------------------------------------------------------------
/**
 * @brief Configuration for session initialization.
 */
struct session_config_t
{
    int argc = 0;
    char** argv = nullptr;

    /** @brief Set command-line arguments for init_library() */
    session_config_t& with_args(int argc_, char** argv_)
    {
        argc = argc_;
        argv = argv_;
        return *this;
    }
};

//----------------------------------------------------------------------------------
/**
 * @brief Options for opening a database.
 */
struct open_options_t
{
    bool auto_analysis = true;
    const char* args = nullptr;

    /** @brief Enable/disable auto-analysis after load */
    open_options_t& with_auto_analysis(bool enable)
    {
        auto_analysis = enable;
        return *this;
    }

    /** @brief Set additional IDA command-line style arguments */
    open_options_t& with_args(const char* args_)
    {
        args = args_;
        return *this;
    }
};

// Forward declaration
class session_t;

//----------------------------------------------------------------------------------
/**
 * @brief RAII guard for automatic database closing.
 *
 * When the guard goes out of scope, the database is automatically closed.
 * Use save() to mark for saving, or discard() to explicitly not save.
 *
 * @warning **Lifetime:** a guard borrows its session (non-owning). It should not
 *          outlive the session_t it came from. As a safety net the guard holds a
 *          weak lifetime token: if the session is destroyed first, the guard's
 *          close becomes a no-op instead of dereferencing a freed session — but
 *          you should still scope the guard within the session's lifetime.
 *
 * @par Example:
 * @code
 * {
 *     auto guard = ida.open_scoped("sample.i64");
 *     if (!guard)
 *         return;
 *
 *     ida.exec([] { set_name(0x401000, "func", SN_FORCE); });
 *     guard.save();  // Will save on close
 * }  // Database closed here
 * @endcode
 */
class database_guard_t
{
public:
    /** @brief Construct invalid guard */
    database_guard_t() = default;

    /** @brief Move constructor */
    database_guard_t(database_guard_t&& other) noexcept
        : result_(std::move(other.result_))
        , session_(other.session_)
        , alive_(std::move(other.alive_))
        , save_(other.save_)
        , closed_(other.closed_)
    {
        other.session_ = nullptr;
        other.closed_ = true;
    }

    /** @brief Move assignment */
    database_guard_t& operator=(database_guard_t&& other) noexcept
    {
        if (this != &other)
        {
            close_impl();
            result_ = std::move(other.result_);
            session_ = other.session_;
            alive_ = std::move(other.alive_);
            save_ = other.save_;
            closed_ = other.closed_;
            other.session_ = nullptr;
            other.closed_ = true;
        }
        return *this;
    }

    /** @brief Destructor - closes database if still open */
    ~database_guard_t()
    {
        close_impl();
    }

    // Non-copyable
    database_guard_t(const database_guard_t&) = delete;
    database_guard_t& operator=(const database_guard_t&) = delete;

    /** @brief Check if guard is valid (database opened successfully) */
    operator bool() const { return result_.success && session_ != nullptr; }

    /** @brief Get the open result */
    const result_t& result() const { return result_; }

    /** @brief Get error message if open failed */
    const std::string& error_message() const { return result_.message; }

    /** @brief Mark database to be saved on close */
    void save() { save_ = true; }

    /** @brief Mark database to NOT be saved on close */
    void discard() { save_ = false; }

    /** @brief Explicitly close the database now */
    result_t close();

private:
    // Only session_t (via open_scoped) may create a valid, token-bearing guard.
    // Private so a hand-constructed guard can't carry an already-expired token
    // (which would report valid via operator bool yet never actually close).
    friend class session_t;

    database_guard_t(result_t result, session_t* session, std::weak_ptr<void> alive)
        : result_(std::move(result))
        , session_(result_.success ? session : nullptr)
        , alive_(std::move(alive))
    {
    }

    void close_impl();

    result_t result_;
    session_t* session_ = nullptr;
    std::weak_ptr<void> alive_;   ///< expires if the owning session is destroyed first
    bool save_ = false;
    bool closed_ = false;
};

//----------------------------------------------------------------------------------
/**
 * @brief Threaded idalib session for headless IDA operations.
 *
 * Runs IDA's kernel in a dedicated worker thread, allowing any thread to
 * queue operations via exec() or exec_async(). This keeps the main thread
 * responsive while IDA processes requests.
 *
 * @note This class is non-copyable and non-movable. Each instance owns
 *       a dedicated worker thread.
 *
 * @warning On Windows, requires delay-loading of ida.dll and idalib.dll
 *          for the worker thread pattern to function correctly.
 */
class session_t
{
public:
    /** @brief Session states */
    enum class state_t
    {
        IDLE,           ///< Initial state, start() not called
        STARTING,       ///< start() in progress (worker spinning up)
        READY,          ///< Library initialized, no database open
        DATABASE_OPEN,  ///< Database is currently open
        STOPPED         ///< Worker terminated, cannot restart
    };

    //---------------------------------------------------------------------------
    /** @brief Construct an idle session */
    session_t() = default;

    /** @brief Destructor - stops worker if running */
    ~session_t() { stop(); }

    // Non-copyable, non-movable
    session_t(const session_t&) = delete;
    session_t& operator=(const session_t&) = delete;
    session_t(session_t&&) = delete;
    session_t& operator=(session_t&&) = delete;

    //---------------------------------------------------------------------------
    // Lifecycle
    //---------------------------------------------------------------------------

    /**
     * @brief Start the IDA worker thread and initialize the library.
     *
     * Mirrors: int init_library(int argc, char* argv[])
     *
     * @param config Configuration options
     * @return result_t Success or error with details
     *
     * @note Can only start once. Calling stop() on a never-started session is a no-op that leaves it
     *       IDLE and still startable; but once a *running* session has been stopped it is STOPPED and
     *       cannot restart.
     * @note WINDOWS: Requires delay-loading of ida.dll and idalib.dll.
     *       Use libidacpp_enable_threaded_idalib(target) in CMake.
     */
    result_t start(const session_config_t& config = {})
    {
        // Serialize the whole lifecycle: start() and stop() never interleave.
        std::lock_guard<std::mutex> life(lifecycle_mutex_);

        // Guard: atomically claim the single-shot start (IDLE -> STARTING).
        // Moving out of IDLE up front closes the window where two concurrent
        // start() calls could both proceed.
        state_t expected = state_t::IDLE;
        if (!state_.compare_exchange_strong(expected, state_t::STARTING))
        {
            if (expected == state_t::STOPPED)
                return result_t::error(-1, "Session stopped, cannot restart");
            return result_t::error(-1, "Session already started");
        }

#ifdef _WIN32
        // Check if IDA DLLs are already loaded - this means delay-load wasn't used
        // and init_library() will deadlock when called from worker thread
        if (GetModuleHandleA("ida.dll") != nullptr ||
            GetModuleHandleA("idalib.dll") != nullptr)
        {
            state_ = state_t::STOPPED;
            return result_t::error(-1,
                "IDA DLLs already loaded - session_t requires delay-loading. "
                "Use libidacpp_enable_threaded_idalib(target) in CMake.");
        }
#endif

        // Store config for worker thread
        config_ = config;
        shutdown_ = false;
        initialized_ = false;
        init_result_ = -1;

        thread_ = std::thread(&session_t::worker_main, this);

        // Wait for initialization to complete
        std::unique_lock<std::mutex> lock(mutex_);
        cv_init_.wait(lock, [this] { return initialized_.load(); });

        if (init_result_ != 0)
        {
            thread_.join();
            state_ = state_t::STOPPED;
            return result_t::error(init_result_,
                "init_library failed with code " + std::to_string(init_result_));
        }

        state_ = state_t::READY;
        return result_t::ok();
    }

    /**
     * @brief Stop the worker thread and cleanup.
     *
     * Closes any open database (without saving), drains already-queued tasks, and
     * terminates the worker. Idempotent; safe to call from any non-worker thread.
     *
     * @return result_t success, or an error if called from the IDA worker thread
     *         itself (a thread cannot join itself) — destroy the session off-worker.
     */
    result_t stop()
    {
        // A thread cannot join itself: refuse if called from the worker (e.g. a
        // task that tries to stop its own session). Destruction must happen off
        // the worker thread.
        if (is_ida_thread())
            return result_t::error(-1, "stop() must not be called from the IDA worker thread");

        // Serialize against start() and other stop() callers (see start()).
        std::lock_guard<std::mutex> life(lifecycle_mutex_);

        state_t current = state_.load();
        if ((current == state_t::STOPPED || current == state_t::IDLE) && !thread_.joinable())
            return result_t::ok();

        {
            std::lock_guard<std::mutex> lock(mutex_);
            shutdown_ = true;
        }
        cv_queue_.notify_one();

        if (thread_.joinable())
            thread_.join();

        state_ = state_t::STOPPED;
        return result_t::ok();
    }

    /** @brief Get current session state */
    state_t state() const { return state_.load(); }

    //---------------------------------------------------------------------------
    // Database Operations
    //---------------------------------------------------------------------------

    /**
     * @brief Open a database.
     *
     * Mirrors: int open_database(const char* file_path, bool run_auto, const char* args)
     *
     * @param path Path to IDB file or executable
     * @param opts Options for opening
     * @return result_t Success or error with details
     *
     * @note Must be in READY state. Close current database first if one is open.
     */
    result_t open(std::string_view path, const open_options_t& opts = {})
    {
        if (!is_running())
            return result_t::error(-1, "Session not started");

        // A shutdown race can reject the queued task (future holds an exception);
        // convert that back to a result_t so this API never throws.
        try
        {
            return exec([this, p = std::string(path), opts]() -> result_t {
                // Authoritative state check on the worker thread (race-free).
                state_t current = state_.load();
                if (current == state_t::DATABASE_OPEN)
                    return result_t::error(-1, "Database already open, close first");
                if (current != state_t::READY)
                    return result_t::error(-1, "Session not ready");

                int rc = open_database(p.c_str(), opts.auto_analysis, opts.args);
                if (rc != 0)
                    return result_t::error(rc, "open_database failed with code " + std::to_string(rc));

                if (opts.auto_analysis)
                    auto_wait();

                state_ = state_t::DATABASE_OPEN;
                return result_t::ok();
            });
        }
        catch (const std::exception& e)
        {
            return result_t::error(-1, e.what());
        }
    }

    /**
     * @brief Open a database with RAII guard for automatic closing.
     *
     * @param path Path to IDB file or executable
     * @param opts Options for opening
     * @return database_guard_t Guard that closes database on destruction
     *
     * @par Example:
     * @code
     * {
     *     auto guard = ida.open_scoped("sample.i64");
     *     if (!guard) {
     *         std::cerr << guard.error_message() << std::endl;
     *         return;
     *     }
     *     // Work with database...
     *     guard.save();  // Optional: mark for saving
     * }  // Database automatically closed here
     * @endcode
     */
    database_guard_t open_scoped(std::string_view path, const open_options_t& opts = {})
    {
        return database_guard_t(open(path, opts), this, alive_);
    }

    /**
     * @brief Close the current database.
     *
     * Mirrors: void close_database(bool save)
     *
     * @param save Whether to save changes before closing
     * @return result_t Success or error with details
     *
     * @note Returns to READY state after closing.
     */
    result_t close(bool save = false)
    {
        if (!is_running())
            return result_t::error(-1, "Session not started");

        try
        {
            return exec([this, save]() -> result_t {
                // Authoritative state check on the worker thread (race-free).
                if (state_.load() != state_t::DATABASE_OPEN)
                    return result_t::error(-1, "No database open");

                close_database(save);
                state_ = state_t::READY;
                return result_t::ok();
            });
        }
        catch (const std::exception& e)
        {
            return result_t::error(-1, e.what());
        }
    }

    //---------------------------------------------------------------------------
    // Execution
    //---------------------------------------------------------------------------

    /**
     * @brief Execute a callable on the IDA worker thread asynchronously.
     *
     * Returns immediately with a future holding the callable's result. The
     * return type is deduced from the callable, so no explicit template
     * argument is needed.
     *
     * - If called from the worker thread itself, the callable runs inline (a
     *   queued self-call would deadlock: the worker cannot service the queue
     *   while it is running a task).
     * - If the session is not running (not READY/DATABASE_OPEN, or shutting
     *   down), the returned future holds a std::runtime_error instead of
     *   blocking forever on a dead worker.
     *
     * @param func Nullary callable to execute
     * @return std::future of the callable's (deduced) result type
     *
     * @par Example:
     * @code
     * auto f = ida.exec_async([] { return get_func_qty(); });  // std::future<size_t>
     * @endcode
     */
    template <typename F>
    auto exec_async(F&& func) -> std::future<std::invoke_result_t<std::decay_t<F>&>>
    {
        // The callable is stored and invoked as an lvalue (both inline and from
        // the queue), so deduce its result as an lvalue invocation.
        using R = std::invoke_result_t<std::decay_t<F>&>;

        auto promise = std::make_shared<std::promise<R>>();
        std::future<R> future = promise->get_future();

        // Re-entrancy: already on the worker thread -> run inline (see above).
        if (is_ida_thread())
        {
            try
            {
                if constexpr (std::is_void_v<R>) { func(); promise->set_value(); }
                else { promise->set_value(func()); }
            }
            catch (...) { promise->set_exception(std::current_exception()); }
            return future;
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);

            state_t s = state_.load();
            if (shutdown_ || (s != state_t::READY && s != state_t::DATABASE_OPEN))
            {
                promise->set_exception(std::make_exception_ptr(
                    std::runtime_error("Session not running")));
                return future;
            }

            queue_.push([func = std::forward<F>(func), promise]() mutable {
                try
                {
                    if constexpr (std::is_void_v<R>) { func(); promise->set_value(); }
                    else { promise->set_value(func()); }
                }
                catch (...) { promise->set_exception(std::current_exception()); }
            });
        }
        cv_queue_.notify_one();

        return future;
    }

    /**
     * @brief Execute a callable on the IDA worker thread synchronously.
     *
     * Blocks until the callable completes and returns its (deduced) result.
     * Callable from any thread; runs inline if already on the worker thread.
     * If the session is not running, the underlying future throws.
     *
     * @param func Nullary callable to execute
     * @return The callable's result
     *
     * @par Example:
     * @code
     * size_t count = ida.exec([] { return get_func_qty(); });
     * @endcode
     */
    template <typename F>
    auto exec(F&& func) -> std::invoke_result_t<std::decay_t<F>&>
    {
        return exec_async(std::forward<F>(func)).get();
    }

    //---------------------------------------------------------------------------
    // Utilities
    //---------------------------------------------------------------------------

    /** @brief Check if current thread is the IDA worker thread */
    bool is_ida_thread() const
    {
        return current_session_ == this;
    }

    /** @brief Check if a database is currently open */
    bool is_database_open() const
    {
        return state_.load() == state_t::DATABASE_OPEN;
    }

    /** @brief Check if the session is running (READY or DATABASE_OPEN) */
    bool is_running() const
    {
        state_t s = state_.load();
        return s == state_t::READY || s == state_t::DATABASE_OPEN;
    }

    /** @brief IDA library version info */
    struct version_info_t
    {
        int major = 0;
        int minor = 0;
        int build = 0;
    };

    /** @brief Get IDA library version */
    version_info_t library_version()
    {
        if (!is_running())
            return version_info_t{};
        try
        {
            return exec([] {
                version_info_t v;
                get_library_version(v.major, v.minor, v.build);
                return v;
            });
        }
        catch (const std::exception&)
        {
            return version_info_t{};  // shutdown race: no version available
        }
    }

private:
    void worker_main()
    {
        current_session_ = this;  // mark this thread as our worker (thread-local; no cross-thread race)

        // Initialize IDA (DLLs load here via delay-load)
        init_result_ = init_library(config_.argc, config_.argv);

        if (init_result_ != 0)
        {
            initialized_ = true;
            cv_init_.notify_one();
            return;
        }

        initialized_ = true;
        cv_init_.notify_one();

        // Process the queue. On shutdown, drain already-accepted tasks (so no
        // caller's future ever hangs), then exit once the queue is empty. New
        // tasks are refused by exec_async() the moment shutdown_ is set, so the
        // queue is guaranteed to run dry.
        for (;;)
        {
            std::function<void()> task;

            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_queue_.wait(lock, [this] {
                    return !queue_.empty() || shutdown_;
                });

                if (queue_.empty())
                {
                    if (shutdown_)
                        break;
                    continue;
                }

                task = std::move(queue_.front());
                queue_.pop();
            }

            task();
        }

        // Cleanup: close database if still open
        if (state_.load() == state_t::DATABASE_OPEN)
            close_database(false);
    }

private:
    std::thread thread_;
    mutable std::mutex mutex_;
    std::mutex lifecycle_mutex_;  ///< serializes start()/stop() so their state+thread transitions never interleave

    // Per-thread marker for THIS session's worker. Set by the worker in
    // worker_main() and read by is_ida_thread() on the CALLING thread, so it is
    // never accessed across threads (avoids a data race on a shared thread id).
    inline static thread_local session_t* current_session_ = nullptr;
    std::condition_variable cv_queue_;
    std::condition_variable cv_init_;
    std::queue<std::function<void()>> queue_;

    std::atomic<state_t> state_{state_t::IDLE};
    std::atomic<bool> initialized_{false};
    std::atomic<bool> shutdown_{false};
    int init_result_ = -1;

    session_config_t config_;

    // Lifetime token handed (as a weak_ptr) to database_guard_t so a guard that
    // outlives its session degrades to a safe no-op instead of using a freed this.
    std::shared_ptr<void> alive_ = std::make_shared<char>();
};

//----------------------------------------------------------------------------------
// database_guard_t implementation (needs session_t definition)
//----------------------------------------------------------------------------------

inline result_t database_guard_t::close()
{
    if (closed_ || !session_)
        return result_t::ok();

    closed_ = true;
    if (alive_.expired())  // owning session already destroyed -> nothing to close
        return result_t::error(-1, "session no longer alive");
    return session_->close(save_);
}

inline void database_guard_t::close_impl()
{
    // Called from the destructor and move-assignment, so it must not throw.
    // Skip entirely if the owning session was destroyed first (token expired);
    // otherwise close (a no-op-with-error if the session isn't running).
    if (!closed_ && session_)
    {
        closed_ = true;
        if (!alive_.expired())
        {
            try { session_->close(save_); } catch (...) { /* dtor must not throw */ }
        }
    }
}

}  // namespace libidacpp::idalib
