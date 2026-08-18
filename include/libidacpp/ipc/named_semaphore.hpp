// Copyright (c) 2019-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * @file named_semaphore.hpp
 * @brief Cross-platform named semaphores + a waiter thread (no IDA SDK).
 *
 * Two small primitives for signaling between processes:
 *   - @ref libidacpp::ipc::named_semaphore_t — a named, cross-process semaphore
 *     (Win32 named semaphore / POSIX @c sem_open). One side @c create()s it, the
 *     other @c open()s it by the same base name; platform naming rules (POSIX
 *     leading slash, macOS length limit) are applied internally so both sides
 *     agree by construction.
 *   - @ref libidacpp::ipc::semaphore_waiter_t — owns a named semaphore plus a
 *     background thread that invokes a callback every time the semaphore is
 *     posted (from this or another process).
 *
 * @author Elias Bachaalany <elias.bachaalany@gmail.com>
 * @copyright 2019-2026
 *
 * @par Example:
 * @code
 * // Waiter side (e.g. a plugin):
 * libidacpp::ipc::semaphore_waiter_t waiter;
 * waiter.start("myplugin_0badf00d", []() { do_the_work(); });
 *
 * // Signaler side (another process):
 * libidacpp::ipc::named_semaphore_t sem;
 * if (sem.open("myplugin_0badf00d"))
 *     sem.post();
 * @endcode
 *
 * @note Not auto-included by the umbrella header — it pulls in platform headers
 *       (@c <windows.h> / @c <semaphore.h> …); include from a .cpp when needed.
 */
#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <thread>

#if defined(_WIN32)
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
#else
    #include <cerrno>
    #include <ctime>
    #include <fcntl.h>
    #include <semaphore.h>
    #include <sys/stat.h>
    #include <unistd.h>
#endif

namespace libidacpp::ipc
{

//------------------------------------------------------------------------------
/// Result of a @ref named_semaphore_t::wait call.
enum class wait_result_t
{
    signaled,   ///< The semaphore was posted.
    timeout,    ///< The timeout elapsed without a post.
    error       ///< The wait failed (invalid semaphore, ...).
};

//------------------------------------------------------------------------------
/**
 * @brief A named, cross-process semaphore.
 *
 * The @p base_name passed to @ref create / @ref open is a plain identifier such
 * as @c "myplugin_0badf00d" — no slashes. Platform naming is handled inside:
 * POSIX prepends the required leading @c '/', and the name length is validated
 * against macOS's tight @c sem_open limit (31 chars including the slash).
 *
 * @c create() is the owner side: it makes the semaphore (initial count 0) and,
 * on POSIX, unlinks any stale semaphore of the same name first — so a previous
 * process killed with @c kill @c -9 can never wedge the name. @c close() (and
 * the destructor) unlink the name again on the owner side.
 *
 * @c open() is the signaler side: it attaches to an existing semaphore and
 * fails if there is none.
 */
class named_semaphore_t
{
public:
    named_semaphore_t() = default;
    named_semaphore_t(const named_semaphore_t &) = delete;
    named_semaphore_t &operator=(const named_semaphore_t &) = delete;

    ~named_semaphore_t()
    {
        close();
    }

    /// Create the semaphore (owner side, initial count 0).
    bool create(const char *base_name)
    {
        close();
        char name[64];
        if (!make_platform_name(base_name, name, sizeof(name)))
            return false;

#if defined(_WIN32)
        h_ = CreateSemaphoreA(nullptr, 0, LONG_MAX, name);
        if (h_ == nullptr)
            return false;
        // ERROR_ALREADY_EXISTS is acceptable: we attached to the existing
        // semaphore (same behavior as IDA's named qsem_create).
#else
        // Unlink any stale semaphore first (a previous owner may have been
        // killed without cleanup). ENOENT is the normal case.
        sem_unlink(name);
        sem_ = sem_open(name, O_CREAT | O_EXCL, 0600, 0);
        if (sem_ == SEM_FAILED)
            return false;
        platform_name_ = name;
#endif
        owner_ = true;
        return true;
    }

    /// Attach to an existing semaphore (signaler side). Fails if absent.
    bool open(const char *base_name)
    {
        close();
        char name[64];
        if (!make_platform_name(base_name, name, sizeof(name)))
            return false;

#if defined(_WIN32)
        h_ = OpenSemaphoreA(SEMAPHORE_MODIFY_STATE | SYNCHRONIZE, FALSE, name);
        if (h_ == nullptr)
            return false;
#else
        sem_ = sem_open(name, 0);
        if (sem_ == SEM_FAILED)
            return false;
#endif
        owner_ = false;
        return true;
    }

    /// Increment the semaphore (wake one waiter).
    bool post()
    {
#if defined(_WIN32)
        return h_ != nullptr && ReleaseSemaphore(h_, 1, nullptr) != 0;
#else
        return sem_ != SEM_FAILED && sem_post(sem_) == 0;
#endif
    }

    /**
     * @brief Wait for a post.
     * @param timeout_ms -1 to block indefinitely, else a timeout in ms.
     *
     * Platform notes: infinite waits map to @c WaitForSingleObject(INFINITE) /
     * @c sem_wait (retried on @c EINTR — the host may install signal handlers).
     * Finite waits use @c sem_timedwait on Linux; macOS has no
     * @c sem_timedwait, so they poll @c sem_trywait every 10 ms against a
     * steady-clock deadline (worst-case ~10 ms overshoot).
     */
    wait_result_t wait(int timeout_ms = -1)
    {
#if defined(_WIN32)
        if (h_ == nullptr)
            return wait_result_t::error;
        DWORD rc = WaitForSingleObject(h_, timeout_ms < 0 ? INFINITE : (DWORD)timeout_ms);
        if (rc == WAIT_OBJECT_0)
            return wait_result_t::signaled;
        if (rc == WAIT_TIMEOUT)
            return wait_result_t::timeout;
        return wait_result_t::error;
#else
        if (sem_ == SEM_FAILED)
            return wait_result_t::error;

        if (timeout_ms < 0)
        {
            for (;;)
            {
                if (sem_wait(sem_) == 0)
                    return wait_result_t::signaled;
                if (errno != EINTR)
                    return wait_result_t::error;
            }
        }

    #if defined(__APPLE__)
        // macOS: no sem_timedwait; poll sem_trywait against a deadline.
        const auto deadline = std::chrono::steady_clock::now()
                            + std::chrono::milliseconds(timeout_ms);
        for (;;)
        {
            if (sem_trywait(sem_) == 0)
                return wait_result_t::signaled;
            if (errno != EAGAIN && errno != EINTR)
                return wait_result_t::error;
            if (std::chrono::steady_clock::now() >= deadline)
                return wait_result_t::timeout;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    #else
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec  += timeout_ms / 1000;
        ts.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
        if (ts.tv_nsec >= 1000000000L)
        {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000L;
        }
        for (;;)
        {
            if (sem_timedwait(sem_, &ts) == 0)
                return wait_result_t::signaled;
            if (errno == ETIMEDOUT)
                return wait_result_t::timeout;
            if (errno != EINTR)
                return wait_result_t::error;
        }
    #endif
#endif
    }

    /// Close the semaphore; the owner side also unlinks the name (POSIX).
    void close()
    {
#if defined(_WIN32)
        if (h_ != nullptr)
        {
            CloseHandle(h_);
            h_ = nullptr;
        }
#else
        if (sem_ != SEM_FAILED)
        {
            sem_close(sem_);
            sem_ = SEM_FAILED;
        }
        if (owner_ && !platform_name_.empty())
        {
            sem_unlink(platform_name_.c_str());
            platform_name_.clear();
        }
#endif
        owner_ = false;
    }

    /// Is a semaphore currently attached?
    bool valid() const
    {
#if defined(_WIN32)
        return h_ != nullptr;
#else
        return sem_ != SEM_FAILED;
#endif
    }

private:
    // Apply platform naming rules to a base name like "myplugin_0badf00d":
    // POSIX prepends '/'; the base must fit macOS's sem_open limit of 31 chars
    // including the leading slash (PSEMNAMLEN) — enforced on all platforms so
    // names stay portable.
    static bool make_platform_name(const char *base, char *out, size_t out_size)
    {
        if (base == nullptr || *base == '\0')
            return false;
        size_t len = strlen(base);
        if (len > 30)   // 30 + '/' = macOS's 31-char limit
            return false;
#if defined(_WIN32)
        if (len + 1 > out_size)
            return false;
        memcpy(out, base, len + 1);
#else
        if (len + 2 > out_size)
            return false;
        out[0] = '/';
        memcpy(out + 1, base, len + 1);
#endif
        return true;
    }

#if defined(_WIN32)
    HANDLE h_ = nullptr;
#else
    sem_t *sem_ = SEM_FAILED;
    std::string platform_name_;   // kept for the owner-side sem_unlink
#endif
    bool owner_ = false;
};

//------------------------------------------------------------------------------
/**
 * @brief Owns a named semaphore and a background thread that runs a callback
 *        each time the semaphore is posted (from this or another process).
 *
 * @c start() creates the semaphore (owner side) and spawns the thread;
 * @c stop() (and the destructor) wake the thread, join it, and release the
 * semaphore. The callback runs on the background thread.
 */
class semaphore_waiter_t
{
public:
    using callback_t = std::function<void()>;

    semaphore_waiter_t() = default;
    semaphore_waiter_t(const semaphore_waiter_t &) = delete;
    semaphore_waiter_t &operator=(const semaphore_waiter_t &) = delete;

    ~semaphore_waiter_t()
    {
        stop();
    }

    /// Create the semaphore and start the waiter thread.
    bool start(const char *base_name, callback_t cb)
    {
        stop();
        if (!sem_.create(base_name))
            return false;

        cb_ = std::move(cb);
        stop_.store(false);
        thread_ = std::thread([this]()
        {
            while (sem_.wait(-1) == wait_result_t::signaled)
            {
                if (stop_.load())
                    break;
                cb_();
            }
        });
        return true;
    }

    /// Post the semaphore from this process (wakes the callback).
    void signal()
    {
        if (sem_.valid())
            sem_.post();
    }

    /// Stop the waiter thread and release the semaphore.
    void stop()
    {
        if (!thread_.joinable())
            return;
        stop_.store(true);
        sem_.post();
        thread_.join();
        sem_.close();
    }

    /// Is the waiter running?
    bool running() const
    {
        return thread_.joinable();
    }

private:
    named_semaphore_t sem_;
    std::thread thread_;
    std::atomic<bool> stop_{false};
    callback_t cb_;
};

}  // namespace libidacpp::ipc
