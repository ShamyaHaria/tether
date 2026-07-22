#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <sys/types.h>

// A single software breakpoint. `original_data` holds the 8-byte word that
// used to live at `address` before we overwrote its low byte with 0xCC
// (INT3), so we can restore it later.
struct Breakpoint {
    uint64_t address = 0;
    long original_data = 0;
    bool enabled = false;
};

// Tether: a small ptrace-based debugger for multithreaded Linux processes.
//
// Model: at any given moment exactly one tracked thread is "in focus" and
// reported to the user at the REPL prompt. Every other tracked thread is
// always left running in the background. When a background thread hits a
// breakpoint, the kernel parks it in a ptrace-stop and the event simply
// waits until the user issues another `continue`, at which point it
// becomes the new focus thread. This avoids needing to broadcast STOP
// signals across the thread group (real "all-stop" semantics) while still
// correctly demonstrating that breakpoints are shared process-wide state:
// any thread that executes the patched instruction will trap.
class Debugger {
public:
    Debugger(std::string program_path, std::vector<std::string> program_args);

    // Fork + PTRACE_TRACEME + execve. Stops the child right after the exec
    // trap, before any user code has run.
    bool launch();

    // PTRACE_ATTACH to an already-running process.
    bool attach(pid_t pid);

    // Interactive command loop. Returns when the user quits or the tracee
    // exits.
    void repl();

private:
    std::string program_path_;
    std::vector<std::string> program_args_;

    pid_t main_pid_ = -1;    // thread-group leader of the tracee
    pid_t focus_tid_ = -1;   // thread currently reported at the REPL prompt
    std::set<pid_t> threads_;
    bool process_alive_ = false;

    bool is_pie_ = false;
    uint64_t load_base_ = 0; // runtime load bias for PIE binaries, else 0

    std::map<uint64_t, Breakpoint> breakpoints_; // keyed by runtime address

    // -- command dispatch --
    void handleCommand(const std::string& line);
    void cmdContinue();
    void cmdStep();
    void cmdBreak(const std::string& arg);
    void cmdDelete(const std::string& arg);
    void cmdRegs(const std::string& arg);
    void cmdExamine(const std::string& arg);
    void cmdThreads();
    void printHelp() const;

    // -- ptrace / process plumbing --
    void detectPieAndLoadBase();
    uint64_t resolveAddress(const std::string& text) const;

    void enableBreakpoint(Breakpoint& bp);
    void disableBreakpoint(Breakpoint& bp);
    void stepOverBreakpointIfNeeded(pid_t tid);

    // Runs the wait loop (waitpid(-1, ..., __WALL)) resuming any thread
    // whose stop isn't a breakpoint hit, until either a breakpoint fires
    // (focus_tid_ updated, function returns) or the whole process exits.
    void runEventLoopUntilStopOrExit();

    uint64_t getPC(pid_t tid) const;
    void setPC(pid_t tid, uint64_t pc);

    void printRegisters(pid_t tid) const;
    void printExit(pid_t tid, int status) const;
};
