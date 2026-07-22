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

// Tether: a small ptrace-based debugger for Linux processes.
//
// This slice adds breakpoints, register inspection, and memory reads on
// top of the process-control layer from the previous commit.
class Debugger {
public:
    Debugger(std::string program_path, std::vector<std::string> program_args);

    // Fork + PTRACE_TRACEME + execve. Stops the child right after the exec
    // trap, before any user code has run.
    bool launch();

    // PTRACE_ATTACH to an already-running process.
    bool attach(pid_t pid);

    // Interactive command loop. Returns when the user quits.
    void repl();

private:
    std::string program_path_;
    std::vector<std::string> program_args_;

    pid_t main_pid_ = -1;
    pid_t focus_tid_ = -1;  // the thread currently reported at the REPL prompt
    std::set<pid_t> threads_;
    bool process_alive_ = false;

    bool is_pie_ = false;
    uint64_t load_base_ = 0; // runtime load bias for PIE binaries, else 0

    std::map<uint64_t, Breakpoint> breakpoints_; // keyed by runtime address

    void detectPieAndLoadBase();
    uint64_t resolveAddress(const std::string& text) const;

    void handleCommand(const std::string& line);
    void printHelp() const;

    void cmdContinue();
    void cmdBreak(const std::string& arg);
    void cmdDelete(const std::string& arg);
    void cmdRegs(const std::string& arg);
    void cmdExamine(const std::string& arg);

    void enableBreakpoint(Breakpoint& bp);
    void disableBreakpoint(Breakpoint& bp);
    void stepOverBreakpointIfNeeded(pid_t tid);

    uint64_t getPC(pid_t tid) const;
    void setPC(pid_t tid, uint64_t pc);
    void printRegisters(pid_t tid) const;
    void printExit(pid_t tid, int status) const;
};
