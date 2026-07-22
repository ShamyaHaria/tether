#pragma once

#include <cstdint>
#include <set>
#include <string>
#include <vector>
#include <sys/types.h>

// Tether: a small ptrace-based debugger for Linux processes.
//
// This first slice only handles getting a tracee under control: launching
// a fresh process (fork + PTRACE_TRACEME + execve) or attaching to one
// that's already running, plus figuring out its PIE load bias so future
// address-based commands (breakpoints, memory reads) can work against the
// addresses objdump reports rather than raw runtime addresses.
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
    std::set<pid_t> threads_;
    bool process_alive_ = false;

    bool is_pie_ = false;
    uint64_t load_base_ = 0; // runtime load bias for PIE binaries, else 0

    void detectPieAndLoadBase();
    uint64_t resolveAddress(const std::string& text) const;

    void handleCommand(const std::string& line);
    void printHelp() const;
};
