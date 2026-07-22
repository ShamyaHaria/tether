#include "debugger.hpp"

#include <cstring>
#include <elf.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

Debugger::Debugger(std::string program_path, std::vector<std::string> program_args)
    : program_path_(std::move(program_path)), program_args_(std::move(program_args)) {}

// ---------------------------------------------------------------------
// process startup
// ---------------------------------------------------------------------

bool Debugger::launch() {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return false;
    }

    if (pid == 0) {
        // Child: become traceable, then exec the target.
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
            perror("ptrace(TRACEME)");
            _exit(127);
        }
        // Disable ASLR so breakpoint addresses are reproducible run to run.
        personality(ADDR_NO_RANDOMIZE);

        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(program_path_.c_str()));
        for (auto& a : program_args_) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);

        execv(program_path_.c_str(), argv.data());
        perror("execv"); // only reached on failure
        _exit(127);
    }

    // Parent
    main_pid_ = pid;

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return false;
    }
    if (!WIFSTOPPED(status)) {
        std::cerr << "child did not stop as expected after exec\n";
        return false;
    }

    threads_.insert(pid);
    process_alive_ = true;
    detectPieAndLoadBase();

    std::cout << "Launched pid " << pid << " (" << program_path_ << ")"
              << (is_pie_ ? " [PIE, load base 0x" : " [non-PIE base 0x")
              << std::hex << load_base_ << std::dec << "]\n";
    return true;
}

bool Debugger::attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0) {
        perror("ptrace(ATTACH)");
        return false;
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return false;
    }

    main_pid_ = pid;
    threads_.insert(pid);
    process_alive_ = true;

    char link[64];
    snprintf(link, sizeof(link), "/proc/%d/exe", pid);
    char resolved[4096];
    ssize_t n = readlink(link, resolved, sizeof(resolved) - 1);
    if (n > 0) {
        resolved[n] = '\0';
        program_path_ = resolved;
    }

    detectPieAndLoadBase();
    std::cout << "Attached to pid " << pid << " (" << program_path_ << ")"
              << (is_pie_ ? " [PIE, load base 0x" : " [non-PIE base 0x")
              << std::hex << load_base_ << std::dec << "]\n";
    return true;
}

void Debugger::detectPieAndLoadBase() {
    is_pie_ = false;
    load_base_ = 0;

    Elf64_Ehdr ehdr{};
    {
        std::ifstream f(program_path_, std::ios::binary);
        if (!f) return;
        f.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));
        if (!f || memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) return;
    }
    is_pie_ = (ehdr.e_type == ET_DYN);
    if (!is_pie_) return;

    char resolved[4096];
    if (!realpath(program_path_.c_str(), resolved)) return;

    std::ifstream maps("/proc/" + std::to_string(main_pid_) + "/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(resolved) == std::string::npos) continue;
        auto dash = line.find('-');
        if (dash == std::string::npos) continue;
        load_base_ = std::stoull(line.substr(0, dash), nullptr, 16);
        break;
    }
}

uint64_t Debugger::resolveAddress(const std::string& text) const {
    std::string s = text;
    if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) s = s.substr(2);
    uint64_t off = std::stoull(s, nullptr, 16);
    return is_pie_ ? off + load_base_ : off;
}

// ---------------------------------------------------------------------
// REPL (breakpoints/registers/stepping arrive in later commits)
// ---------------------------------------------------------------------

void Debugger::printHelp() const {
    std::cout <<
        "commands:\n"
        "  help | h                  show this message\n"
        "  quit | q                  detach/kill and exit\n"
        "(breakpoints, registers, and stepping land in upcoming commits)\n";
}

void Debugger::handleCommand(const std::string& line) {
    std::istringstream iss(line);
    std::string cmd;
    iss >> cmd;
    if (cmd.empty()) return;

    if (cmd == "help" || cmd == "h") {
        printHelp();
    } else if (cmd == "quit" || cmd == "q") {
        if (process_alive_) ptrace(PTRACE_KILL, main_pid_, nullptr, nullptr);
        process_alive_ = false;
    } else {
        std::cout << "unknown command '" << cmd << "' (try 'help')\n";
    }
}

void Debugger::repl() {
    std::cout << "tether -- type 'help' for commands\n";
    std::string line;
    std::cout << "(tether) " << std::flush;
    while (process_alive_ && std::getline(std::cin, line)) {
        handleCommand(line);
        if (!process_alive_) break;
        std::cout << "(tether) " << std::flush;
    }
}
