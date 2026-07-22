#include "debugger.hpp"

#include <cerrno>
#include <cstring>
#include <elf.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/user.h>
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
    focus_tid_ = pid;

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
    focus_tid_ = pid;
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
// registers / memory
// ---------------------------------------------------------------------

uint64_t Debugger::getPC(pid_t tid) const {
    struct user_regs_struct regs{};
    ptrace(PTRACE_GETREGS, tid, nullptr, &regs);
    return regs.rip;
}

void Debugger::setPC(pid_t tid, uint64_t pc) {
    struct user_regs_struct regs{};
    ptrace(PTRACE_GETREGS, tid, nullptr, &regs);
    regs.rip = pc;
    ptrace(PTRACE_SETREGS, tid, nullptr, &regs);
}

void Debugger::printRegisters(pid_t tid) const {
    struct user_regs_struct regs{};
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) < 0) {
        perror("PTRACE_GETREGS");
        return;
    }
    auto hx = [](unsigned long long v) {
        std::ostringstream o;
        o << "0x" << std::hex << std::setfill('0') << std::setw(16) << v;
        return o.str();
    };
    std::cout << "-- registers (thread " << tid << ") --\n";
    std::cout << "rip " << hx(regs.rip) << "   rsp " << hx(regs.rsp)
               << "   rbp " << hx(regs.rbp) << "\n";
    std::cout << "rax " << hx(regs.rax) << "   rbx " << hx(regs.rbx)
               << "   rcx " << hx(regs.rcx) << "\n";
    std::cout << "rdx " << hx(regs.rdx) << "   rsi " << hx(regs.rsi)
               << "   rdi " << hx(regs.rdi) << "\n";
    std::cout << "r8  " << hx(regs.r8)  << "   r9  " << hx(regs.r9)
               << "   r10 " << hx(regs.r10) << "\n";
    std::cout << "r11 " << hx(regs.r11) << "   r12 " << hx(regs.r12)
               << "   r13 " << hx(regs.r13) << "\n";
    std::cout << "r14 " << hx(regs.r14) << "   r15 " << hx(regs.r15)
               << "   eflags " << hx(regs.eflags) << "\n";
}

void Debugger::printExit(pid_t tid, int status) const {
    if (WIFEXITED(status)) {
        std::cout << "[thread " << tid << "] exited with status " << WEXITSTATUS(status) << "\n";
    } else if (WIFSIGNALED(status)) {
        std::cout << "[thread " << tid << "] killed by signal " << WTERMSIG(status) << "\n";
    }
}

// ---------------------------------------------------------------------
// breakpoints
// ---------------------------------------------------------------------
//
// NOTE: PTRACE_PEEKTEXT/POKETEXT require their target *tid* to currently be
// in a ptrace-stop. focus_tid_ is always the thread guaranteed to be
// stopped whenever the REPL has control, so memory ops target that rather
// than main_pid_ (which matters once multiple threads are in the picture).

void Debugger::enableBreakpoint(Breakpoint& bp) {
    errno = 0;
    long orig = ptrace(PTRACE_PEEKTEXT, focus_tid_, reinterpret_cast<void*>(bp.address), nullptr);
    if (orig == -1 && errno != 0) {
        perror("PTRACE_PEEKTEXT");
        return;
    }
    bp.original_data = orig;
    long patched = (orig & ~0xffL) | 0xCC;
    if (ptrace(PTRACE_POKETEXT, focus_tid_, reinterpret_cast<void*>(bp.address),
               reinterpret_cast<void*>(patched)) < 0) {
        perror("PTRACE_POKETEXT");
        return;
    }
    bp.enabled = true;
}

void Debugger::disableBreakpoint(Breakpoint& bp) {
    if (!bp.enabled) return;
    ptrace(PTRACE_POKETEXT, focus_tid_, reinterpret_cast<void*>(bp.address),
           reinterpret_cast<void*>(bp.original_data));
    bp.enabled = false;
}

void Debugger::stepOverBreakpointIfNeeded(pid_t tid) {
    uint64_t pc = getPC(tid);
    auto it = breakpoints_.find(pc);
    if (it == breakpoints_.end() || !it->second.enabled) return;

    disableBreakpoint(it->second);
    ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr);
    int status = 0;
    waitpid(tid, &status, 0);
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        threads_.erase(tid);
        if (tid == main_pid_) {
            process_alive_ = false;
            printExit(tid, status);
        }
        return;
    }
    enableBreakpoint(it->second);
}

// ---------------------------------------------------------------------
// REPL
// ---------------------------------------------------------------------

void Debugger::printHelp() const {
    std::cout <<
        "commands:\n"
        "  continue | c              resume the focus thread\n"
        "  step | s                  single-step one instruction\n"
        "  break | b <addr>          set a breakpoint (hex address)\n"
        "  delete | d <addr>         remove a breakpoint\n"
        "  regs | r                  print registers of the focus thread\n"
        "  examine | x <addr> [n]    dump n 8-byte words starting at addr (default 4)\n"
        "  help | h                  show this message\n"
        "  quit | q                  detach/kill and exit\n"
        "(multithreaded tracing lands in an upcoming commit)\n";
}

void Debugger::cmdContinue() {
    // Single-thread version for now: this only waits on focus_tid_ directly.
    // Multithreaded tracing (waitpid(-1, ..., __WALL) across every tracked
    // thread) is added in a later commit.
    if (!process_alive_) {
        std::cout << "no process running\n";
        return;
    }
    stepOverBreakpointIfNeeded(focus_tid_);
    if (!process_alive_) return;
    if (ptrace(PTRACE_CONT, focus_tid_, nullptr, nullptr) < 0) {
        perror("PTRACE_CONT");
        return;
    }

    int status = 0;
    if (waitpid(focus_tid_, &status, 0) < 0) {
        perror("waitpid");
        return;
    }
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        process_alive_ = false;
        printExit(focus_tid_, status);
        return;
    }
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        uint64_t pc = getPC(focus_tid_);
        uint64_t maybe_bp = pc - 1;
        auto it = breakpoints_.find(maybe_bp);
        if (it != breakpoints_.end() && it->second.enabled) {
            setPC(focus_tid_, maybe_bp);
            std::cout << "Breakpoint hit at 0x" << std::hex << maybe_bp << std::dec
                      << " (thread " << focus_tid_ << ")\n";
        }
    }
}

void Debugger::cmdStep() {
    if (!process_alive_) {
        std::cout << "no process running\n";
        return;
    }
    uint64_t pc = getPC(focus_tid_);
    auto it = breakpoints_.find(pc);
    bool had_bp = (it != breakpoints_.end() && it->second.enabled);
    if (had_bp) disableBreakpoint(it->second);

    ptrace(PTRACE_SINGLESTEP, focus_tid_, nullptr, nullptr);
    int status = 0;
    waitpid(focus_tid_, &status, 0);

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        threads_.erase(focus_tid_);
        process_alive_ = false;
        printExit(focus_tid_, status);
        return;
    }
    if (had_bp) enableBreakpoint(it->second);

    std::cout << "stepped to 0x" << std::hex << getPC(focus_tid_) << std::dec
              << " (thread " << focus_tid_ << ")\n";
}

void Debugger::cmdBreak(const std::string& arg) {
    if (arg.empty()) {
        std::cout << "usage: break <addr>\n";
        return;
    }
    uint64_t addr;
    try {
        addr = resolveAddress(arg);
    } catch (...) {
        std::cout << "invalid address: " << arg << "\n";
        return;
    }
    if (breakpoints_.count(addr)) {
        std::cout << "breakpoint already set at 0x" << std::hex << addr << std::dec << "\n";
        return;
    }
    Breakpoint bp;
    bp.address = addr;
    if (process_alive_) enableBreakpoint(bp);
    breakpoints_[addr] = bp;
    std::cout << "breakpoint set at 0x" << std::hex << addr << std::dec << "\n";
}

void Debugger::cmdDelete(const std::string& arg) {
    if (arg.empty()) {
        std::cout << "usage: delete <addr>\n";
        return;
    }
    uint64_t addr;
    try {
        addr = resolveAddress(arg);
    } catch (...) {
        std::cout << "invalid address: " << arg << "\n";
        return;
    }
    auto it = breakpoints_.find(addr);
    if (it == breakpoints_.end()) {
        std::cout << "no breakpoint at 0x" << std::hex << addr << std::dec << "\n";
        return;
    }
    if (process_alive_) disableBreakpoint(it->second);
    breakpoints_.erase(it);
    std::cout << "removed breakpoint at 0x" << std::hex << addr << std::dec << "\n";
}

void Debugger::cmdRegs(const std::string& /*arg*/) {
    if (!process_alive_) {
        std::cout << "no process running\n";
        return;
    }
    printRegisters(focus_tid_);
}

void Debugger::cmdExamine(const std::string& arg) {
    if (!process_alive_) {
        std::cout << "no process running\n";
        return;
    }
    std::istringstream iss(arg);
    std::string addr_tok;
    int count = 4;
    iss >> addr_tok;
    if (iss >> count) { /* optional second token overrides count */ }
    if (addr_tok.empty()) {
        std::cout << "usage: examine <addr> [count]\n";
        return;
    }
    uint64_t addr;
    try {
        addr = resolveAddress(addr_tok);
    } catch (...) {
        std::cout << "invalid address: " << addr_tok << "\n";
        return;
    }
    for (int i = 0; i < count; ++i) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKTEXT, focus_tid_,
                            reinterpret_cast<void*>(addr + i * 8), nullptr);
        if (word == -1 && errno != 0) {
            perror("PTRACE_PEEKTEXT");
            return;
        }
        std::cout << "0x" << std::hex << (addr + i * 8) << ": 0x" << std::setfill('0')
                  << std::setw(16) << static_cast<unsigned long>(word) << std::dec
                  << std::setfill(' ') << "\n";
    }
}

void Debugger::handleCommand(const std::string& line) {
    std::istringstream iss(line);
    std::string cmd;
    iss >> cmd;
    if (cmd.empty()) return;
    std::string arg;
    std::getline(iss, arg);
    // trim a single leading space left over from the >> extraction
    if (!arg.empty() && arg.front() == ' ') arg.erase(0, 1);

    if (cmd == "continue" || cmd == "c") {
        cmdContinue();
    } else if (cmd == "step" || cmd == "s") {
        cmdStep();
    } else if (cmd == "break" || cmd == "b") {
        cmdBreak(arg);
    } else if (cmd == "delete" || cmd == "d") {
        cmdDelete(arg);
    } else if (cmd == "regs" || cmd == "r") {
        cmdRegs(arg);
    } else if (cmd == "examine" || cmd == "x") {
        cmdExamine(arg);
    } else if (cmd == "help" || cmd == "h") {
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
