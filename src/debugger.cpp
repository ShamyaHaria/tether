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

namespace {

std::vector<std::string> split(const std::string& line) {
    std::istringstream iss(line);
    std::vector<std::string> tokens;
    std::string tok;
    while (iss >> tok) tokens.push_back(tok);
    return tokens;
}

} // namespace

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

    // Auto-attach cloned threads; kill the tracee if we ourselves die.
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACECLONE | PTRACE_O_EXITKILL);

    threads_.insert(pid);
    process_alive_ = true;
    detectPieAndLoadBase();
    loadSymbolTable();

    std::cout << "Launched pid " << pid << " (" << program_path_ << ")"
              << (is_pie_ ? " [PIE, load base 0x" : " [non-PIE base 0x")
              << std::hex << load_base_ << std::dec << "]"
              << " [" << symbols_.size() << " symbols]\n";
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
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACECLONE);

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
    loadSymbolTable();
    std::cout << "Attached to pid " << pid << " (" << program_path_ << ")"
              << (is_pie_ ? " [PIE, load base 0x" : " [non-PIE base 0x")
              << std::hex << load_base_ << std::dec << "]"
              << " [" << symbols_.size() << " symbols]\n";
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
    // An explicit "0x" prefix always means a raw address, never a symbol
    // name -- this is the escape hatch for the rare symbol whose name is
    // itself all hex digits.
    if (text.rfind("0x", 0) == 0 || text.rfind("0X", 0) == 0) {
        uint64_t off = std::stoull(text.substr(2), nullptr, 16);
        return is_pie_ ? off + load_base_ : off;
    }
    // Otherwise, a known function name wins over a bare hex guess.
    auto it = symbols_.find(text);
    if (it != symbols_.end()) {
        return is_pie_ ? it->second + load_base_ : it->second;
    }
    // Fall back to treating it as hex without the "0x" prefix, matching
    // how objdump prints addresses.
    uint64_t off = std::stoull(text, nullptr, 16);
    return is_pie_ ? off + load_base_ : off;
}

// Parses the ELF section header table looking for a symbol table --
// .symtab if the binary still has one, otherwise .dynsym -- and builds a
// name -> static address map. Addresses stored here are exactly what's in
// the file (pre-ASLR); resolveAddress() adds the PIE load bias at lookup
// time, the same way it already does for hand-typed addresses.
void Debugger::loadSymbolTable() {
    symbols_.clear();

    std::ifstream f(program_path_, std::ios::binary);
    if (!f) return;

    Elf64_Ehdr ehdr{};
    f.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));
    if (!f || memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) return;

    std::vector<Elf64_Shdr> sections(ehdr.e_shnum);
    f.seekg(ehdr.e_shoff);
    f.read(reinterpret_cast<char*>(sections.data()),
           static_cast<std::streamsize>(ehdr.e_shnum) * sizeof(Elf64_Shdr));
    if (!f) return;

    int symtab_idx = -1;
    for (size_t i = 0; i < sections.size(); ++i) {
        if (sections[i].sh_type == SHT_SYMTAB) { symtab_idx = static_cast<int>(i); break; }
    }
    if (symtab_idx < 0) {
        for (size_t i = 0; i < sections.size(); ++i) {
            if (sections[i].sh_type == SHT_DYNSYM) { symtab_idx = static_cast<int>(i); break; }
        }
    }
    if (symtab_idx < 0) return; // no symbol table at all (fully stripped)

    const Elf64_Shdr& symtab = sections[symtab_idx];
    const Elf64_Shdr& strtab = sections[symtab.sh_link]; // sh_link -> matching string table

    size_t sym_count = symtab.sh_size / sizeof(Elf64_Sym);
    std::vector<Elf64_Sym> syms(sym_count);
    f.seekg(symtab.sh_offset);
    f.read(reinterpret_cast<char*>(syms.data()),
           static_cast<std::streamsize>(sym_count) * sizeof(Elf64_Sym));
    if (!f) return;

    std::vector<char> strs(strtab.sh_size);
    f.seekg(strtab.sh_offset);
    f.read(strs.data(), static_cast<std::streamsize>(strtab.sh_size));
    if (!f) return;

    for (const auto& sym : syms) {
        if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC) continue; // functions only
        if (sym.st_shndx == SHN_UNDEF) continue;               // skip imports/externs
        if (sym.st_name == 0 || sym.st_name >= strtab.sh_size) continue;
        std::string name(&strs[sym.st_name]);
        if (name.empty()) continue;
        symbols_[name] = sym.st_value;
    }
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

// ---------------------------------------------------------------------
// breakpoints
// ---------------------------------------------------------------------

// NOTE: PTRACE_PEEKTEXT/POKETEXT require their target *tid* to currently be
// in a ptrace-stop. All threads in a process share one address space, so
// any currently-stopped thread will do -- it need not be the thread-group
// leader. focus_tid_ is always the (one) thread guaranteed to be stopped
// whenever the REPL has control, so we use that rather than main_pid_.
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
// event loop
// ---------------------------------------------------------------------

void Debugger::printExit(pid_t tid, int status) const {
    if (WIFEXITED(status)) {
        std::cout << "[thread " << tid << "] exited with status " << WEXITSTATUS(status) << "\n";
    } else if (WIFSIGNALED(status)) {
        std::cout << "[thread " << tid << "] killed by signal " << WTERMSIG(status) << "\n";
    }
}

void Debugger::runEventLoopUntilStopOrExit() {
    while (true) {
        int status = 0;
        pid_t wpid = waitpid(-1, &status, __WALL);
        if (wpid < 0) {
            if (errno == ECHILD) {
                process_alive_ = false;
                std::cout << "process has no more tracked threads\n";
            }
            return;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            threads_.erase(wpid);
            printExit(wpid, status);
            if (wpid == main_pid_ || threads_.empty()) {
                process_alive_ = false;
                return;
            }
            continue; // a non-leader thread exited; keep waiting
        }

        if (!WIFSTOPPED(status)) continue;

        bool first_sighting = threads_.insert(wpid).second;
        if (first_sighting && wpid != main_pid_) {
            // Initial auto-attach stop for a freshly cloned thread
            // (PTRACE_O_TRACECLONE). Let it run; it now shares every
            // breakpoint already installed in the address space.
            std::cout << "[new thread " << wpid << "] attached\n";
            ptrace(PTRACE_CONT, wpid, nullptr, nullptr);
            continue;
        }

        int sig = WSTOPSIG(status);
        int event = status >> 16;

        if (sig == SIGTRAP && event == PTRACE_EVENT_CLONE) {
            // The cloning thread itself just trapped on the clone() call;
            // the new child's own stop arrives as a separate wait event.
            ptrace(PTRACE_CONT, wpid, nullptr, nullptr);
            continue;
        }

        if (sig == SIGTRAP) {
            uint64_t pc = getPC(wpid);
            uint64_t maybe_bp = pc - 1;
            auto it = breakpoints_.find(maybe_bp);
            if (it != breakpoints_.end() && it->second.enabled) {
                setPC(wpid, maybe_bp);
                focus_tid_ = wpid;
                std::cout << "Breakpoint hit at 0x" << std::hex << maybe_bp << std::dec
                          << " (thread " << wpid << ")\n";
                return;
            }
            // Stray trap on a thread we're not deliberately stepping; just
            // let it continue.
            ptrace(PTRACE_CONT, wpid, nullptr, nullptr);
            continue;
        }

        // Some other signal was delivered to the tracee; forward it and
        // keep going.
        ptrace(PTRACE_CONT, wpid, nullptr, reinterpret_cast<void*>(sig));
    }
}

// ---------------------------------------------------------------------
// REPL
// ---------------------------------------------------------------------

void Debugger::printHelp() const {
    std::cout <<
        "commands:\n"
        "  continue | c              resume the focus thread\n"
        "  step | s                  single-step one instruction\n"
        "  break | b <addr|name>     set a breakpoint (hex address or function name)\n"
        "  delete | d <addr|name>    remove a breakpoint\n"
        "  regs | r                  print registers of the focus thread\n"
        "  examine | x <addr|name> [n]  dump n 8-byte words starting there (default 4)\n"
        "  threads | t               list tracked thread ids\n"
        "  symbols | y [filter]      list known function symbols, optionally filtered\n"
        "  help | h                  show this message\n"
        "  quit | q                  detach/kill and exit\n";
}

void Debugger::cmdContinue() {
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
    runEventLoopUntilStopOrExit();
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

void Debugger::cmdThreads() {
    std::cout << "tracked threads (" << threads_.size() << "):\n";
    for (pid_t t : threads_) {
        std::cout << "  " << t << (t == main_pid_ ? " (main)" : "")
                   << (t == focus_tid_ ? " <- focus" : "") << "\n";
    }
}

void Debugger::cmdSymbols(const std::string& arg) {
    if (symbols_.empty()) {
        std::cout << "no symbols loaded (binary may be stripped)\n";
        return;
    }
    size_t shown = 0;
    for (const auto& [name, addr] : symbols_) {
        if (!arg.empty() && name.find(arg) == std::string::npos) continue;
        uint64_t runtime = is_pie_ ? addr + load_base_ : addr;
        std::cout << "  0x" << std::hex << runtime << std::dec << "  " << name << "\n";
        if (++shown >= 50) {
            std::cout << "  ... (" << symbols_.size() - shown << " more, narrow with a filter)\n";
            break;
        }
    }
    if (shown == 0) std::cout << "no symbols match '" << arg << "'\n";
}

void Debugger::handleCommand(const std::string& line) {
    auto tokens = split(line);
    if (tokens.empty()) return;
    const std::string& cmd = tokens[0];
    std::string arg = (tokens.size() > 1) ? line.substr(line.find(tokens[1])) : "";

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
    } else if (cmd == "threads" || cmd == "t") {
        cmdThreads();
    } else if (cmd == "symbols" || cmd == "y") {
        cmdSymbols(arg);
    } else if (cmd == "help" || cmd == "h") {
        printHelp();
    } else if (cmd == "quit" || cmd == "q") {
        if (process_alive_) {
            ptrace(PTRACE_KILL, main_pid_, nullptr, nullptr);
        }
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
