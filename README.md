# Tether

A small ptrace-based debugger for multithreaded Linux processes, written in
C++17 with no dependencies beyond the standard library and the kernel's
`ptrace(2)` API.

Tether can launch or attach to a process, set software breakpoints, read
and write registers and memory, single-step instructions, and automatically
follow every thread a target spawns — including firing a breakpoint no
matter which thread happens to execute it.

```
$ ./bin/tether ./bin/threaded_target
Launched pid 750 (./bin/threaded_target) [non-PIE base 0x0]
tether -- type 'help' for commands
(tether) break 0x40124f
breakpoint set at 0x40124f
(tether) continue
[new thread 751] attached
Breakpoint hit at 0x40124f (thread 751)
(tether) continue
[new thread 752] attached
Breakpoint hit at 0x40124f (thread 752)
```

## Why

This started as a focused exercise in the layer just below a language
runtime: how a debugger actually gets a handle on another process, how
breakpoints work as opcode patches rather than magic, and how that changes
once the target has more than one thread. It's deliberately scoped to be
readable end to end rather than feature-complete.

## Features

- Launch a new process (`fork` + `PTRACE_TRACEME` + `execve`) or attach to
  a running one (`PTRACE_ATTACH`)
- Software breakpoints via `INT3` (`0xCC`) injection, with correct
  step-over-and-restore so a breakpoint doesn't just trap forever
- Register inspection (`PTRACE_GETREGS`)
- Memory reads (`PTRACE_PEEKTEXT`)
- Single-instruction stepping (`PTRACE_SINGLESTEP`)
- Automatic tracing of new threads via `PTRACE_O_TRACECLONE` — breakpoints
  are process-wide, so one set on a shared function fires in whichever
  thread runs it next
- PIE-aware addressing: reads the ELF header to detect `ET_DYN` binaries
  and computes the ASLR load bias from `/proc/<pid>/maps`, so you can enter
  addresses the way `objdump -d` prints them

## Platform requirements

Tether is Linux-only, on purpose: it's built directly on Linux's `ptrace`
API (`PTRACE_GETREGS`/`SETREGS`, `PTRACE_O_TRACECLONE`), reads `/proc/<pid>/maps`,
and parses ELF headers. None of that exists on macOS (Mach-O binaries, no
`/proc`, a much more restricted `ptrace`) or Windows. If you're on macOS,
the easiest fix is a real Linux environment via Docker, since Docker
Desktop runs a Linux VM under the hood:

```bash
docker build -t tether-dev .
docker run --rm -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -v "$(pwd)":/work tether-dev bash
# inside the container:
make
./bin/tether ./bin/simple_target
```

`--cap-add=SYS_PTRACE` and the unconfined seccomp profile are required
because Docker's default container profile blocks `ptrace` outright. A
Lima/UTM/multipass Linux VM, or a cloud dev box, works the same way and
avoids the container flags entirely if you'd rather not touch seccomp.

## Build

```
make
```

Produces `bin/tether` plus two demo targets (`bin/simple_target`,
`bin/threaded_target`) used in the walkthrough below. Requires `g++` with
C++17 support and Linux (uses `<sys/ptrace.h>`, `<sys/user.h>`, `<elf.h>`).
Attaching to a process you didn't launch needs `CAP_SYS_PTRACE` (or to be
its owner, subject to `yama/ptrace_scope`).

## Usage

```
tether <program> [args...]     launch and trace a new process
tether -p <pid>                attach to a running process
```

Addresses are entered the way `objdump -d <binary>` prints them — Tether
adds the runtime ASLR load bias for you if the binary is PIE.

| command                  | does |
|---------------------------|------|
| `continue` / `c`          | resume the focus thread |
| `step` / `s`              | single-step one instruction |
| `break` / `b <addr>`      | set a breakpoint |
| `delete` / `d <addr>`     | remove a breakpoint |
| `regs` / `r`              | print registers of the focus thread |
| `examine` / `x <addr> [n]`| dump `n` 8-byte words starting at `addr` (default 4) |
| `threads` / `t`           | list every tracked thread id |
| `help` / `h`              | show the command list |
| `quit` / `q`              | kill/detach and exit |

## A five-minute walkthrough

```
make
objdump -d bin/simple_target | grep -A1 '<add>:'   # find add()'s address
./bin/tether ./bin/simple_target
(tether) break <address from objdump, e.g. 0x11a9>
(tether) continue      # traps at add()
(tether) regs          # rdi/rsi hold add()'s actual arguments
(tether) step           # advance one instruction
(tether) continue      # traps again on the next loop iteration
(tether) quit
```

Then the multithreaded case:

```
objdump -d bin/threaded_target | grep -A1 '<worker>:'
./bin/tether ./bin/threaded_target
(tether) break <address from objdump, e.g. 0x40124f>
(tether) continue      # thread 1 traps
(tether) threads       # shows the main thread plus every auto-attached one
(tether) continue      # thread 2 traps on the *same* breakpoint
(tether) continue      # thread 3 traps too
```

## Design notes

**PIE addressing.** Most compilers default to position-independent
executables now, so a static address from `objdump` isn't the runtime
address. Tether reads the ELF header (`e_type == ET_DYN`) to detect PIE,
then reads `/proc/<pid>/maps` right after the target stops to find its
load bias. Launched processes also get `personality(ADDR_NO_RANDOMIZE)` so
the bias is reproducible run to run.

**Breakpoints as opcode patches.** Setting one reads the 8-byte word at the
target address, overwrites its low byte with `0xCC` (`INT3`), and writes it
back. On hit, the tracee traps with `SIGTRAP` and `rip` one past the
breakpoint; Tether rewinds `rip` by one. Resuming past a breakpoint means
disabling it, single-stepping the real instruction, and re-arming it —
otherwise you'd trap on the same address forever.

**A subtlety worth calling out:** `PEEKTEXT`/`POKETEXT` (and most ptrace
requests) only work against a thread that's *currently stopped*. The
natural instinct is to always operate on the process's main thread, but in
a multithreaded tracee the main thread is very often running in the
background while some other thread is the one stopped at a breakpoint. All
memory operations in Tether target `focus_tid_` — the one thread
guaranteed to be stopped whenever the REPL has control — rather than the
thread-group leader, which is what the [commit history](#commit-history)
below actually caught as a real bug partway through.

**Multithreading.** `PTRACE_O_TRACECLONE` is set on the tracee right after
the initial stop. When the kernel creates a new thread, the tracer sees two
events: a `PTRACE_EVENT_CLONE` stop on the cloning thread, and a separate
first-stop for the brand-new tid (auto-attached, not yet running any user
code). Tether resumes both immediately. Because threads share one address
space, a breakpoint installed once is live for every thread.

**Concurrency model.** Tether runs "non-stop": only one thread is ever
reported to the user at a time (`focus_tid_`), and every other tracked
thread keeps running in the background rather than being forcibly frozen.
If a background thread hits a breakpoint while you're at the prompt, the
kernel just parks it — the next `continue` picks up that pending stop. This
sidesteps the extra complexity (and races) of broadcasting `SIGSTOP` across
a whole thread group to get GDB-style "all-stop" semantics, while still
exercising the real multithreaded tracing machinery.

## Commit history

The commits on this repo are ordered to read as a build log, each one
compiling and working on its own:

1. Build system and CLI skeleton
2. Process bootstrap: launch/attach and PIE-aware address resolution
3. Software breakpoints and register/memory inspection
4. Single-instruction stepping
5. Multithreaded tracing via `PTRACE_O_TRACECLONE`
6. Docs

## Test targets

- `test/simple_target.c` — single-threaded, built as a default PIE binary.
  Exercises the PIE load-bias path.
- `test/threaded_target.c` — spawns 3 pthreads that all call the same
  `worker()` function; built `-no-pie` so its addresses are static. Used to
  verify `PTRACE_O_TRACECLONE` auto-attach and a breakpoint shared across
  threads.

## Roadmap / not built (yet)

- ELF symbol table parsing, so you can `break main` instead of
  `break 0x4011a0`
- Minimal DWARF line-number parsing for `break file.c:42` and source-line
  stepping
- Hardware watchpoints via debug registers (`DR0`–`DR3`)

## License

MIT.
