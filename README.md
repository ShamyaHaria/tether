# Tether

A small ptrace-based debugger for multithreaded Linux processes, written in
C++17 with no dependencies beyond the standard library and the kernel's
`ptrace(2)` API.

Tether can launch or attach to a process, set software breakpoints, read
and write registers and memory, single-step instructions, and
automatically follow every thread a target spawns.

$ ./bin/tether ./bin/threaded_target
Launched pid 750 (./bin/threaded_target)
tether -- type 'help' for commands
(tether) break 0x40124f
breakpoint set at 0x40124f
(tether) continue
[new thread 751] attached
Breakpoint hit at 0x40124f (thread 751)


## Features

- Launch a new process or attach to a running one (`-p <pid>`)
- Software breakpoints with correct step-over/restore
- Register inspection and memory reads
- Single-instruction stepping
- Automatic tracing of every thread a target spawns, including PIE binaries
  (position-independent executables)

## Build

make


Produces `bin/tether` plus two demo targets used below. Requires `g++`
with C++17 support and Linux. Attaching to a process you didn't launch
needs `CAP_SYS_PTRACE`.

**On macOS or Windows:** this project only builds on Linux. Use the
included `Dockerfile`, or GitHub Codespaces, for a real Linux environment.

docker build -t tether-dev .
docker run --rm -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v "$(pwd)":/work tether-dev bash


## Usage

tether <program> [args...] launch and trace a new process
tether -p <pid> attach to a running process


| command                    | does |
|----------------------------|------|
| `continue` / `c`           | resume the focus thread |
| `step` / `s`               | single-step one instruction |
| `break` / `b <addr>`       | set a breakpoint |
| `delete` / `d <addr>`      | remove a breakpoint |
| `regs` / `r`               | print registers of the focus thread |
| `examine` / `x <addr> [n]` | dump memory starting at addr |
| `threads` / `t`            | list every tracked thread id |
| `help` / `h`               | show the command list |
| `quit` / `q`               | kill/detach and exit |

Addresses are entered the way `objdump -d <binary>` prints them.

## Test targets

- `test/simple_target.c` — single-threaded, PIE
- `test/threaded_target.c` — spawns 3 pthreads calling a shared function,
  used to verify breakpoints fire correctly across threads

## Roadmap

- ELF symbol table lookup (`break main` instead of `break 0x4011a0`)
- DWARF line-number info for source-level stepping
- Hardware watchpoints

## License

MIT.
