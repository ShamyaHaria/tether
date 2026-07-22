#include <cstdio>

// Entry point skeleton. The actual ptrace engine (Debugger class) lands in
// the next commit; this just nails down the CLI shape:
//   tether <program> [args...]   launch and trace a new process
//   tether -p <pid>              attach to a running process
int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage:\n");
        fprintf(stderr, "  %s <program> [args...]     launch and trace a new process\n", argv[0]);
        fprintf(stderr, "  %s -p <pid>                attach to a running process\n", argv[0]);
        return 1;
    }
    printf("tether: debugger engine not implemented yet\n");
    return 0;
}
