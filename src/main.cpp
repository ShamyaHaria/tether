#include "debugger.hpp"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {

void usage(const char* argv0) {
    std::cerr << "usage:\n"
              << "  " << argv0 << " <program> [args...]     launch and trace a new process\n"
              << "  " << argv0 << " -p <pid>                attach to a running process\n";
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (std::strcmp(argv[1], "-p") == 0) {
        if (argc < 3) {
            usage(argv[0]);
            return 1;
        }
        pid_t pid = static_cast<pid_t>(std::atoi(argv[2]));
        Debugger dbg("", {});
        if (!dbg.attach(pid)) return 1;
        dbg.repl();
        return 0;
    }

    std::string program = argv[1];
    std::vector<std::string> args;
    for (int i = 2; i < argc; ++i) args.emplace_back(argv[i]);

    Debugger dbg(program, args);
    if (!dbg.launch()) return 1;
    dbg.repl();
    return 0;
}
