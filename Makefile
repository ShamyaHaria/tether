CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -g -O0 -Iinclude
CC       := gcc
CFLAGS   := -g -O0 -Wall

SRC := src/main.cpp src/debugger.cpp
BIN := bin/tether

.PHONY: all clean test-targets

all: $(BIN) test-targets

$(BIN): $(SRC) include/debugger.hpp
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o $(BIN) $(SRC)

# Two demo targets: one built as a default PIE binary, one forced non-PIE,
# so both address-resolution paths in the debugger get exercised.
test-targets: bin/simple_target bin/threaded_target

bin/simple_target: test/simple_target.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $<

bin/threaded_target: test/threaded_target.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -no-pie -o $@ $< -lpthread

clean:
	rm -rf bin
