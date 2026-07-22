CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -g -O0 -Iinclude

SRC := src/main.cpp src/debugger.cpp
BIN := bin/tether

.PHONY: all clean

all: $(BIN)

$(BIN): $(SRC) include/debugger.hpp
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o $(BIN) $(SRC)

bin/simple_target: test/simple_target.c
	@mkdir -p bin
	gcc -g -O0 -Wall -o $@ $<

clean:
	rm -rf bin
