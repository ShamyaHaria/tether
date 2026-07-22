CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -g -O0 -Iinclude

SRC := src/main.cpp
BIN := bin/tether

.PHONY: all clean

all: $(BIN)

$(BIN): $(SRC)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o $(BIN) $(SRC)

clean:
	rm -rf bin
