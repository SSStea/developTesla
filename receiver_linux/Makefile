CXX ?= g++

CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra
LDLIBS ?= -lssl -lcrypto -pthread

TARGET := bin/receiver_linux
SRC := main.cpp
HEADERS := json.hpp

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(SRC) $(HEADERS)
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(SRC) -o $@ $(LDLIBS)

run: $(TARGET)
	./$(TARGET)

clean:
	$(RM) $(TARGET)
