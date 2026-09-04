# SPDX-FileCopyrightText: 2026 Kebag-Logic
# SPDX-License-Identifier: MIT
#
# Build: make -j            -> build/avb-introspectd
# Tests: make -j test       -> build & run unit tests
# Note (OQ-11): plain Make instead of CMake — no extra toolchain needed.

CXX      ?= g++
CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++20 -Wall -Wextra -pthread
LDLIBS   := -lz -lsodium -pthread

# Build identity, shown by `avb-introspectd --version` and in the startup
# banner. Defaults to `git describe`; release/container builds pass it
# explicitly (make VERSION=1.2.0, docker build --build-arg VERSION=...).
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

BUILD    := build
SRCDIR   := backend/src
TESTDIR  := backend/tests

SRCS := $(shell find $(SRCDIR) -name '*.cpp' ! -name main.cpp | sort)
OBJS := $(SRCS:$(SRCDIR)/%.cpp=$(BUILD)/obj/%.o)
MAIN_OBJ := $(BUILD)/obj/main.o

TEST_SRCS := $(shell find $(TESTDIR) -name '*.cpp' | sort)
TEST_OBJS := $(TEST_SRCS:$(TESTDIR)/%.cpp=$(BUILD)/test-obj/%.o)

BIN  := $(BUILD)/avb-introspectd
TEST := $(BUILD)/avb-tests

.PHONY: all test clean

all: $(BIN)

$(BIN): $(OBJS) $(MAIN_OBJ)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

# Logic modules register at static init; --whole-archive semantics are not
# needed because objects are linked directly (no intermediate static lib).
$(TEST): $(OBJS) $(TEST_OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/obj/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MMD -MP -c -o $@ $<

# Only main.o carries the version string, so a changed VERSION costs one
# object rebuild (touch it if you rebuild in place with a new VERSION).
$(BUILD)/obj/main.o: $(SRCDIR)/main.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -DAVB_VERSION='"$(VERSION)"' -MMD -MP -c -o $@ $<

$(BUILD)/test-obj/%.o: $(TESTDIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -I$(SRCDIR) -MMD -MP -c -o $@ $<

test: $(TEST)
	./$(TEST)

clean:
	rm -rf $(BUILD)

-include $(OBJS:.o=.d) $(MAIN_OBJ:.o=.d) $(TEST_OBJS:.o=.d)
