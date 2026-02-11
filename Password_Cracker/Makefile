# Makefile for Advanced Dictionary Hash Checker
# Supports multiple build configurations and platforms

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -D_POSIX_C_SOURCE=200809L
LDFLAGS = -lssl -lcrypto -lpthread
TARGET = hash_checker
SOURCE = hash_checker_cleaned.c

# Build configurations
DEBUG_FLAGS = -g -O0 -DDEBUG -fsanitize=address -fsanitize=undefined
RELEASE_FLAGS = -O3 -march=native -DNDEBUG -flto
PROFILE_FLAGS = -pg -O2

# Colors for output
RED = \033[1;31m
GREEN = \033[1;32m
YELLOW = \033[1;33m
BLUE = \033[1;34m
RESET = \033[0m

# Default target
.PHONY: all
all: release

# Release build (optimized)
.PHONY: release
release: CFLAGS += $(RELEASE_FLAGS)
release: clean
	@echo "$(BLUE)Building optimized release version...$(RESET)"
	$(CC) $(CFLAGS) $(SOURCE) -o $(TARGET) $(LDFLAGS)
	@echo "$(GREEN)✓ Release build complete: $(TARGET)$(RESET)"
	@echo "$(YELLOW)Run with: ./$(TARGET) <args>$(RESET)"

# Debug build (with sanitizers)
.PHONY: debug
debug: CFLAGS += $(DEBUG_FLAGS)
debug: LDFLAGS += -fsanitize=address -fsanitize=undefined
debug: clean
	@echo "$(BLUE)Building debug version with sanitizers...$(RESET)"
	$(CC) $(CFLAGS) $(SOURCE) -o $(TARGET)_debug $(LDFLAGS)
	@echo "$(GREEN)✓ Debug build complete: $(TARGET)_debug$(RESET)"
	@echo "$(YELLOW)Run with: ./$(TARGET)_debug <args>$(RESET)"

# Profile build (for performance analysis)
.PHONY: profile
profile: CFLAGS += $(PROFILE_FLAGS)
profile: clean
	@echo "$(BLUE)Building profiling version...$(RESET)"
	$(CC) $(CFLAGS) $(SOURCE) -o $(TARGET)_profile $(LDFLAGS)
	@echo "$(GREEN)✓ Profile build complete: $(TARGET)_profile$(RESET)"
	@echo "$(YELLOW)Run, then analyze with: gprof $(TARGET)_profile gmon.out$(RESET)"

# Static build (portable binary)
.PHONY: static
static: LDFLAGS = -lssl -lcrypto -lpthread -static
static: CFLAGS += $(RELEASE_FLAGS)
static: clean
	@echo "$(BLUE)Building static binary...$(RESET)"
	$(CC) $(CFLAGS) $(SOURCE) -o $(TARGET)_static $(LDFLAGS) 2>/dev/null || \
		(echo "$(RED)✗ Static build failed. Try: sudo apt-get install libssl-dev$(RESET)" && false)
	@echo "$(GREEN)✓ Static build complete: $(TARGET)_static$(RESET)"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "$(BLUE)Cleaning build artifacts...$(RESET)"
	@rm -f $(TARGET) $(TARGET)_debug $(TARGET)_profile $(TARGET)_static
	@rm -f *.o gmon.out *.gcda *.gcno
	@echo "$(GREEN)✓ Clean complete$(RESET)"

# Install to system
.PHONY: install
install: release
	@echo "$(BLUE)Installing $(TARGET) to /usr/local/bin...$(RESET)"
	@sudo cp $(TARGET) /usr/local/bin/
	@sudo chmod 755 /usr/local/bin/$(TARGET)
	@echo "$(GREEN)✓ Installed successfully$(RESET)"

# Uninstall from system
.PHONY: uninstall
uninstall:
	@echo "$(BLUE)Uninstalling $(TARGET)...$(RESET)"
	@sudo rm -f /usr/local/bin/$(TARGET)
	@echo "$(GREEN)✓ Uninstalled successfully$(RESET)"

# Run tests
.PHONY: test
test: debug
	@echo "$(BLUE)Running test suite...$(RESET)"
	@./run_tests.sh || echo "$(YELLOW)Create run_tests.sh for automated testing$(RESET)"

# Check for memory leaks with valgrind
.PHONY: valgrind
valgrind: debug
	@echo "$(BLUE)Running valgrind memory check...$(RESET)"
	@echo "test" > /tmp/test_dict.txt
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
		./$(TARGET)_debug /tmp/test_dict.txt 0 "test" 0 md5 1
	@rm -f /tmp/test_dict.txt

# Performance benchmark
.PHONY: benchmark
benchmark: release
	@echo "$(BLUE)Running performance benchmark...$(RESET)"
	@echo "Generating 1M line test dictionary..."
	@seq 1 1000000 > /tmp/bench_dict.txt
	@echo "$(YELLOW)1 thread:$(RESET)"
	@time ./$(TARGET) /tmp/bench_dict.txt 0 "999999" 0 md5 1
	@echo "$(YELLOW)4 threads:$(RESET)"
	@time ./$(TARGET) /tmp/bench_dict.txt 0 "999999" 0 md5 4
	@echo "$(YELLOW)8 threads:$(RESET)"
	@time ./$(TARGET) /tmp/bench_dict.txt 0 "999999" 0 md5 8
	@rm -f /tmp/bench_dict.txt

# Check code style
.PHONY: lint
lint:
	@echo "$(BLUE)Running static analysis...$(RESET)"
	@which cppcheck > /dev/null 2>&1 || (echo "$(RED)cppcheck not installed$(RESET)" && false)
	cppcheck --enable=all --suppress=missingIncludeSystem $(SOURCE)

# Generate documentation
.PHONY: docs
docs:
	@echo "$(BLUE)Generating documentation...$(RESET)"
	@which doxygen > /dev/null 2>&1 || (echo "$(YELLOW)doxygen not installed$(RESET)" && false)
	doxygen Doxyfile 2>/dev/null || echo "$(YELLOW)Create Doxyfile for documentation$(RESET)"

# Show help
.PHONY: help
help:
	@echo "$(CYAN)════════════════════════════════════════════════════════════════$(RESET)"
	@echo "$(CYAN)║$(RESET)  Advanced Dictionary Hash Checker - Build System          $(CYAN)║$(RESET)"
	@echo "$(CYAN)════════════════════════════════════════════════════════════════$(RESET)"
	@echo ""
	@echo "$(YELLOW)Available targets:$(RESET)"
	@echo "  $(GREEN)make$(RESET) or $(GREEN)make release$(RESET)  - Build optimized release version"
	@echo "  $(GREEN)make debug$(RESET)             - Build debug version with sanitizers"
	@echo "  $(GREEN)make profile$(RESET)           - Build for performance profiling"
	@echo "  $(GREEN)make static$(RESET)            - Build static binary (portable)"
	@echo "  $(GREEN)make clean$(RESET)             - Remove build artifacts"
	@echo "  $(GREEN)make install$(RESET)           - Install to /usr/local/bin (requires sudo)"
	@echo "  $(GREEN)make uninstall$(RESET)         - Remove from /usr/local/bin (requires sudo)"
	@echo "  $(GREEN)make test$(RESET)              - Run test suite"
	@echo "  $(GREEN)make valgrind$(RESET)          - Check for memory leaks"
	@echo "  $(GREEN)make benchmark$(RESET)         - Run performance benchmark"
	@echo "  $(GREEN)make lint$(RESET)              - Run static analysis (requires cppcheck)"
	@echo "  $(GREEN)make help$(RESET)              - Show this help message"
	@echo ""
	@echo "$(YELLOW)Dependencies:$(RESET)"
	@echo "  - OpenSSL development libraries (libssl-dev)"
	@echo "  - POSIX threads support"
	@echo "  - C11 compiler (gcc or clang)"
	@echo ""
	@echo "$(YELLOW)Install dependencies (Ubuntu/Debian):$(RESET)"
	@echo "  $(BLUE)sudo apt-get install libssl-dev build-essential$(RESET)"
	@echo ""
	@echo "$(YELLOW)Example usage after building:$(RESET)"
	@echo "  $(BLUE)./hash_checker wordlist.txt 0 password123 0 md5 8$(RESET)"
	@echo ""
	@echo "$(CYAN)════════════════════════════════════════════════════════════════$(RESET)"

# Platform-specific optimizations
.PHONY: optimize
optimize:
	@echo "$(BLUE)Building with platform-specific optimizations...$(RESET)"
	@echo "$(YELLOW)Detecting CPU features...$(RESET)"
	@gcc -march=native -Q --help=target | grep enabled | head -20
	@echo ""
	$(MAKE) release

# Code coverage build
.PHONY: coverage
coverage: CFLAGS += -fprofile-arcs -ftest-coverage -O0 -g
coverage: LDFLAGS += -lgcov
coverage: clean
	@echo "$(BLUE)Building with coverage instrumentation...$(RESET)"
	$(CC) $(CFLAGS) $(SOURCE) -o $(TARGET)_coverage $(LDFLAGS)
	@echo "$(GREEN)✓ Coverage build complete$(RESET)"
	@echo "$(YELLOW)Run tests, then: gcov $(SOURCE)$(RESET)"

# Address sanitizer only
.PHONY: asan
asan: CFLAGS += -fsanitize=address -O1 -g
asan: LDFLAGS += -fsanitize=address
asan: clean
	@echo "$(BLUE)Building with Address Sanitizer...$(RESET)"
	$(CC) $(CFLAGS) $(SOURCE) -o $(TARGET)_asan $(LDFLAGS)
	@echo "$(GREEN)✓ ASan build complete$(RESET)"

# Thread sanitizer only
.PHONY: tsan
tsan: CFLAGS += -fsanitize=thread -O1 -g
tsan: LDFLAGS += -fsanitize=thread
tsan: clean
	@echo "$(BLUE)Building with Thread Sanitizer...$(RESET)"
	$(CC) $(CFLAGS) $(SOURCE) -o $(TARGET)_tsan $(LDFLAGS)
	@echo "$(GREEN)✓ TSan build complete$(RESET)"
	@echo "$(YELLOW)This build detects race conditions$(RESET)"