CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -s

# Define the targets
all: original build run

# Rule to build the original binary
original: example/original.c
	@$(CC) $(LDFLAGS) example/original.c -o example/original

original_golang: example/original.go 
	@go build -o example/original_go example/original.go

# Rule to invoke make in the ../build directory
build:
	@$(MAKE) -C build

# Rule to run the program
run: run_original run_thesis run_patched

run_golang: run_original_golang run_thesis_golang run_patched_golang

# Run the original binary
run_original:
	@echo "Running the original binary..."
	@./example/original || { echo "Error: Failed to run original binary"; exit 1; }

# Run the thesis tool to patch the binary
run_thesis:
	@echo "Patching the binary with thesis tool..."
	@./build/thesis example/patch.c example/original example/original_cocay || { echo "Error: Failed to patch the binary"; exit 1; }

# Run the patched binary
run_patched:
	@echo "Running the patched binary..."
	@./example/original_cocay || { echo "Error: Failed to run patched binary"; exit 1; }

# Run the original Go binary
run_original_golang:
	@echo "Running the original Go binary..."
	@./example/original_go || { echo "Error: Failed to run original Go binary"; exit 1; }

# Run the thesis tool to patch the Go binary
run_thesis_golang:
	@echo "Patching the Go binary with thesis tool..."
	@./build/thesis example/patch.c example/original_go example/original_go_cocay || { echo "Error: Failed to patch the Go binary"; exit 1; }

# Run the patched Go binary
run_patched_golang:
	@echo "Running the patched Go binary..."
	@./example/original_go_cocay || { echo "Error: Failed to run patched Go binary"; exit 1; }

# Phony targets to avoid conflicts with files of the same name
.PHONY: original build run_original run_thesis run_patched clean

# Rule to clean up generated files
clean:
	rm -f example/original
	rm -f example/original_cocay
	rm -f example/original_go