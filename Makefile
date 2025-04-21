CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -s

all: original build run clean
golang: original_golang build run_golang clean

original: example/original.c
	@$(CC) $(LDFLAGS) example/original.c -o example/original

original_golang: example/original.go 
	@go build -o example/original_go example/original.go

build:
	@$(MAKE) -C build

run: run_original run_thesis run_patched

run_golang: run_original_golang run_thesis_golang run_patched_golang

run_original:
	@echo "Running the original binary..."
	@./example/original || { echo "Error: Failed to run original binary"; exit 1; }

run_thesis:
	@echo "Patching the binary with thesis tool..."
	@./build/thesis example/patch.c example/original example/original_patched || { echo "Error: Failed to patch the binary"; exit 1; }

run_patched:
	@echo "Running the patched binary..."
	@./example/original_patched || { echo "Error: Failed to run patched binary"; exit 1; }

run_original_golang:
	@echo "Running the original Go binary..."
	@./example/original_go || { echo "Error: Failed to run original Go binary"; exit 1; }

run_thesis_golang:
	@echo "Patching the Go binary with thesis tool..."
	@./build/thesis example/patch.c example/original_go example/original_go_patched || { echo "Error: Failed to patch the Go binary"; exit 1; }

run_patched_golang:
	@echo "Running the patched Go binary..."
	@./example/original_go_patched || { echo "Error: Failed to run patched Go binary"; exit 1; }

.PHONY: original build run_original run_thesis run_patched clean

clean:
	@rm -f example/original
	@rm -f example/original_patched
	@rm -f example/original_go
	@rm -f example/original_go_patched