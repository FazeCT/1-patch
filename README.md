# 1-patch
A static binary patcher using patches in high-level programming languages.

## Introduction

[1-patch](https://github.com/FazeCT/1-patch) is a static binary patcher that demonstrates the usage of patches written in high-level programming languages in patching binaries. Currently, it supports C, and works with patching x86-64 ELF binaries. 

### Install dependencies

These instructions target Ubuntu x86-64, including WSL. The build requires CMake 3.24 or newer.

```bash caption="" /apply/ /components/
sudo apt update
sudo apt install -y build-essential cmake git binutils libdwarf-dev libelf-dev zlib1g-dev

cmake --version
```

The project also needs the LIEF C++ SDK. Install LIEF 1.0.0 into your user directory:

```bash caption="" /apply/ /components/
mkdir -p "$HOME/src"
git clone --depth 1 --branch 1.0.0 \
  https://github.com/lief-project/LIEF.git "$HOME/src/LIEF"

cmake -S "$HOME/src/LIEF" -B "$HOME/src/LIEF/build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DLIEF_PYTHON_API=OFF \
  -DLIEF_EXAMPLES=OFF \
  -DLIEF_TESTS=OFF \
  -DCMAKE_INSTALL_PREFIX="$HOME/.local"

cmake --build "$HOME/src/LIEF/build" --target install -j2
```

Capstone and Keystone are installed and built automatically during the project build.

### Build and test

```bash caption="" /apply/ /components/
git clone https://github.com/FazeCT/1-patch.git
cd 1-patch

cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$HOME/.local"

cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
```

The first project build needs access to GitHub to fetch Capstone and Keystone. 

If CMake cannot find LIEF, locate `LIEFConfig.cmake` with:

```bash caption="" /apply/ /components/
find "$HOME/.local" -name LIEFConfig.cmake
```

and pass its containing directory as `-DLIEF_DIR=<dir_here>`.

## Documentation

Refer to [the documentation here](https://blog.fazect.com/projects/1-patch).

## Extra Information

This work was my Computer Science Bachelor's thesis in Ho Chi Minh City University of Technology (late 2024).

This work was based on [CRISPR](https://www.politesi.polimi.it/handle/10589/177822) by Filippo Cremonese @ Politecnico di Milano and [Redback](https://groundx.io/redback/) by Quynh Nguyen Anh @ Blackhat Asia 2020.