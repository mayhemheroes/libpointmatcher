#!/bin/bash
set -euo pipefail

# RLENV Build Script
# This script rebuilds the application from source located at /rlenv/source/libpointmatcher/
#
# Original image: ghcr.io/mayhemheroes/libpointmatcher:master
# Git revision: e1788d2157ff4bc60850becafc264481c1db679c

# ============================================================================
# Environment Variables
# ============================================================================
export CC=clang
export CXX=clang++

# ============================================================================
# REQUIRED: Change to Source Directory
# ============================================================================
cd /rlenv/source/libpointmatcher

# ============================================================================
# Clean Previous Build (recommended)
# ============================================================================
# Remove old build artifacts to ensure fresh rebuild
rm -rf build/
# Note: /fuzz_lib is handled by 'cat >' which overwrites automatically

# ============================================================================
# Build Commands (NO NETWORK, NO PACKAGE INSTALLATION)
# ============================================================================
# Note: libnabo dependency is already built and installed in the container
# We only need to rebuild libpointmatcher itself

# Create build directory and run CMake
mkdir build && cd build

# Configure with CMake (same flags as original Dockerfile)
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -DMAYHEM=ON ..

# Build with single job to be conservative
make -j1

# Skip 'make install' - we don't need system-wide installation
# The fuzzer binary links against libnabo which is already installed in the container

# ============================================================================
# Copy Artifacts (use 'cat >' for busybox compatibility)
# ============================================================================
# Copy the fuzzer binary to expected location
cat mayhem/fuzz_libpointmatcher > /fuzz_lib

# ============================================================================
# Set Permissions
# ============================================================================
chmod 777 /fuzz_lib 2>/dev/null || true

# ============================================================================
# REQUIRED: Verify Build Succeeded
# ============================================================================
if [ ! -f /fuzz_lib ]; then
    echo "Error: Build artifact not found at /fuzz_lib"
    exit 1
fi

# Verify executable bit
if [ ! -x /fuzz_lib ]; then
    echo "Warning: Build artifact is not executable"
fi

# Verify file size (fuzzer should be at least a few KB)
SIZE=$(stat -c%s /fuzz_lib 2>/dev/null || stat -f%z /fuzz_lib 2>/dev/null || echo 0)
if [ "$SIZE" -lt 1000 ]; then
    echo "Warning: Build artifact is suspiciously small ($SIZE bytes)"
fi

echo "Build completed successfully: /fuzz_lib (${SIZE} bytes)"
