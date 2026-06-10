#!/usr/bin/env bash
#
# mayhem/build.sh — build libpointmatcher's fuzz harness(es) + its test suite.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The org base
# (ghcr.io/mayhemheroes/base) exports the build contract: CC, CXX, LIB_FUZZING_ENGINE,
# STANDALONE_FUZZ_MAIN, SANITIZER_FLAGS, SRC. apt deps (eigen3, boost, yaml-cpp) are installed
# by the Dockerfile as root. libnabo (libpointmatcher's kd-tree dep) is NOT packaged — we build
# it from source into a mayhem-owned prefix here (no root needed).
#
# Target `lib-fuzz` (binary /mayhem/fuzz_lib): fuzzes PointMatcher<float>::DataPoints::load() on a
# temp .csv/.vtk file → exercises libpointmatcher's CSV + VTK point-cloud parsers (pointmatcher/IO.cpp).
#
# ADDITIVE: upstream is built exactly as it documents (cmake), no upstream file is edited. The library
# itself is built WITH $SANITIZER_FLAGS so the fuzzed parser code is instrumented (not just the harness);
# the gtest `utest` suite is a SEPARATE clean build with normal flags so test.sh is an honest oracle.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF < 4 symbols independently of the sanitizer off-switch.
# clang-19's plain -g emits DWARF-5; -gdwarf-3 is explicit (Mayhem triage requires < 4).
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

# Idempotency: remove build dirs so a second run on an already-built tree exits 0.
rm -rf "$SRC/build-fuzz" "$SRC/build-tests" "$SRC/.deps"

DEPS_PREFIX="$SRC/.deps"           # mayhem-owned install prefix for libnabo (no root)
FDP_INC="$("$CC" -print-resource-dir)/include/fuzzer"   # base ships fuzzer/FuzzedDataProvider.h here

# ----------------------------------------------------------------------------------------------
# 1) libnabo — dependency required by libpointmatcher's find_package(libnabo). Build normally
#    (it is not on the fuzzed code path: DataPoints::load is pure IO and doesn't touch the kd-tree),
#    install into a mayhem-owned prefix.
# ----------------------------------------------------------------------------------------------
NABO_SRC=/opt/libnabo-src
# libnabo source was pre-fetched into the image by the Dockerfile (air-gap §6.5). No network needed.
# Build into /tmp/libnabo-build to keep the source dir clean for re-runs.
NABO_BUILD=/tmp/libnabo-build
rm -rf "$NABO_BUILD"
cmake -S "$NABO_SRC" -B "$NABO_BUILD" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$DEPS_PREFIX" \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DLIBNABO_BUILD_EXAMPLES=OFF -DLIBNABO_BUILD_TESTS=OFF -DLIBNABO_BUILD_PYTHON=OFF
cmake --build "$NABO_BUILD" -j"$MAYHEM_JOBS"
cmake --install "$NABO_BUILD"

# ----------------------------------------------------------------------------------------------
# 2) libpointmatcher — INSTRUMENTED build (the fuzzed code). Static lib, sanitizer flags on the
#    library sources. examples/evaluations/tests off (only the lib is needed for the harness).
# ----------------------------------------------------------------------------------------------
cmake -S "$SRC" -B "$SRC/build-fuzz" -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
  -DCMAKE_PREFIX_PATH="$DEPS_PREFIX" \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_EXAMPLES=OFF -DBUILD_EVALUATIONS=OFF -DBUILD_TESTS=OFF -DBUILD_PYTHON_MODULE=OFF \
  -DUSE_OPEN_MP=FALSE
cmake --build "$SRC/build-fuzz" -j"$MAYHEM_JOBS" --target pointmatcher

LPM_A="$SRC/build-fuzz/libpointmatcher.a"
[ -f "$LPM_A" ] || { echo "FATAL: $LPM_A not produced by the instrumented build" >&2; exit 1; }

# Link deps for the harness: instrumented libpointmatcher first, then its transitive deps.
HARNESS_INCLUDES=( -I"$SRC" -I"$SRC/pointmatcher" -I"$FDP_INC" -I/usr/include/eigen3 -I"$DEPS_PREFIX/include" )
HARNESS_LIBS=( "$LPM_A" "$DEPS_PREFIX/lib/libnabo.a" -lyaml-cpp
               -lboost_thread -lboost_system -lboost_program_options -lboost_date_time -lboost_chrono
               -lpthread )

# ----------------------------------------------------------------------------------------------
# 3) Harness, built twice: (a) libFuzzer binary, (b) standalone run-once reproducer.
#    The standalone driver is C — compile it as a C object first so its LLVMFuzzerTestOneInput
#    reference keeps C linkage (clang++ would mangle it and miss the harness's extern "C" def).
#
#    asan_options.c: strong __asan_default_options(detect_leaks=0) to disable LSan.
#    LSan ptrace-attaches at exit which conflicts with Mayhem's ptrace-based coverage collection
#    → 0-edge "Run Failed". Linked into both binaries.
# ----------------------------------------------------------------------------------------------
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/asan_options.c" -o /tmp/asan_options.o

"$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS -std=c++17 \
  "${HARNESS_INCLUDES[@]}" \
  "$SRC/mayhem/fuzz_lib.cpp" /tmp/asan_options.o \
  "${HARNESS_LIBS[@]}" \
  $LIB_FUZZING_ENGINE \
  -o /mayhem/fuzz_lib

"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
"$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS -std=c++17 \
  "${HARNESS_INCLUDES[@]}" \
  "$SRC/mayhem/fuzz_lib.cpp" /tmp/asan_options.o /tmp/standalone_main.o \
  "${HARNESS_LIBS[@]}" \
  -o /mayhem/fuzz_lib-standalone

# ----------------------------------------------------------------------------------------------
# 4) TEST suite — the gtest `utest` runner, a SEPARATE clean build with NORMAL flags (no
#    sanitizers) so test.sh stays an honest functional oracle. Leaves utest where test.sh looks.
# ----------------------------------------------------------------------------------------------
cmake -S "$SRC" -B "$SRC/build-tests" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_PREFIX_PATH="$DEPS_PREFIX" \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_EXAMPLES=OFF -DBUILD_EVALUATIONS=OFF -DBUILD_TESTS=ON -DBUILD_PYTHON_MODULE=OFF \
  -DUSE_OPEN_MP=FALSE
cmake --build "$SRC/build-tests" -j"$MAYHEM_JOBS" --target utest

[ -x "$SRC/build-tests/utest/utest" ] || { echo "FATAL: utest runner not produced" >&2; exit 1; }

echo "=== build.sh done: /mayhem/fuzz_lib, /mayhem/fuzz_lib-standalone, build-tests/utest/utest ==="
ls -l /mayhem/fuzz_lib /mayhem/fuzz_lib-standalone "$SRC/build-tests/utest/utest"
