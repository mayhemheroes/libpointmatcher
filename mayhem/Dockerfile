# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile for libpointmatcher — builds ON TOP of the org C/C++ base
# (ghcr.io/mayhemheroes/base). The base provides debian + clang/llvm + libFuzzer/ASan/UBSan +
# the build contract ENV; this adds libpointmatcher's apt deps and runs the per-commit build.
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) -t libpointmatcher-commit:test .

FROM ghcr.io/mayhemheroes/base:20260621

ARG COMMIT
ARG REPO_URL
ARG SOURCE_DATE_EPOCH
ARG SANITIZER_FLAGS
ARG MAYHEM_JOBS=

# libpointmatcher's system deps: Eigen3 (headers), Boost (thread/system/program_options/date_time/
# chrono), yaml-cpp. libnabo is NOT packaged — we fetch its source here (network available during
# docker build) and store it at /opt/libnabo-src so build.sh can build it offline (§6.5).
USER root
RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true ; \
    apt-get update && apt-get install -yq --no-install-recommends \
      libeigen3-dev \
      libboost-thread-dev libboost-system-dev libboost-program-options-dev \
      libboost-date-time-dev libboost-chrono-dev \
      libyaml-cpp-dev \
 && rm -rf /var/lib/apt/lists/*

# Pre-fetch libnabo 1.1.2 source into the image so build.sh can build it offline (air-gap §6.5).
RUN git clone --depth 1 --branch 1.1.2 https://github.com/norlab-ulaval/libnabo.git /opt/libnabo-src \
 && chmod -R a+rX /opt/libnabo-src

USER mayhem

WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN bash mayhem/build.sh

# Run the gtest suite at build time — a failing suite fails the image build.
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
