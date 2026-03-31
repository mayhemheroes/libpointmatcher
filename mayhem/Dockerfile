# Build Stage
FROM --platform=linux/amd64 ubuntu:22.04 as builder

## Install build dependencies.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y clang cmake git libeigen3-dev libboost-all-dev

## Install libnabo
RUN git clone https://github.com/ethz-asl/libnabo.git
RUN mkdir libnabo/build && cd libnabo/build && \
    cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo .. && \
    make -j$(nproc) && \
    make install

ENV CC=clang
ENV CXX=clang++

## Add source code to the build stage.
ADD . /libpointmatcher
WORKDIR /libpointmatcher

## Build
RUN mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -DMAYHEM=ON .. && \
    make -j$(nproc) && \
    make install

# Package Stage
FROM --platform=linux/amd64 ubuntu:22.04
COPY --from=builder /libpointmatcher/build/mayhem/fuzz_libpointmatcher /fuzz_lib
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y libboost-thread1.74.0 libboost-atomic1.74.0 libboost-filesystem1.74.0 libboost-system1.74.0 libboost-program-options1.74.0 libboost-date-time1.74.0 libboost-chrono1.74.0 libc6-i386 libc6 libgcc-s1 lib32gcc-s1 libc6 libc6-i386

## Set up fuzzing!
ENTRYPOINT []
CMD /fuzz_lib
