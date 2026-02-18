FROM debian:trixie-slim AS setup

RUN apt update

RUN apt install -y \
    git build-essential bison flex autoconf automake libtool \
    libnl-3-dev libnl-genl-3-dev pkg-config \
    golang npm libgtk-3-dev libwebkit2gtk-4.1-dev

# Build libpcap from source to ensure it's compiled with libnl (the Debian versions aren't). 
# We need libpcap to be compiled with libnl for monitor mode support.
RUN git clone https://github.com/the-tcpdump-group/libpcap.git /libpcap

RUN cd /libpcap \
    && ./autogen.sh \
    && ./configure --enable-remote \
    && make \
    && make install

# Setup Wails, which is used to build the UI.
RUN go install github.com/wailsapp/wails/v2/cmd/wails@latest
ENV PATH="$PATH:/root/go/bin"

FROM setup AS build
WORKDIR /app

# Because libpcap is a shared library, we will want to bundle it with the binary.
RUN mkdir -p lib
RUN cp /usr/local/lib/libpcap.so* lib

COPY . .
RUN wails build -tags webkit2_41

# Extract the built binary and its dependencies
FROM scratch AS runtime
COPY --from=build /app/lib /lib
COPY --from=build /app/build/bin /