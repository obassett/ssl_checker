# Build stage
FROM rust:1.87.0 AS builder

# TARGETARCH is automatically provided by buildx, e.g., amd64, arm64
ARG TARGETARCH

RUN apt-get update && \
    apt-get install -y musl-tools && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.lock Cargo.toml /app/
COPY src /app/src/

# Ensure static linking
ENV RUSTFLAGS="-C target-feature=+crt-static"

# Determine Rust target, install it, build, and copy to a generic path
RUN \
    # Set default for CURRENT_TARGETARCH if TARGETARCH is not provided (e.g. local docker build .)
    CURRENT_TARGETARCH=${TARGETARCH:-amd64} && \
    RUST_TARGET_TRIPLE="" && \
    if [ "$CURRENT_TARGETARCH" = "amd64" ]; then \
    RUST_TARGET_TRIPLE="x86_64-unknown-linux-musl"; \
    elif [ "$CURRENT_TARGETARCH" = "arm64" ]; then \
    RUST_TARGET_TRIPLE="aarch64-unknown-linux-musl"; \
    else \
    echo "Warning: TARGETARCH is '${TARGETARCH}', which is unsupported or unexpected. Defaulting to x86_64-unknown-linux-musl." >&2; \
    RUST_TARGET_TRIPLE="x86_64-unknown-linux-musl"; \
    fi && \
    echo "Building for architecture: ${CURRENT_TARGETARCH}, Rust target: ${RUST_TARGET_TRIPLE}" && \
    rustup target add ${RUST_TARGET_TRIPLE} && \
    cargo build --release --target ${RUST_TARGET_TRIPLE} && \
    # Copy the built binary to a fixed location within the builder stage
    cp "/app/target/${RUST_TARGET_TRIPLE}/release/ssl_checker" /app/ssl_checker_run

# Get CA certificates
FROM alpine:3.18 AS certs
RUN apk add --no-cache ca-certificates

# Final image
FROM scratch
COPY --from=builder /app/ssl_checker_run /ssl_checker
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/ssl_checker"]
