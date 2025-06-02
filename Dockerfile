# Build stage
FROM rust:1.87.0 AS builder
RUN apt-get update && apt-get install -y musl-tools
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /app
COPY Cargo.lock Cargo.toml /app/
COPY src /app/src/ 

# Ensure static linking
ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN cargo build --release --target x86_64-unknown-linux-musl

# Get CA certificates
FROM alpine:3.18 AS certs
RUN apk add --no-cache ca-certificates

# Final image
FROM scratch
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/ssl_checker /ssl_checker
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/ssl_checker"]
