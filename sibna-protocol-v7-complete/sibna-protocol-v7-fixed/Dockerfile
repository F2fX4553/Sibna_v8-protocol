# Sibna Protocol - Production Dockerfile
# Multi-stage build for minimal image size

# Build stage
FROM rust:1.75-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY core/Cargo.toml ./core/
COPY core/src ./core/src

# Build in release mode
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash sibna

WORKDIR /app

# Copy built binaries
COPY --from=builder /build/target/release/libsibna.so /usr/lib/
COPY --from=builder /build/target/release/libsibna.a /usr/lib/

# Set permissions
RUN chown -R sibna:sibna /app

USER sibna

# Default command
CMD ["/bin/bash"]
