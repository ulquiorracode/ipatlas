# Multi-stage ultra-lightweight Docker container for IPAtlas Sidecar microservice

FROM rust:1.74-slim AS builder
WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY core/ ./core/
COPY adapters/ ./adapters/
COPY cli/ ./cli/

RUN cargo build --release -p ipatlas-cli

# Runtime image: minimal scratch or debian-slim with ca-certificates
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/target/release/ipatlas /usr/local/bin/ipatlas

EXPOSE 8080

# Default entrypoint runs HTTP microservice / sidecar
ENTRYPOINT ["ipatlas", "serve"]
CMD ["-d", "/data/ipatlas.bin", "-p", "8080", "-b", "0.0.0.0"]
