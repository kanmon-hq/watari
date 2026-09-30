# Multi-stage build for multi-arch static binary
FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /app

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs
RUN cargo build --release || true
RUN rm -rf src

# Copy source code and build final binary
COPY src ./src
RUN touch src/main.rs src/lib.rs
RUN cargo build --release

# Minimal runtime image
FROM alpine:3.20

RUN addgroup -S -g 10001 watari && \
    adduser -S -u 10001 -G watari watari && \
    apk --no-cache add ca-certificates tzdata curl

WORKDIR /app

COPY --from=builder /app/target/release/watari /app/watari
COPY examples/tenants.yaml /app/examples/tenants.yaml

RUN chown -R watari:watari /app
USER watari:watari

EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
  CMD curl -f http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/app/watari"]
