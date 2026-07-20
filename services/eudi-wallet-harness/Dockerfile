# EUDI Wallet Kit Test Harness
#
# Multi-stage build: Gradle build → slim JRE runtime.
# Uses the official EUDI Wallet Kit JVM libraries to exercise Marty's
# OID4VCI/OID4VP endpoints as a real wallet would.

FROM gradle:8.11-jdk17@sha256:91d559b8d55f522de5bc6882f73bcedc4e2cc7b0a58e839a9fa0ed95811a988d AS builder
WORKDIR /build
COPY build.gradle.kts settings.gradle.kts ./
COPY gradle/ gradle/
COPY gradle.lockfile ./
# Download dependencies first (layer caching)
RUN gradle dependencies --no-daemon
COPY src/ src/
RUN gradle installDist --no-daemon

FROM eclipse-temurin:17-jre@sha256:92999aea37688157a53a40bfcb187c30f317422e028045fd5fc5c548fde9e626
WORKDIR /app
COPY --from=builder /build/build/install/eudi-wallet-harness/ ./

ENV PORT=9090
EXPOSE 9090

HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=30s \
    CMD curl -sf http://localhost:9090/health || exit 1

ENTRYPOINT ["./bin/eudi-wallet-harness"]
