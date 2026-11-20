# EUDI Wallet Kit Test Harness
#
# Multi-stage build: Gradle build → slim JRE runtime.
# Uses the official EUDI Wallet Kit JVM libraries to exercise Marty's
# OID4VCI/OID4VP endpoints as a real wallet would.

FROM gradle:9.8.0-jdk21@sha256:4debe478645a3ad9208f3403ac021859fdf4d1a819d59970d75309b098f28f76 AS builder
WORKDIR /build
COPY build.gradle.kts settings.gradle.kts ./
COPY gradle/ gradle/
COPY gradle.lockfile ./
# Download dependencies first (layer caching)
RUN gradle dependencies --no-daemon
COPY src/ src/
RUN gradle installDist --no-daemon

FROM eclipse-temurin:21-jre@sha256:ca73b4d3961703d6d7830a4361f49ef0478f8f28b39defc07bb72f4cc7f834f6
WORKDIR /app
COPY --from=builder /build/build/install/eudi-wallet-harness/ ./

ENV PORT=9090
EXPOSE 9090

HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=30s \
    CMD curl -sf http://localhost:9090/health || exit 1

ENTRYPOINT ["./bin/eudi-wallet-harness"]
