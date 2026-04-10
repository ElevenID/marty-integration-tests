# EUDI Wallet Kit Test Harness
#
# Multi-stage build: Gradle build → slim JRE runtime.
# Uses the official EUDI Wallet Kit JVM libraries to exercise Marty's
# OID4VCI/OID4VP endpoints as a real wallet would.

FROM gradle:8.11-jdk17 AS builder
WORKDIR /build
COPY build.gradle.kts settings.gradle.kts ./
COPY gradle/ gradle/
# Download dependencies first (layer caching)
RUN gradle dependencies --no-daemon 2>/dev/null || true
COPY src/ src/
RUN gradle installDist --no-daemon

FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=builder /build/build/install/eudi-wallet-harness/ ./

ENV PORT=9090
EXPOSE 9090

HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=30s \
    CMD curl -sf http://localhost:9090/health || exit 1

ENTRYPOINT ["./bin/eudi-wallet-harness"]
