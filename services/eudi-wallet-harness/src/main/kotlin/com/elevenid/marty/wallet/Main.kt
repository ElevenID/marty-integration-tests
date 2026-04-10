/*
 * EUDI Wallet Kit Test Harness
 *
 * A headless wallet service that wraps the official EU Digital Identity Wallet
 * SDK libraries (eudi-lib-jvm-openid4vci-kt / eudi-lib-jvm-openid4vp-kt) and
 * exposes them via a simple HTTP API for integration test orchestration.
 *
 * This proves real wallet compatibility: the same libraries that power the
 * EUDI Reference Wallet mobile app are used here to exercise Marty's OID4VCI
 * and OID4VP endpoints.
 */
package com.elevenid.marty.wallet

import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.Json

fun main() {
    val port = System.getenv("PORT")?.toIntOrNull() ?: 9090
    println("Starting EUDI Wallet Harness on port $port")

    embeddedServer(Netty, port = port) {
        install(ContentNegotiation) {
            json(Json {
                ignoreUnknownKeys = true
                prettyPrint = true
                encodeDefaults = true
            })
        }
        install(StatusPages) {
            exception<Throwable> { call, cause ->
                call.application.log.error("Unhandled error", cause)
                call.respond(
                    HttpStatusCode.InternalServerError,
                    ErrorResponse(
                        error = cause::class.simpleName ?: "Unknown",
                        message = cause.message ?: "No message",
                        stackTrace = cause.stackTraceToString().take(2000),
                    )
                )
            }
        }
        configureRoutes()
    }.start(wait = true)
}

fun Application.configureRoutes() {
    routing {
        // Health check
        get("/health") {
            call.respond(HealthResponse(
                status = "ok",
                service = "eudi-wallet-harness",
                openid4vciVersion = "0.9.1",
                openid4vpVersion = "0.12.3",
            ))
        }

        // OID4VCI: Pre-authorized code issuance flow
        post("/issuance/pre-auth") {
            val request = call.receive<IssuanceRequest>()
            log.info("Starting pre-auth issuance: offerUri=${request.credentialOfferUri}")

            val result = WalletIssuanceService.runPreAuthIssuance(
                credentialOfferUri = request.credentialOfferUri,
                txCode = request.txCode,
            )
            call.respond(result)
        }

        // OID4VCI: Metadata resolution only
        post("/issuance/resolve-offer") {
            val request = call.receive<IssuanceRequest>()
            log.info("Resolving offer: offerUri=${request.credentialOfferUri}")

            val result = WalletIssuanceService.resolveOffer(
                credentialOfferUri = request.credentialOfferUri,
            )
            call.respond(result)
        }

        // OID4VP: Presentation flow (resolve auth request + submit VP)
        post("/presentation/submit") {
            val request = call.receive<PresentationRequest>()
            log.info("Starting presentation: authRequestUri=${request.authorizationRequestUri}")

            val result = WalletPresentationService.submitPresentation(
                authorizationRequestUri = request.authorizationRequestUri,
                credentialCompact = request.credential,
            )
            call.respond(result)
        }

        // OID4VP: Build and submit VP token without the EUDI library's resolution.
        // Useful when the verifier's client_id_scheme is not supported by the
        // library (e.g. DID-based) — the test orchestrator resolves the request
        // itself and passes in the details.
        post("/presentation/direct-post") {
            val request = call.receive<DirectPostRequest>()
            log.info("Direct posting VP to: ${request.responseUri}")

            val result = WalletPresentationService.directPost(
                responseUri = request.responseUri,
                vpToken = request.vpToken,
                presentationSubmission = request.presentationSubmission,
                state = request.state,
            )
            call.respond(result)
        }

        // OID4VP: Build a VP token (SD-JWT with KB-JWT) without submitting.
        // The test orchestrator can then submit it via the gateway client.
        post("/presentation/build-vp-token") {
            val request = call.receive<BuildVpTokenRequest>()
            log.info("Building VP token: audience=${request.audience}, format=${request.format}")

            val vpToken = when (request.format) {
                "sd-jwt", "dc+sd-jwt", "vc+sd-jwt" -> {
                    WalletPresentationService.buildSdJwtVpTokenString(
                        sdJwtCompact = request.credential,
                        audience = request.audience,
                        nonce = request.nonce,
                    )
                }
                else -> {
                    // mDoc / other — pass through raw credential
                    request.credential
                }
            }
            call.respond(BuildVpTokenResponse(vpToken = vpToken))
        }
    }
}
