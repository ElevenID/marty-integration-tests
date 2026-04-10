/*
 * Wallet presentation service — wraps eudi-lib-jvm-openid4vp-kt.
 *
 * Implements OID4VP holder role: resolves the verifier's authorization
 * request, builds a VP token from a held credential, and dispatches
 * it to the verifier's direct_post endpoint.  Uses the exact same
 * EUDI Wallet Kit library that powers the EUDI Reference Wallet.
 */
package com.elevenid.marty.wallet

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.ktor.client.*
import io.ktor.client.engine.java.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.logging.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.*
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

object WalletPresentationService {
    private val log = LoggerFactory.getLogger(javaClass)

    /** Trust-all manager for test environments with self-signed certs. */
    private val trustAllManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    private fun createHttpClient(): HttpClient = HttpClient(Java) {
        install(ContentNegotiation) {
            json(Json { ignoreUnknownKeys = true })
        }
        install(Logging) {
            logger = Logger.DEFAULT
            level = LogLevel.INFO
        }
        engine {
            config {
                sslContext(
                    SSLContext.getInstance("TLS").apply {
                        init(null, arrayOf<TrustManager>(trustAllManager), java.security.SecureRandom())
                    }
                )
            }
        }
    }

    /**
     * Submit a credential presentation via the EUDI OID4VP library.
     *
     * NOTE: This path requires the verifier's client_id_scheme to be
     * supported by the EUDI library (pre-registered, x509_san_dns, etc.).
     * For Marty's DID-based client_id_scheme, use [directPost] instead.
     */
    suspend fun submitPresentation(
        authorizationRequestUri: String,
        credentialCompact: String,
    ): PresentationResult = coroutineScope {
        try {
            log.info("submitPresentation is a placeholder — use directPost for DID-based verifiers")
            PresentationResult(
                success = false,
                error = "submitPresentation via EUDI library requires x509/preregistered client_id_scheme. " +
                        "Use /presentation/direct-post for DID-based verifiers.",
            )
        } catch (e: Exception) {
            log.error("Presentation flow failed", e)
            PresentationResult(
                success = false,
                error = "${e::class.simpleName}: ${e.message}",
            )
        }
    }

    /**
     * Build an SD-JWT VP token string with a Key Binding JWT appended.
     *
     * Same key-binding logic as [buildSdJwtVpToken] but returns a raw String
     * instead of a VerifiablePresentation wrapper — useful for the direct_post
     * path where the test orchestrator constructs the VP token itself.
     */
    fun buildSdJwtVpTokenString(
        sdJwtCompact: String,
        audience: String,
        nonce: String,
    ): String {
        val holderKey: ECKey = ECKeyGenerator(Curve.P_256).generate()

        val sdHash = run {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(sdJwtCompact.encodeToByteArray())
            Base64.getUrlEncoder().withoutPadding().encodeToString(digest.digest())
        }

        val kbJwt = run {
            val header = JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType("kb+jwt"))
                .keyID(holderKey.keyID)
                .build()
            val claims = JWTClaimsSet.Builder()
                .audience(audience)
                .claim("nonce", nonce)
                .issueTime(Date())
                .claim("sd_hash", sdHash)
                .build()
            SignedJWT(header, claims).apply { sign(ECDSASigner(holderKey)) }
        }

        return "$sdJwtCompact${kbJwt.serialize()}"
    }

    /**
     * Direct-post a VP token to the verifier's response_uri.
     *
     * Bypasses the EUDI OID4VP library's authorization request resolution,
     * which is useful when the verifier's client_id_scheme (e.g. "did") is
     * not natively supported by the library.  The test orchestrator resolves
     * the authorization request JWT itself, extracts nonce/state/response_uri,
     * and calls this method to post the VP token.
     *
     * Posts application/x-www-form-urlencoded per OID4VP §6.2.
     */
    suspend fun directPost(
        responseUri: String,
        vpToken: String,
        presentationSubmission: String? = null,
        state: String? = null,
    ): PresentationResult = coroutineScope {
        createHttpClient().use { httpClient ->
            try {
                log.info("Direct-posting VP token to: $responseUri")

                val response = withContext(Dispatchers.IO) {
                    httpClient.submitForm(
                        url = responseUri,
                        formParameters = parameters {
                            append("vp_token", vpToken)
                            if (presentationSubmission != null) {
                                append("presentation_submission", presentationSubmission)
                            }
                            if (state != null) {
                                append("state", state)
                            }
                        },
                    )
                }

                val body = response.bodyAsText()
                val status = response.status.value
                log.info("Direct-post response: status=$status, body=${body.take(500)}")

                PresentationResult(
                    success = status in 200..299,
                    responseMode = "direct_post",
                    verifierAccepted = status in 200..299,
                    responseStatus = status,
                    responseBody = body,
                )
            } catch (e: Exception) {
                log.error("Direct-post failed", e)
                PresentationResult(
                    success = false,
                    error = "${e::class.simpleName}: ${e.message}",
                )
            }
        }
    }
}
