/*
 * Wallet presentation service backed by eudi-lib-jvm-openid4vp-kt.
 *
 * The official path resolves and validates the authorization request, creates
 * holder-bound SD-JWT presentation material, and lets the EUDI library encode
 * and dispatch the response. The compatibility direct-post endpoint remains
 * available for tests that intentionally exercise an already-resolved request.
 */
package com.elevenid.marty.wallet

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.Consensus
import eu.europa.ec.eudi.openid4vp.DispatchOutcome
import eu.europa.ec.eudi.openid4vp.EncryptionParameters
import eu.europa.ec.eudi.openid4vp.HashAlgorithm
import eu.europa.ec.eudi.openid4vp.JarConfiguration
import eu.europa.ec.eudi.openid4vp.OpenId4VPConfig
import eu.europa.ec.eudi.openid4vp.OpenId4Vp
import eu.europa.ec.eudi.openid4vp.Resolution
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject
import eu.europa.ec.eudi.openid4vp.ResponseEncryptionConfiguration
import eu.europa.ec.eudi.openid4vp.ResponseMode
import eu.europa.ec.eudi.openid4vp.SupportedClientIdPrefix
import eu.europa.ec.eudi.openid4vp.SupportedRequestUriMethods
import eu.europa.ec.eudi.openid4vp.TransactionData
import eu.europa.ec.eudi.openid4vp.VPConfiguration
import eu.europa.ec.eudi.openid4vp.VerifiablePresentation
import eu.europa.ec.eudi.openid4vp.VerifiablePresentations
import eu.europa.ec.eudi.openid4vp.VpFormatsSupported
import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.logging.LogLevel
import io.ktor.client.plugins.logging.Logging
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.parameters
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.slf4j.LoggerFactory
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Collections
import java.util.Date
import java.util.LinkedHashMap

class MissingHolderKeyException(message: String) : IllegalStateException(message)

object WalletPresentationService {
    private val log = LoggerFactory.getLogger(javaClass)
    private const val MAX_RETAINED_HOLDER_KEYS = 256
    private const val REQUEST_OBJECT_TRUST_ANCHOR_FILE_ENV = "EUDI_OID4VP_TRUST_ANCHOR_FILE"
    private val pemCertificate = Regex(
        """-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----""",
    )

    /*
     * This is a disposable test wallet, so private holder keys are process-local
     * and never returned over HTTP. The credential digest is only an index; it is
     * not a secret and avoids retaining another copy of the credential.
     */
    private val holderKeys = Collections.synchronizedMap(
        object : LinkedHashMap<String, ECKey>(32, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, ECKey>?): Boolean =
                size > MAX_RETAINED_HOLDER_KEYS
        },
    )

    internal fun rememberHolderKey(credentialCompact: String, holderKey: ECKey) {
        require(holderKey.isPrivate) { "A private holder key is required" }
        holderKeys[credentialFingerprint(credentialCompact)] = holderKey
    }

    private fun holderKeyFor(credentialCompact: String): ECKey =
        holderKeys[credentialFingerprint(credentialCompact)]
            ?: throw MissingHolderKeyException(
                "No holder key is available for this credential. " +
                    "Issue it through this wallet-harness process before presentation.",
            )

    private fun credentialFingerprint(credentialCompact: String): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(credentialCompact.encodeToByteArray()),
        )

    private fun createHttpClient(): HttpClient = HttpClient(Java) {
        install(ContentNegotiation) {
            json(Json { ignoreUnknownKeys = true })
        }
        install(Logging) {
            level = LogLevel.INFO
        }
    }

    private fun createOpenId4Vp(httpClient: HttpClient): OpenId4Vp {
        val certificateTrust = eu.europa.ec.eudi.openid4vp.X509CertificateTrust(::validateCertificateChain)
        val config = OpenId4VPConfig(
            vpConfiguration = VPConfiguration(
                vpFormatsSupported = VpFormatsSupported(
                    sdJwtVc = VpFormatsSupported.SdJwtVc.HAIP,
                ),
            ),
            jarConfiguration = JarConfiguration(
                supportedAlgorithms = listOf(
                    JWSAlgorithm.ES256,
                    JWSAlgorithm.ES384,
                    JWSAlgorithm.ES512,
                ),
                supportedRequestUriMethods = SupportedRequestUriMethods.Default,
            ),
            responseEncryptionConfiguration = ResponseEncryptionConfiguration.Supported(
                supportedAlgorithms = listOf(JWEAlgorithm.ECDH_ES),
                supportedMethods = listOf(EncryptionMethod.A128GCM),
            ),
            supportedClientIdPrefixes = listOf(
                SupportedClientIdPrefix.RedirectUri,
                SupportedClientIdPrefix.X509SanDns(certificateTrust),
                SupportedClientIdPrefix.X509Hash(certificateTrust),
                SupportedClientIdPrefix.DecentralizedIdentifier { didUrl ->
                    resolveDidWebPublicKey(httpClient, didUrl)
                },
            ),
        )
        return OpenId4Vp(config, httpClient)
    }

    /**
     * Resolve, validate, and dispatch an SD-JWT presentation using the pinned
     * official EUDI OID4VP library.
     */
    suspend fun submitPresentation(
        authorizationRequestUri: String,
        credentialCompact: String,
    ): PresentationResult = coroutineScope {
        createHttpClient().use { httpClient ->
            try {
                val openId4Vp = createOpenId4Vp(httpClient)
                val request = when (val resolution = openId4Vp.resolveRequestUri(authorizationRequestUri)) {
                    is Resolution.Success -> resolution.requestObject
                    is Resolution.Invalid -> error(
                        "Official OID4VP resolver rejected the authorization request: ${resolution.error}",
                    )
                }

                val credentialQuery = request.query.credentials.value.singleOrNull()
                    ?: error("The harness currently requires exactly one DCQL credential query")
                require(credentialQuery.format.value == "dc+sd-jwt") {
                    "Official presentation currently supports dc+sd-jwt; requested ${credentialQuery.format.value}"
                }

                val vpToken = buildSdJwtVpToken(
                    sdJwtCompact = credentialCompact,
                    holderKey = holderKeyFor(credentialCompact),
                    audience = request.client.id.clientId,
                    nonce = request.nonce,
                    transactionData = request.transactionData,
                )
                val consensus = Consensus.PositiveConsensus(
                    VerifiablePresentations(
                        mapOf(
                            credentialQuery.id to listOf(VerifiablePresentation.Generic(vpToken)),
                        ),
                    ),
                )
                val encryptionParameters = request.responseEncryptionSpecification?.let {
                    val apu = ByteArray(32).also(SecureRandom()::nextBytes)
                    EncryptionParameters.DiffieHellman(Base64URL.encode(apu))
                }

                when (val outcome = openId4Vp.dispatch(request, consensus, encryptionParameters)) {
                    is DispatchOutcome.VerifierResponse.Accepted -> PresentationResult(
                        success = true,
                        responseMode = request.responseMode.label(),
                        redirectUri = outcome.redirectURI?.toString(),
                        verifierAccepted = true,
                    )
                    DispatchOutcome.VerifierResponse.Rejected -> PresentationResult(
                        success = false,
                        responseMode = request.responseMode.label(),
                        verifierAccepted = false,
                        error = "Verifier rejected the official OID4VP response",
                    )
                    is DispatchOutcome.RedirectURI -> PresentationResult(
                        success = true,
                        responseMode = request.responseMode.label(),
                        redirectUri = outcome.value.toString(),
                        verifierAccepted = false,
                    )
                }
            } catch (e: Exception) {
                log.error("Official OID4VP presentation flow failed", e)
                PresentationResult(
                    success = false,
                    error = "${e::class.simpleName}: ${e.message}",
                )
            }
        }
    }

    /**
     * Build an SD-JWT VP token for the compatibility direct-post path. The key
     * is the same key used in the OID4VCI proof that caused the issuer to place
     * the holder public JWK in cnf; a newly generated key would be invalid.
     */
    fun buildSdJwtVpTokenString(
        sdJwtCompact: String,
        audience: String,
        nonce: String,
    ): String = buildSdJwtVpToken(
        sdJwtCompact = sdJwtCompact,
        holderKey = holderKeyFor(sdJwtCompact),
        audience = audience,
        nonce = nonce,
        transactionData = null,
    )

    private fun buildSdJwtVpToken(
        sdJwtCompact: String,
        holderKey: ECKey,
        audience: String,
        nonce: String,
        transactionData: List<TransactionData>?,
    ): String {
        val sdJwtForPresentation = if (sdJwtCompact.endsWith("~")) sdJwtCompact else "$sdJwtCompact~"
        val sdHash = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(sdJwtForPresentation.encodeToByteArray()),
        )

        val headerBuilder = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("kb+jwt"))
        holderKey.keyID?.let(headerBuilder::keyID)

        val claimsBuilder = JWTClaimsSet.Builder()
            .audience(audience)
            .claim("nonce", nonce)
            .issueTime(Date())
            .claim("sd_hash", sdHash)

        if (!transactionData.isNullOrEmpty()) {
            require(transactionData.all {
                it is TransactionData.SdJwtVc && HashAlgorithm.SHA_256 in it.hashAlgorithmsOrDefault
            }) { "Only SHA-256 SD-JWT transaction data is supported" }
            val hashes = transactionData.map {
                Base64.getUrlEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(it.value.encodeToByteArray()),
                )
            }
            claimsBuilder
                .claim("transaction_data_hashes_alg", HashAlgorithm.SHA_256.name)
                .claim("transaction_data_hashes", hashes)
        }

        val keyBindingJwt = SignedJWT(headerBuilder.build(), claimsBuilder.build()).apply {
            sign(ECDSASigner(holderKey))
        }
        return "$sdJwtForPresentation${keyBindingJwt.serialize()}"
    }

    /**
     * Compatibility endpoint for an already-resolved request. It intentionally
     * does not count as official-library OID4VP coverage.
     */
    suspend fun directPost(
        responseUri: String,
        vpToken: String,
        presentationSubmission: String? = null,
        state: String? = null,
    ): PresentationResult = coroutineScope {
        createHttpClient().use { httpClient ->
            try {
                val response = withContext(Dispatchers.IO) {
                    httpClient.submitForm(
                        url = responseUri,
                        formParameters = parameters {
                            append("vp_token", vpToken)
                            presentationSubmission?.let { append("presentation_submission", it) }
                            state?.let { append("state", it) }
                        },
                    )
                }
                val body = response.bodyAsText()
                val status = response.status.value
                PresentationResult(
                    success = status in 200..299,
                    responseMode = "direct_post_compatibility",
                    verifierAccepted = status in 200..299,
                    responseStatus = status,
                    responseBody = body,
                )
            } catch (e: Exception) {
                log.error("Compatibility direct-post failed", e)
                PresentationResult(
                    success = false,
                    error = "${e::class.simpleName}: ${e.message}",
                )
            }
        }
    }

    private suspend fun resolveDidWebPublicKey(httpClient: HttpClient, didUrl: URI): java.security.PublicKey? {
        val completeDidUrl = didUrl.toString()
        val did = completeDidUrl.substringBefore('#')
        if (!did.startsWith("did:web:")) return null

        val decoded = did.removePrefix("did:web:")
            .split(':')
            .map { URLDecoder.decode(it, StandardCharsets.UTF_8) }
        if (decoded.isEmpty() || decoded.first().isBlank()) return null

        val documentUrl = if (decoded.size == 1) {
            "https://${decoded.first()}/.well-known/did.json"
        } else {
            "https://${decoded.first()}/${decoded.drop(1).joinToString("/")}/did.json"
        }
        val document = Json.parseToJsonElement(httpClient.get(documentUrl).bodyAsText()).jsonObject
        val methods = document["verificationMethod"]?.jsonArray ?: return null
        val method = methods
            .map { it.jsonObject }
            .firstOrNull { candidate ->
                val id = candidate["id"]?.jsonPrimitive?.content
                id == completeDidUrl || (didUrl.fragment != null && id == "$did#${didUrl.fragment}")
            }
            ?: return null
        val publicJwk = method["publicKeyJwk"]?.jsonObject ?: return null
        return when (val jwk = JWK.parse(publicJwk.toString())) {
            is ECKey -> jwk.toECPublicKey()
            is RSAKey -> jwk.toRSAPublicKey()
            else -> null
        }
    }

    private fun validateCertificateChain(chain: List<X509Certificate>): Boolean {
        if (chain.isEmpty()) return false
        return try {
            chain.forEach(X509Certificate::checkValidity)
            val anchors = requestObjectTrustAnchors()

            val certificates = chain.toMutableList()
            if (certificates.size > 1 && anchors.any { anchor ->
                    anchor.trustedCert.encoded.contentEquals(certificates.last().encoded)
                }
            ) {
                certificates.removeLast()
            }
            val certPath = CertificateFactory.getInstance("X.509").generateCertPath(certificates)
            val parameters = PKIXParameters(anchors).apply { isRevocationEnabled = false }
            CertPathValidator.getInstance("PKIX").validate(certPath, parameters)
            true
        } catch (e: Exception) {
            log.warn("Verifier certificate chain was not trusted: ${e.message}")
            false
        }
    }

    private fun requestObjectTrustAnchors(): MutableSet<TrustAnchor> {
        val trustAnchorPath = System.getenv(REQUEST_OBJECT_TRUST_ANCHOR_FILE_ENV)
            ?.takeIf(String::isNotBlank)
            ?: error("$REQUEST_OBJECT_TRUST_ANCHOR_FILE_ENV is required for x509 client identifiers")
        val configuredPem = Files.readString(Path.of(trustAnchorPath))
        val certificateFactory = CertificateFactory.getInstance("X.509")
        val anchors = pemCertificate.findAll(configuredPem).map { match ->
            val certificate = certificateFactory.generateCertificate(
                match.value.byteInputStream(),
            ) as X509Certificate
            certificate.checkValidity()
            require(certificate.basicConstraints >= 0) {
                "$REQUEST_OBJECT_TRUST_ANCHOR_FILE_ENV must contain only CA certificates"
            }
            TrustAnchor(certificate, null)
        }.toMutableSet()
        require(anchors.isNotEmpty()) {
            "$REQUEST_OBJECT_TRUST_ANCHOR_FILE_ENV contains no PEM certificate"
        }
        return anchors
    }

    private fun ResponseMode.label(): String = when (this) {
        is ResponseMode.DirectPost -> "direct_post"
        is ResponseMode.DirectPostJwt -> "direct_post.jwt"
        is ResponseMode.Query -> "query"
        is ResponseMode.QueryJwt -> "query.jwt"
        is ResponseMode.Fragment -> "fragment"
        is ResponseMode.FragmentJwt -> "fragment.jwt"
    }
}
