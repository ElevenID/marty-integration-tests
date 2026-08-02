/*
 * Wallet issuance service — wraps eudi-lib-jvm-openid4vci-kt.
 *
 * Uses the exact same library that powers the EUDI Reference Wallet to
 * exercise Marty's OID4VCI endpoints, proving real wallet compatibility.
 */
package com.elevenid.marty.wallet

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.*
import io.ktor.client.*
import io.ktor.client.engine.java.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.cookies.*
import io.ktor.client.plugins.logging.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import java.security.SecureRandom
import java.security.Signature
import java.time.Duration
import java.time.Instant
import java.util.Date
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

object WalletIssuanceService {
    private val log = LoggerFactory.getLogger(javaClass)

    private class OfferResolutionStageException(
        val stage: String,
        cause: Throwable,
    ) : RuntimeException(cause)

    private class IssuanceStageException(
        val stage: String,
        cause: Throwable,
    ) : RuntimeException(cause)

    private fun failureClassSlug(exception: Throwable): String =
        generateSequence(exception) { it.cause }
            .lastOrNull()
            ?.javaClass
            ?.simpleName
            ?.replace(Regex("([a-z0-9])([A-Z])"), "$1-$2")
            ?.lowercase()
            ?.replace(Regex("[^a-z0-9-]"), "-")
            ?.trim('-')
            ?.takeIf { it.isNotEmpty() }
            ?: "unclassified"

    private fun issuanceFailureSlug(exception: Throwable): String {
        val protocolError = (exception as? CredentialIssuanceError.IssuanceRequestFailed)
            ?.error
            ?.takeIf { Regex("[a-z][a-z0-9_]{0,63}").matches(it) }
            ?.replace('_', '-')
        val errorClass = failureClassSlug(exception)
        return protocolError?.let { "$errorClass-$it" } ?: errorClass
    }

    /**
     * Reduce the official library's nested failures to a stable, public-safe
     * diagnostic code. The complete exception remains in the private service
     * log, while CI evidence can identify the failed protocol boundary without
     * publishing credential offers, endpoints, tokens, or issuer identifiers.
     */
    internal fun offerResolutionErrorCode(
        exception: Throwable,
        stage: String? = null,
    ): String {
        val causes = generateSequence(exception) { it.cause }.toList()
        val offerError = causes
            .filterIsInstance<CredentialOfferRequestException>()
            .firstOrNull()
            ?.error

        if (offerError == null) {
            val classes = causes.mapNotNull { it::class.simpleName }.toSet()
            return when {
                "UnableToResolveCredentialIssuerMetadata" in classes ||
                    "NonParseableCredentialIssuerMetadata" in classes ->
                    classifyMetadataFailure(exception, "issuer")
                "UnableToResolveAuthorizationServerMetadata" in classes ->
                    classifyMetadataFailure(exception, "authorization-server")
                else -> {
                    // Exception class names are safe to publish and make an
                    // otherwise opaque CI failure actionable without exposing
                    // offers, endpoints, tokens, identifiers, or messages.
                    val rootClass = failureClassSlug(exception)
                    "offer-resolution-${stage?.let { "$it-" }.orEmpty()}$rootClass"
                }
            }
        }

        return when (offerError) {
            is CredentialOfferRequestError.NonParsableCredentialOfferEndpointUrl ->
                "offer-endpoint-url-invalid"
            is CredentialOfferRequestValidationError.OneOfCredentialOfferOrCredentialOfferUri ->
                "offer-parameter-selection-invalid"
            is CredentialOfferRequestValidationError.InvalidCredentialOfferUri ->
                "offer-reference-url-invalid"
            is CredentialOfferRequestError.UnableToFetchCredentialOffer ->
                "offer-fetch-failed"
            is CredentialOfferRequestError.NonParseableCredentialOffer ->
                "offer-json-invalid"
            is CredentialOfferRequestValidationError.InvalidCredentialIssuerId ->
                "offer-issuer-id-invalid"
            is CredentialOfferRequestValidationError.InvalidCredentials ->
                "offer-credential-configuration-invalid"
            is CredentialOfferRequestValidationError.InvalidGrants ->
                "offer-grants-invalid"
            is CredentialOfferRequestError.UnableToResolveCredentialIssuerMetadata ->
                classifyMetadataFailure(offerError.reason, "issuer")
            is CredentialOfferRequestError.UnableToResolveAuthorizationServerMetadata ->
                classifyMetadataFailure(offerError.reason, "authorization-server")
        }
    }

    private fun classifyMetadataFailure(reason: Throwable, boundary: String): String {
        val causes = generateSequence(reason) { it.cause }.toList()
        val classes = causes.mapNotNull { it::class.simpleName }.toSet()
        val messages = causes.mapNotNull { it.message }
        val detail = when {
            // Prefer the transport root cause over the library's outer
            // UnableToFetch wrapper so a CI run remains directly actionable.
            "CertPathBuilderException" in classes || messages.any {
                it.contains("PKIX path building failed", ignoreCase = true) ||
                    it.contains("unable to find valid certification path", ignoreCase = true)
            } -> "tls-certificate-path-untrusted"
            classes.any { it in setOf("CertificateExpiredException", "CertificateNotYetValidException") } ->
                "tls-certificate-validity-failed"
            messages.any {
                it.contains("No subject alternative DNS name matching", ignoreCase = true) ||
                    it.contains("No name matching", ignoreCase = true)
            } -> "tls-hostname-mismatch"
            messages.any { it.contains("trustAnchors parameter must be non-empty", ignoreCase = true) } ->
                "tls-truststore-empty"
            "SSLHandshakeException" in classes -> "tls-handshake-failed"
            "UnknownHostException" in classes -> "hostname-resolution-failed"
            "ConnectException" in classes || "HttpConnectTimeoutException" in classes ->
                "connection-failed"
            "UnableToFetchCredentialIssuerMetadata" in classes -> "fetch-failed"
            "NonParseableCredentialIssuerMetadata" in classes ->
                metadataJsonFailureCode(messages)
            "InvalidCredentialIssuerId" in classes -> "issuer-id-invalid"
            "InvalidAuthorizationServer" in classes -> "authorization-server-url-invalid"
            "InvalidCredentialEndpoint" in classes -> "credential-endpoint-invalid"
            "InvalidNonceEndpoint" in classes -> "nonce-endpoint-invalid"
            "InvalidDeferredCredentialEndpoint" in classes -> "deferred-endpoint-invalid"
            "InvalidNotificationEndpoint" in classes -> "notification-endpoint-invalid"
            "InvalidCredentialsSupported" in classes -> "credential-configuration-invalid"
            "CredentialsSupportedRequired" in classes -> "credential-configurations-empty"
            "CredentialResponseEncryptionAlgorithmsRequired" in classes ->
                "response-encryption-algorithms-missing"
            "CredentialResponseAsymmetricEncryptionAlgorithmsRequired" in classes ->
                "response-encryption-asymmetric-algorithms-missing"
            "CredentialRequestEncryptionMustExistIfCredentialResponseEncryptionExists" in classes ->
                "request-encryption-metadata-missing"
            "InvalidBatchSize" in classes -> "batch-size-invalid"
            else -> "resolution-failed"
        }
        return "$boundary-metadata-$detail"
    }

    /**
     * Preserve only the schema field named by kotlinx.serialization. Values,
     * URLs, configuration identifiers, and JSON fragments must never cross
     * the public test-facade boundary.
     */
    private fun metadataJsonFailureCode(messages: List<String>): String {
        val knownFields = listOf(
            "credential_configurations_supported" to "credential-configurations-supported",
            "credential_signing_alg_values_supported" to "credential-signing-algorithms",
            "cryptographic_binding_methods_supported" to "binding-methods",
            "proof_types_supported" to "proof-types",
            "credential_definition" to "credential-definition",
            "credential_metadata" to "credential-metadata",
            "authorization_servers" to "authorization-servers",
            "display" to "display",
            "claims" to "claims",
            "doctype" to "doctype",
            "vct" to "vct",
        )
        val field = knownFields.firstOrNull { (wireName, _) ->
            messages.any { it.contains(wireName, ignoreCase = true) }
        }?.second
        return field?.let { "json-invalid-$it" } ?: "json-invalid"
    }

    private data class HolderProofMaterial(
        val proofs: ProofSpecification,
        val privateKey: ECKey,
    )

    /**
     * OpenId4VCI configuration matching the EUDI Reference Wallet's defaults.
     * Public client with P-256 key, supporting credential response encryption.
     */
    private val vciConfig = OpenId4VCIConfig(
        clientAuthentication = ClientAuthentication.None("marty-eudi-harness"),
        authFlowRedirectionURI = URI.create("urn:ietf:wg:oauth:2.0:oob"),
        encryptionSupportConfig = EncryptionSupportConfig(
            Curve.P_256,
            2048,
            CredentialResponseEncryptionPolicy.SUPPORTED,
        ),
        parUsage = ParUsage.IfSupported(),
        issuerMetadataPolicy = IssuerMetadataPolicy.IgnoreSigned,
    )

    private suspend fun makeIssuer(
        credentialOfferUri: String,
        httpClient: HttpClient,
    ): Issuer {
        return try {
            Issuer.make(vciConfig, credentialOfferUri, httpClient).getOrThrow().first
        } catch (exception: Exception) {
            if (exception is CancellationException) throw exception
            throw OfferResolutionStageException("offer-and-issuer-resolution", exception)
        }
    }

    private fun stagedOfferResolutionErrorCode(exception: Exception): String {
        val staged = exception as? OfferResolutionStageException
        return offerResolutionErrorCode(
            staged?.cause ?: exception,
            stage = staged?.stage,
        )
    }

    private suspend fun <T> issuanceStage(
        stage: String,
        block: suspend () -> T,
    ): T =
        try {
            block()
        } catch (exception: Throwable) {
            if (exception is CancellationException || exception is Error) throw exception
            throw IssuanceStageException(stage, exception)
        }

    private fun preAuthorizedIssuanceErrorCode(exception: Exception): String {
        val staged = exception as? IssuanceStageException
        return if (staged == null) {
            stagedOfferResolutionErrorCode(exception)
        } else {
            "issuance-${staged.stage}-${issuanceFailureSlug(staged.cause ?: staged)}"
        }
    }

    private fun configuredTlsContext(): SSLContext? {
        val trustStorePath = System.getProperty("javax.net.ssl.trustStore")
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
            ?: return null
        val trustStorePassword = requireNotNull(
            System.getProperty("javax.net.ssl.trustStorePassword")?.takeIf { it.isNotEmpty() }
        ) { "configured TLS truststore requires a password" }
        val trustStoreType = System.getProperty("javax.net.ssl.trustStoreType")
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
            ?: KeyStore.getDefaultType()

        val trustStore = KeyStore.getInstance(trustStoreType)
        Files.newInputStream(Path.of(trustStorePath)).use { input ->
            trustStore.load(input, trustStorePassword.toCharArray())
        }
        val trustManagers = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm()
        ).apply {
            init(trustStore)
        }
        return SSLContext.getInstance("TLS").apply {
            init(null, trustManagers.trustManagers, SecureRandom())
        }
    }

    private fun createHttpClient(): HttpClient = HttpClient(Java) {
        engine {
            configuredTlsContext()?.let { tlsContext ->
                config {
                    sslContext(tlsContext)
                }
            }
        }
        install(ContentNegotiation) {
            json(Json { ignoreUnknownKeys = true })
        }
        install(HttpCookies)
        install(Logging) {
            logger = Logger.DEFAULT
            level = LogLevel.INFO
        }
    }

    private fun walletAttester(): ECKey {
        val path = requireNotNull(System.getenv("EUDI_WALLET_ATTESTER_JWKS_FILE")) {
            "EUDI_WALLET_ATTESTER_JWKS_FILE is required"
        }
        val key = JWKSet.load(Path.of(path).toFile()).keys.singleOrNull() as? ECKey
            ?: error("wallet attester JWKS must contain exactly one EC key")
        require(key.isPrivate) { "wallet attester JWKS must contain its disposable private key" }
        require(key.x509CertChain?.isNotEmpty() == true) {
            "wallet attester key must carry its X.509 certificate chain"
        }
        return key
    }

    private fun keyAttestation(
        attestedKey: ECKey,
        nonce: Nonce?,
        preferredPeriod: PositiveDuration?,
    ): KeyAttestationJWT {
        val attester = walletAttester()
        val now = Instant.now()
        val lifetime = preferredPeriod?.value ?: Duration.ofHours(1)
        val expires = now.plus(lifetime.coerceAtMost(Duration.ofHours(4)))
        val statusExpires = now.plus(Duration.ofHours(4))
        val claims = JWTClaimsSet.Builder()
            .issueTime(Date.from(now))
            .expirationTime(Date.from(expires))
            .claim("attested_keys", listOf(attestedKey.toPublicJWK().toJSONObject()))
            .claim("key_storage", listOf("iso_18045_high"))
            .claim("user_authentication", listOf("iso_18045_high"))
            .claim("certification", "https://wallet-attester.test/certification")
            .claim("nonce", nonce?.value)
            .claim(
                "key_storage_status",
                mapOf(
                    "status" to mapOf(
                        "status_list" to mapOf(
                            "idx" to 0,
                            "uri" to "https://wallet-attester.test/status",
                        ),
                    ),
                    "exp" to statusExpires.epochSecond,
                ),
            )
            .build()
        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("key-attestation+jwt"))
            .x509CertChain(attester.x509CertChain)
            .build()
        val jwt = SignedJWT(header, claims).apply { sign(ECDSASigner(attester)) }
        return KeyAttestationJWT(jwt.serialize())
    }

    /** Create a P-256 holder key and a wallet-provider key attestation. */
    private fun createP256ProofSigner(): HolderProofMaterial {
        val ecKey: ECKey = ECKeyGenerator(Curve.P_256).generate()
        val jcaAlgorithm = "SHA256withECDSA"
        val proofs = ProofSpecification.JwtProof { nonce, preferredPeriod ->
            val attestation = keyAttestation(ecKey, nonce, preferredPeriod)
            object : Signer<KeyAttestationJWT> {
                override val javaAlgorithm: String = jcaAlgorithm
                override suspend fun acquire(): SignOperation<KeyAttestationJWT> =
                    SignOperation(
                        // The EUDI signing callback follows the JCA contract:
                        // ECDSA signatures are ASN.1 DER here. The official
                        // library converts DER to the JOSE r||s representation
                        // when it serializes the proof JWT.
                        function = SignFunction { input ->
                            derEncodedEcdsaSignature(ecKey, input)
                        },
                        publicMaterial = attestation,
                    )

                override suspend fun release(signOperation: SignOperation<KeyAttestationJWT>?) = Unit
            }
        }

        return HolderProofMaterial(
            proofs = proofs,
            privateKey = ecKey,
        )
    }

    internal fun derEncodedEcdsaSignature(
        privateKey: ECKey,
        input: ByteArray,
    ): ByteArray = Signature.getInstance("SHA256withECDSA").run {
        initSign(privateKey.toECPrivateKey())
        update(input)
        sign()
    }

    /**
     * Resolve a credential offer URI — validates metadata, checks grant types.
     * This alone exercises a significant portion of the OID4VCI spec.
     */
    suspend fun resolveOffer(credentialOfferUri: String): OfferResolutionResult =
        coroutineScope {
            createHttpClient().use { httpClient ->
                try {
                    val issuer = makeIssuer(credentialOfferUri, httpClient)
                    val offer = issuer.credentialOffer
                    val meta = offer.credentialIssuerMetadata

                    val grantType = when (offer.grants) {
                        is Grants.PreAuthorizedCode -> "pre-authorized_code"
                        is Grants.AuthorizationCode -> "authorization_code"
                        is Grants.Both -> "both"
                        null -> "none"
                    }

                    OfferResolutionResult(
                        success = true,
                        issuerMetadata = extractMetadata(meta),
                        grantType = grantType,
                        credentialConfigurationIds = offer.credentialConfigurationIdentifiers
                            .map { it.value },
                    )
                } catch (e: Exception) {
                    log.error("Offer resolution failed", e)
                    OfferResolutionResult(
                        success = false,
                        error = stagedOfferResolutionErrorCode(e),
                    )
                }
            }
        }

    /**
     * Full pre-authorized code issuance flow using the EUDI Wallet Kit.
     *
     * Steps (all handled by the library):
     * 1. Resolve credential offer URI → fetch + validate issuer metadata
     * 2. Authorize with pre-authorized code
     * 3. Generate proof-of-possession JWT (P-256)
     * 4. Request credential(s) from the credential endpoint
     * 5. Return issued credential(s)
     */
    suspend fun runPreAuthIssuance(
        credentialOfferUri: String,
        txCode: String? = null,
    ): IssuanceResult = coroutineScope {
        createHttpClient().use { httpClient ->
            try {
                // Step 1: Resolve offer
                log.info("Resolving credential offer through the public issuer endpoint")
                val issuer = makeIssuer(credentialOfferUri, httpClient)
                val offer = issuer.credentialOffer
                val meta = offer.credentialIssuerMetadata

                log.info(
                    "Resolved issuer: {} with {} credential configs",
                    meta.credentialIssuerIdentifier.toString(),
                    offer.credentialConfigurationIdentifiers.size,
                )

                // Verify pre-auth grant is available
                require(
                    offer.grants is Grants.PreAuthorizedCode || offer.grants is Grants.Both
                ) { "Offer does not support pre-authorized code grant" }

                // Step 2: Authorize
                log.info("Authorizing with pre-authorized code (txCode=${txCode != null})")
                val authorized = issuanceStage("authorization") {
                    with(issuer) {
                        authorizeWithPreAuthorizationCode(txCode).getOrThrow()
                    }
                }
                log.info("Authorization successful")

                // Step 3-4: Request each credential
                val credentials = mutableListOf<CredentialInfo>()
                var currentAuth = authorized

                for (credCfgId in offer.credentialConfigurationIdentifiers) {
                    log.info("Requesting credential: ${credCfgId.value}")
                    val requestPayload = IssuanceRequestPayload.ConfigurationBased(credCfgId)

                    // Generate P-256 proof signer (same as EUDI Reference Wallet)
                    val holderProof = issuanceStage("holder-proof") {
                        createP256ProofSigner()
                    }

                    val (updatedAuth, outcome) = issuanceStage("credential-request") {
                        with(issuer) {
                            currentAuth.request(requestPayload, holderProof.proofs).getOrThrow()
                        }
                    }
                    currentAuth = updatedAuth

                    when (outcome) {
                        is SubmissionOutcome.Success -> {
                            for (cred in outcome.credentials) {
                                val credStr = when (val c = cred.credential) {
                                    is Credential.Str -> c.value
                                    is Credential.Json -> c.value.toString()
                                }
                                credentials.add(CredentialInfo(
                                    format = credCfgId.value,
                                    credential = credStr,
                                    notificationId = outcome.notificationId?.value,
                                ))
                                WalletPresentationService.rememberHolderKey(
                                    credentialCompact = credStr,
                                    holderKey = holderProof.privateKey,
                                )
                            }
                            log.info("Credential issued for: ${credCfgId.value}")
                        }
                        is SubmissionOutcome.Deferred -> {
                            log.info("Got deferred issuance for ${credCfgId.value}")
                            val (_, deferredOutcome) = with(issuer) {
                                currentAuth.queryForDeferredCredential(outcome.transactionId).getOrThrow()
                            }
                            when (deferredOutcome) {
                                is DeferredCredentialQueryOutcome.Issued -> {
                                    for (cred in deferredOutcome.credentials) {
                                        val credStr = when (val c = cred.credential) {
                                            is Credential.Str -> c.value
                                            is Credential.Json -> c.value.toString()
                                        }
                                        credentials.add(CredentialInfo(
                                            format = credCfgId.value,
                                            credential = credStr,
                                            notificationId = deferredOutcome.notificationId?.value,
                                        ))
                                        WalletPresentationService.rememberHolderKey(
                                            credentialCompact = credStr,
                                            holderKey = holderProof.privateKey,
                                        )
                                    }
                                }
                                is DeferredCredentialQueryOutcome.IssuancePending ->
                                    log.warn("Deferred issuance still pending for ${credCfgId.value}")
                                is DeferredCredentialQueryOutcome.Errored ->
                                    log.warn("Deferred issuance errored for ${credCfgId.value}: ${deferredOutcome.error}")
                            }
                        }
                        is SubmissionOutcome.Failed -> {
                            throw IssuanceStageException("credential-outcome", outcome.error)
                        }
                    }
                }

                IssuanceResult(
                    success = true,
                    credentialCount = credentials.size,
                    credentials = credentials,
                    issuerMetadata = extractMetadata(meta),
                )
            } catch (e: Exception) {
                log.error("Pre-auth issuance failed", e)
                IssuanceResult(
                    success = false,
                    error = preAuthorizedIssuanceErrorCode(e),
                )
            }
        }
    }

    private fun extractMetadata(meta: CredentialIssuerMetadata): IssuerMetadataInfo {
        return IssuerMetadataInfo(
            credentialIssuerId = meta.credentialIssuerIdentifier.toString(),
            credentialConfigurationIds = meta.credentialConfigurationsSupported.keys
                .map { it.value },
            authorizationServers = meta.authorizationServers.map { it.toString() },
            tokenEndpoint = null, // available on auth server metadata
            credentialEndpoint = meta.credentialEndpoint.toString(),
            nonceEndpoint = meta.nonceEndpoint?.toString(),
            parEndpoint = null,
        )
    }
}
